/*
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package credentialprovider obtains cluster credentials from credential plugins
// and keeps them in memory, re-minting each before it expires. Credentials are
// never written anywhere.
package credentialprovider

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"k8s.io/klog/v2"

	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/api"
)

const (
	// refreshAt is the fraction of a credential's lifetime after which it is re-minted.
	refreshAt = 0.8
	// expirySkew treats a credential as expired this long before its stated expiry,
	// to cover clock drift and the request's own time in flight.
	expirySkew = 30 * time.Second

	requestTimeout  = 10 * time.Second
	maxResponseSize = 1 << 20
)

// providerName is also the socket's file name, so it must not be able to name a path.
var providerName = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$`)

// Credential is a bearer token or a client certificate and key.
type Credential struct {
	Token       string
	Certificate []byte
	PrivateKey  []byte
	Expiry      time.Time
}

type entry struct {
	credential *Credential
	refreshAt  time.Time
}

// Client requests credentials from the plugins in one directory and caches them.
type Client struct {
	dir   string
	now   func() time.Time
	group singleflight.Group

	mu    sync.Mutex
	cache map[string]*entry
}

var (
	clientsMu sync.Mutex
	clients   = map[string]*Client{}
)

// ForDir returns the process-wide Client for dir, so its cache is shared by every
// request.
func ForDir(dir string) *Client {
	clientsMu.Lock()
	defer clientsMu.Unlock()
	if c, ok := clients[dir]; ok {
		return c
	}
	c := NewClient(dir)
	clients[dir] = c
	return c
}

// NewClient returns a Client for the plugin sockets in dir.
func NewClient(dir string) *Client {
	return &Client{dir: dir, now: time.Now, cache: map[string]*entry{}}
}

// Get returns a credential for cluster from the named provider. A cached
// credential is returned until refreshAt of its lifetime has passed; after that
// the first caller mints a new one and concurrent callers share the result. If
// minting fails, the cached credential is returned for as long as it is valid.
func (c *Client) Get(ctx context.Context, provider, cluster string, config []byte) (*Credential, error) {
	if !providerName.MatchString(provider) {
		return nil, fmt.Errorf("invalid credential provider name %q", provider)
	}
	sum := sha256.Sum256(config)
	key := fmt.Sprintf("%s/%s/%x", provider, cluster, sum)

	now := c.now()
	cached := c.load(key)
	if cached != nil && now.Before(cached.refreshAt) {
		return cached.credential, nil
	}

	v, err, _ := c.group.Do(key, func() (interface{}, error) {
		if e := c.load(key); e != nil && c.now().Before(e.refreshAt) {
			return e.credential, nil
		}
		issued := c.now()
		cred, err := c.mint(ctx, provider, cluster, config, issued)
		if err != nil {
			return nil, err
		}
		lifetime := cred.Expiry.Sub(issued)
		c.store(key, &entry{credential: cred, refreshAt: issued.Add(time.Duration(float64(lifetime) * refreshAt))})
		return cred, nil
	})
	if err == nil {
		return v.(*Credential), nil
	}
	if cached != nil && now.Before(cached.credential.Expiry.Add(-expirySkew)) {
		klog.Warningf("Refreshing credential for cluster %q from plugin %q failed, using the cached one until it expires at %s: %v",
			cluster, provider, cached.credential.Expiry.Format(time.RFC3339), err)
		return cached.credential, nil
	}
	return nil, err
}

func (c *Client) load(key string) *entry {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cache[key]
}

func (c *Client) store(key string, e *entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[key] = e
}

func (c *Client) mint(ctx context.Context, provider, cluster string, config []byte, now time.Time) (*Credential, error) {
	socket := filepath.Join(c.dir, provider+".sock")
	if _, err := os.Stat(socket); err != nil {
		return nil, fmt.Errorf("credential plugin %q is not installed (no socket at %s)", provider, socket)
	}

	body, err := json.Marshal(&api.CredentialRequest{
		APIVersion: api.RequestAPIVersion,
		Kind:       api.RequestKind,
		Cluster:    cluster,
		Config:     json.RawMessage(config),
	})
	if err != nil {
		return nil, fmt.Errorf("credential plugin %q: encoding request: %w", provider, err)
	}

	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+provider+api.CredentialPath, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("credential plugin %q: %w", provider, err)
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", socket)
		},
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("credential plugin %q: %w", provider, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return nil, fmt.Errorf("credential plugin %q: reading response: %w", provider, err)
	}

	if resp.StatusCode != http.StatusOK {
		perr := &api.Error{}
		if err := json.Unmarshal(raw, perr); err != nil || perr.Message == "" {
			return nil, fmt.Errorf("credential plugin %q returned %s", provider, resp.Status)
		}
		return nil, fmt.Errorf("credential plugin %q returned %s: %s", provider, resp.Status, perr.Message)
	}
	return parseCredential(provider, raw, now)
}

// parseCredential never quotes the response, which holds the credential.
func parseCredential(provider string, raw []byte, now time.Time) (*Credential, error) {
	ec := &api.ExecCredential{}
	if err := json.Unmarshal(raw, ec); err != nil {
		return nil, fmt.Errorf("credential plugin %q returned a malformed response", provider)
	}
	if ec.APIVersion != api.ExecCredentialAPIVersion || ec.Kind != api.ExecCredentialKind {
		return nil, fmt.Errorf("credential plugin %q returned an unexpected response %s, Kind=%s", provider, ec.APIVersion, ec.Kind)
	}
	if ec.Status == nil {
		return nil, fmt.Errorf("credential plugin %q returned no status", provider)
	}
	s := ec.Status
	cred := &Credential{Token: s.Token}
	switch {
	case s.Token != "" && s.ClientCertificateData == "" && s.ClientKeyData == "":
	case s.Token == "" && s.ClientCertificateData != "" && s.ClientKeyData != "":
		cred.Certificate = []byte(s.ClientCertificateData)
		cred.PrivateKey = []byte(s.ClientKeyData)
	default:
		return nil, fmt.Errorf("credential plugin %q returned neither a token nor a client certificate and key", provider)
	}
	if s.ExpirationTimestamp == nil || s.ExpirationTimestamp.IsZero() {
		return nil, fmt.Errorf("credential plugin %q returned a credential without an expirationTimestamp", provider)
	}
	cred.Expiry = *s.ExpirationTimestamp
	if !now.Before(cred.Expiry.Add(-expirySkew)) {
		return nil, fmt.Errorf("credential plugin %q returned a credential that has already expired (%s)", provider, cred.Expiry.Format(time.RFC3339))
	}
	return cred, nil
}
