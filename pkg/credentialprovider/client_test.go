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

package credentialprovider

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/api"
)

// fakePlugin serves the plugin protocol on <dir>/<name>.sock.
type fakePlugin struct {
	calls    atomic.Int32
	lastReq  atomic.Pointer[api.CredentialRequest]
	respond  func(req *api.CredentialRequest, n int32) (int, any)
	blockFor chan struct{}
}

func (f *fakePlugin) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.URL.Path != api.CredentialPath {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	req := &api.CredentialRequest{}
	if err := json.NewDecoder(r.Body).Decode(req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	n := f.calls.Add(1)
	f.lastReq.Store(req)
	if f.blockFor != nil {
		<-f.blockFor
	}
	code, body := f.respond(req, n)
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

func startPlugin(t *testing.T, dir, name string, p *fakePlugin) {
	t.Helper()
	l, err := net.Listen("unix", filepath.Join(dir, name+".sock"))
	require.NoError(t, err)
	srv := &http.Server{Handler: p}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
}

// pluginDir is short because macOS caps unix socket paths at 104 bytes.
func pluginDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "cgp")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func tokenResponse(token string, expiry time.Time) any {
	return &api.ExecCredential{
		APIVersion: api.ExecCredentialAPIVersion,
		Kind:       api.ExecCredentialKind,
		Status:     &api.ExecCredentialStatus{Token: token, ExpirationTimestamp: &expiry},
	}
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestClient(dir string) (*Client, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	c := NewClient(dir)
	c.now = clock.Now
	return c, clock
}

func TestGetMintsAndCachesUntilRefresh(t *testing.T) {
	dir := pluginDir(t)
	c, clock := newTestClient(dir)
	p := &fakePlugin{respond: func(_ *api.CredentialRequest, n int32) (int, any) {
		return http.StatusOK, tokenResponse(fmt.Sprintf("token-%d", n), clock.Now().Add(15*time.Minute))
	}}
	startPlugin(t, dir, "aws", p)
	ctx := context.Background()

	cred, err := c.Get(ctx, "aws", "prod", []byte(`{"region":"eu-west-1"}`))
	require.NoError(t, err)
	assert.Equal(t, "token-1", cred.Token)
	assert.Equal(t, "prod", p.lastReq.Load().Cluster)
	assert.Equal(t, api.RequestAPIVersion, p.lastReq.Load().APIVersion)
	assert.Equal(t, api.RequestKind, p.lastReq.Load().Kind)
	assert.JSONEq(t, `{"region":"eu-west-1"}`, string(p.lastReq.Load().Config))

	// 80% of 15 minutes is 12: cached before, re-minted after.
	clock.Advance(11 * time.Minute)
	cred, err = c.Get(ctx, "aws", "prod", []byte(`{"region":"eu-west-1"}`))
	require.NoError(t, err)
	assert.Equal(t, "token-1", cred.Token)
	assert.EqualValues(t, 1, p.calls.Load())

	clock.Advance(2 * time.Minute)
	cred, err = c.Get(ctx, "aws", "prod", []byte(`{"region":"eu-west-1"}`))
	require.NoError(t, err)
	assert.Equal(t, "token-2", cred.Token)
	assert.EqualValues(t, 2, p.calls.Load())
}

func TestGetCachesPerClusterAndConfig(t *testing.T) {
	dir := pluginDir(t)
	c, clock := newTestClient(dir)
	p := &fakePlugin{respond: func(req *api.CredentialRequest, n int32) (int, any) {
		return http.StatusOK, tokenResponse(fmt.Sprintf("%s-%d", req.Cluster, n), clock.Now().Add(15*time.Minute))
	}}
	startPlugin(t, dir, "aws", p)
	ctx := context.Background()

	a, err := c.Get(ctx, "aws", "a", []byte(`{"roleArn":"r1"}`))
	require.NoError(t, err)
	b, err := c.Get(ctx, "aws", "b", []byte(`{"roleArn":"r1"}`))
	require.NoError(t, err)
	a2, err := c.Get(ctx, "aws", "a", []byte(`{"roleArn":"r2"}`))
	require.NoError(t, err)

	assert.Equal(t, "a-1", a.Token)
	assert.Equal(t, "b-2", b.Token)
	assert.Equal(t, "a-3", a2.Token)
}

func TestGetSharesOneMintBetweenConcurrentCallers(t *testing.T) {
	dir := pluginDir(t)
	c, clock := newTestClient(dir)
	release := make(chan struct{})
	p := &fakePlugin{blockFor: release, respond: func(_ *api.CredentialRequest, _ int32) (int, any) {
		return http.StatusOK, tokenResponse("token", clock.Now().Add(15*time.Minute))
	}}
	startPlugin(t, dir, "aws", p)

	const callers = 20
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.Get(context.Background(), "aws", "prod", nil)
			errs <- err
		}()
	}
	require.Eventually(t, func() bool { return p.calls.Load() == 1 }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		assert.NoError(t, err)
	}
	assert.EqualValues(t, 1, p.calls.Load())
}

func TestGetServesCachedCredentialWhileRefreshFails(t *testing.T) {
	dir := pluginDir(t)
	c, clock := newTestClient(dir)
	p := &fakePlugin{respond: func(_ *api.CredentialRequest, n int32) (int, any) {
		if n == 1 {
			return http.StatusOK, tokenResponse("secret-token", clock.Now().Add(15*time.Minute))
		}
		return http.StatusServiceUnavailable, &api.Error{Message: "sts unavailable"}
	}}
	startPlugin(t, dir, "aws", p)
	ctx := context.Background()

	_, err := c.Get(ctx, "aws", "prod", nil)
	require.NoError(t, err)

	clock.Advance(13 * time.Minute)
	cred, err := c.Get(ctx, "aws", "prod", nil)
	require.NoError(t, err)
	assert.Equal(t, "secret-token", cred.Token)

	clock.Advance(2 * time.Minute)
	_, err = c.Get(ctx, "aws", "prod", nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "sts unavailable")
	assert.NotContains(t, err.Error(), "secret-token")
}

func TestGetErrors(t *testing.T) {
	dir := pluginDir(t)
	startPlugin(t, dir, "noexpiry", &fakePlugin{respond: func(_ *api.CredentialRequest, _ int32) (int, any) {
		return http.StatusOK, &api.ExecCredential{
			APIVersion: api.ExecCredentialAPIVersion, Kind: api.ExecCredentialKind,
			Status: &api.ExecCredentialStatus{Token: "secret-token"},
		}
	}})
	startPlugin(t, dir, "expired", &fakePlugin{respond: func(_ *api.CredentialRequest, _ int32) (int, any) {
		return http.StatusOK, tokenResponse("secret-token", time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC))
	}})
	startPlugin(t, dir, "empty", &fakePlugin{respond: func(_ *api.CredentialRequest, _ int32) (int, any) {
		return http.StatusOK, &api.ExecCredential{
			APIVersion: api.ExecCredentialAPIVersion, Kind: api.ExecCredentialKind,
			Status: &api.ExecCredentialStatus{ExpirationTimestamp: &time.Time{}},
		}
	}})
	startPlugin(t, dir, "certonly", &fakePlugin{respond: func(_ *api.CredentialRequest, _ int32) (int, any) {
		expiry := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
		return http.StatusOK, &api.ExecCredential{
			APIVersion: api.ExecCredentialAPIVersion, Kind: api.ExecCredentialKind,
			Status: &api.ExecCredentialStatus{ClientCertificateData: "cert", ExpirationTimestamp: &expiry},
		}
	}})
	startPlugin(t, dir, "denied", &fakePlugin{respond: func(_ *api.CredentialRequest, _ int32) (int, any) {
		return http.StatusForbidden, &api.Error{Message: "role not in allowlist"}
	}})
	startPlugin(t, dir, "wrongkind", &fakePlugin{respond: func(_ *api.CredentialRequest, _ int32) (int, any) {
		return http.StatusOK, map[string]string{"apiVersion": "v1", "kind": "Secret"}
	}})
	c, _ := newTestClient(dir)

	cases := map[string]string{
		"":          "invalid credential provider name",
		"../etc":    "invalid credential provider name",
		"AWS":       "invalid credential provider name",
		"gcp":       `credential plugin "gcp" is not installed`,
		"noexpiry":  "without an expirationTimestamp",
		"expired":   "already expired",
		"empty":     "neither a token nor a client certificate and key",
		"certonly":  "neither a token nor a client certificate and key",
		"denied":    "role not in allowlist",
		"wrongkind": "unexpected response v1, Kind=Secret",
	}
	for provider, want := range cases {
		t.Run(provider, func(t *testing.T) {
			_, err := c.Get(context.Background(), provider, "prod", nil)
			require.Error(t, err)
			assert.Contains(t, err.Error(), want)
			assert.NotContains(t, err.Error(), "secret-token")
		})
	}
}

func TestGetClientCertificate(t *testing.T) {
	dir := pluginDir(t)
	c, clock := newTestClient(dir)
	startPlugin(t, dir, "pki", &fakePlugin{respond: func(_ *api.CredentialRequest, _ int32) (int, any) {
		expiry := clock.Now().Add(time.Hour)
		return http.StatusOK, &api.ExecCredential{
			APIVersion: api.ExecCredentialAPIVersion, Kind: api.ExecCredentialKind,
			Status: &api.ExecCredentialStatus{ClientCertificateData: "cert", ClientKeyData: "key", ExpirationTimestamp: &expiry},
		}
	}})

	cred, err := c.Get(context.Background(), "pki", "prod", nil)
	require.NoError(t, err)
	assert.Equal(t, []byte("cert"), cred.Certificate)
	assert.Equal(t, []byte("key"), cred.PrivateKey)
	assert.Empty(t, cred.Token)
	assert.True(t, strings.HasPrefix(cred.Expiry.String(), "2026-01-01 01:00:00"))
}
