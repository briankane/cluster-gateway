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

// Package eks mints EKS bearer tokens for the AWS credential plugin.
package eks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/api"
	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/plugin"
)

const (
	tokenPrefix = "k8s-aws-v1."
	// clusterIDHeader binds the token to one EKS cluster.
	clusterIDHeader = "x-k8s-aws-id"
	// presignExpiry is how long the presigned URL is valid. EKS accepts the token
	// for 15 minutes from signing regardless, which tokenLifetime stays inside.
	presignExpiry = "60"
	tokenLifetime = 14 * time.Minute
)

var (
	regionPattern  = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	clusterPattern = regexp.MustCompile(`^[0-9A-Za-z][A-Za-z0-9_-]{0,99}$`)
	rolePattern    = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/[\w+=,.@/-]+$`)
)

// providerConfig is the provider-config a cluster Secret passes to this plugin.
type providerConfig struct {
	Region      string `json:"region"`
	ClusterName string `json:"clusterName"`
	// RoleARN is assumed before signing. It must match the plugin's allowlist.
	RoleARN string `json:"roleArn,omitempty"`
}

// Options configure a Minter. The allowlist is the plugin's own configuration,
// never the cluster Secret's: whoever can write a Secret must not be able to
// choose which roles the gateway assumes.
type Options struct {
	// Base supplies the pod's own credentials, normally IRSA or EKS Pod Identity.
	Base aws.Config
	// AllowPodIdentity lets clusters without a roleArn be signed with Base directly.
	AllowPodIdentity bool
	// AllowedRoleARNs lists role ARNs that may be assumed. An entry ending in
	// ":role/*" allows every role in that account.
	AllowedRoleARNs []string
	// SessionName is the RoleSessionName for assumed roles, visible in CloudTrail
	// and in the username EKS maps the identity to.
	SessionName string
}

// Minter mints EKS bearer tokens.
type Minter struct {
	opts         Options
	exactRoles   map[string]bool
	accountRoles []string

	now func() time.Time
	// assumeRoleEndpoint overrides the STS endpoint used for AssumeRole.
	assumeRoleEndpoint string

	mu    sync.Mutex
	roles map[string]aws.CredentialsProvider
}

// NewMinter validates the allowlist and returns a Minter.
func NewMinter(opts Options) (*Minter, error) {
	m := &Minter{opts: opts, exactRoles: map[string]bool{}, now: time.Now, roles: map[string]aws.CredentialsProvider{}}
	if m.opts.SessionName == "" {
		m.opts.SessionName = "cluster-gateway"
	}
	for _, entry := range opts.AllowedRoleARNs {
		if prefix, ok := strings.CutSuffix(entry, ":role/*"); ok && rolePattern.MatchString(prefix+":role/x") {
			m.accountRoles = append(m.accountRoles, prefix+":role/")
			continue
		}
		if !rolePattern.MatchString(entry) {
			return nil, fmt.Errorf("invalid allowlist entry %q: want a role ARN, or arn:<partition>:iam::<account>:role/* for every role in an account", entry)
		}
		m.exactRoles[entry] = true
	}
	return m, nil
}

func (m *Minter) roleAllowed(arn string) bool {
	if m.exactRoles[arn] {
		return true
	}
	for _, prefix := range m.accountRoles {
		if strings.HasPrefix(arn, prefix) {
			return true
		}
	}
	return false
}

// Mint returns a token for the EKS cluster described by req.Config.
func (m *Minter) Mint(ctx context.Context, req *api.CredentialRequest) (*api.ExecCredentialStatus, error) {
	cfg, err := parseConfig(req.Config)
	if err != nil {
		return nil, plugin.BadRequest(err)
	}

	creds := m.opts.Base.Credentials
	switch {
	case cfg.RoleARN != "":
		if !m.roleAllowed(cfg.RoleARN) {
			return nil, plugin.Forbidden(fmt.Errorf("roleArn %s is not in the allowlist", cfg.RoleARN))
		}
		creds = m.assumedRole(cfg.Region, cfg.RoleARN)
	case !m.opts.AllowPodIdentity:
		return nil, plugin.Forbidden(errors.New("roleArn is required: signing with the plugin's own identity is disabled"))
	}

	signedAt := m.now()
	token, err := m.presign(ctx, cfg.Region, cfg.ClusterName, creds)
	if err != nil {
		return nil, err
	}
	expiry := signedAt.Add(tokenLifetime)
	return &api.ExecCredentialStatus{Token: token, ExpirationTimestamp: &expiry}, nil
}

func parseConfig(raw json.RawMessage) (*providerConfig, error) {
	if len(raw) == 0 {
		return nil, errors.New("provider-config is required")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	cfg := &providerConfig{}
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("invalid provider-config: %v", err)
	}
	switch {
	case cfg.Region == "":
		return nil, errors.New("region is required")
	case !regionPattern.MatchString(cfg.Region):
		return nil, fmt.Errorf("invalid region %q", cfg.Region)
	case cfg.ClusterName == "":
		return nil, errors.New("clusterName is required")
	case !clusterPattern.MatchString(cfg.ClusterName):
		return nil, fmt.Errorf("invalid clusterName %q", cfg.ClusterName)
	case cfg.RoleARN != "" && !rolePattern.MatchString(cfg.RoleARN):
		return nil, fmt.Errorf("invalid roleArn %q", cfg.RoleARN)
	}
	return cfg, nil
}

// assumedRole returns a cached provider for the role, which refreshes the
// assumed credentials before they expire.
func (m *Minter) assumedRole(region, roleARN string) aws.CredentialsProvider {
	key := region + "|" + roleARN
	m.mu.Lock()
	defer m.mu.Unlock()
	if p, ok := m.roles[key]; ok {
		return p
	}
	client := sts.NewFromConfig(m.opts.Base, func(o *sts.Options) {
		o.Region = region
		if m.assumeRoleEndpoint != "" {
			o.BaseEndpoint = aws.String(m.assumeRoleEndpoint)
		}
	})
	p := aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(client, roleARN, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = m.opts.SessionName
	}))
	m.roles[key] = p
	return p
}

// presign builds the token: a presigned STS GetCallerIdentity URL carrying the
// cluster name as a signed header. EKS replays it to STS to learn the caller.
func (m *Minter) presign(ctx context.Context, region, cluster string, creds aws.CredentialsProvider) (string, error) {
	client := sts.NewFromConfig(m.opts.Base, func(o *sts.Options) {
		o.Region = region
		o.Credentials = creds
	})
	req, err := sts.NewPresignClient(client).PresignGetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}, func(po *sts.PresignOptions) {
		po.ClientOptions = append(po.ClientOptions, func(o *sts.Options) {
			o.APIOptions = append(o.APIOptions,
				smithyhttp.SetHeaderValue(clusterIDHeader, cluster),
				smithyhttp.SetHeaderValue("X-Amz-Expires", presignExpiry))
		})
	})
	if err != nil {
		return "", fmt.Errorf("presigning GetCallerIdentity in %s: %w", region, err)
	}
	return tokenPrefix + base64.RawURLEncoding.EncodeToString([]byte(req.URL)), nil
}
