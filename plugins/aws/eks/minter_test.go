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

package eks

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/api"
	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/plugin"
)

var testNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func newTestMinter(t *testing.T, opts Options) *Minter {
	t.Helper()
	opts.Base = aws.Config{Credentials: credentials.NewStaticCredentialsProvider("AKIDPODIDENTITY", "SECRETKEYVALUE", "SESSIONTOKENVALUE")}
	m, err := NewMinter(opts)
	if err != nil {
		t.Fatal(err)
	}
	m.now = func() time.Time { return testNow }
	return m
}

func request(config string) *api.CredentialRequest {
	return &api.CredentialRequest{
		APIVersion: api.RequestAPIVersion,
		Kind:       api.RequestKind,
		Cluster:    "prod-eu",
		Config:     json.RawMessage(config),
	}
}

// decodeToken returns the presigned URL inside an EKS token.
func decodeToken(t *testing.T, token string) *url.URL {
	t.Helper()
	const prefix = "k8s-aws-v1."
	if !strings.HasPrefix(token, prefix) {
		t.Fatalf("token lacks prefix %q", prefix)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(token, prefix))
	if err != nil {
		t.Fatalf("token is not base64url: %v", err)
	}
	u, err := url.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestMintToken(t *testing.T) {
	m := newTestMinter(t, Options{AllowPodIdentity: true})
	status, err := m.Mint(context.Background(), request(`{"region":"eu-west-1","clusterName":"prod"}`))
	if err != nil {
		t.Fatal(err)
	}

	u := decodeToken(t, status.Token)
	q := u.Query()
	checks := map[string][2]string{
		"scheme":         {"https", u.Scheme},
		"host":           {"sts.eu-west-1.amazonaws.com", u.Host},
		"Action":         {"GetCallerIdentity", q.Get("Action")},
		"X-Amz-Expires":  {"60", q.Get("X-Amz-Expires")},
		"signed headers": {"host;x-k8s-aws-id", q.Get("X-Amz-SignedHeaders")},
	}
	for name, c := range checks {
		if c[0] != c[1] {
			t.Errorf("%s: want %q, got %q", name, c[0], c[1])
		}
	}
	if !strings.HasPrefix(q.Get("X-Amz-Credential"), "AKIDPODIDENTITY/") || !strings.Contains(q.Get("X-Amz-Credential"), "/eu-west-1/sts/aws4_request") {
		t.Errorf("unexpected X-Amz-Credential %q", q.Get("X-Amz-Credential"))
	}
	if want := testNow.Add(14 * time.Minute); !status.ExpirationTimestamp.Equal(want) {
		t.Errorf("expiry: want %s, got %s", want, status.ExpirationTimestamp)
	}
}

func TestMintRejects(t *testing.T) {
	m := newTestMinter(t, Options{
		AllowPodIdentity: false,
		AllowedRoleARNs:  []string{"arn:aws:iam::111111111111:role/vela-hub", "arn:aws:iam::222222222222:role/*"},
	})
	cases := []struct {
		name   string
		config string
		want   string
		forbid bool
	}{
		{"no config", ``, "provider-config is required", false},
		{"not json", `nope`, "invalid provider-config", false},
		{"unknown field", `{"region":"eu-west-1","clusterName":"prod","role":"x"}`, "unknown field", false},
		{"no region", `{"clusterName":"prod"}`, "region is required", false},
		{"bad region", `{"region":"EU WEST","clusterName":"prod"}`, "invalid region", false},
		{"no cluster", `{"region":"eu-west-1"}`, "clusterName is required", false},
		{"bad cluster", `{"region":"eu-west-1","clusterName":"prod/../x"}`, "invalid clusterName", false},
		{"pod identity disabled", `{"region":"eu-west-1","clusterName":"prod"}`, "roleArn is required", true},
		{"role not allowed", `{"region":"eu-west-1","clusterName":"prod","roleArn":"arn:aws:iam::333333333333:role/x"}`, "not in the allowlist", true},
		{"prefix is not a wildcard", `{"region":"eu-west-1","clusterName":"prod","roleArn":"arn:aws:iam::111111111111:role/vela-hub-admin"}`, "not in the allowlist", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := m.Mint(context.Background(), request(c.config))
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
			if got := isForbidden(err); got != c.forbid {
				t.Errorf("forbidden: want %v, got %v (%v)", c.forbid, got, err)
			}
		})
	}
}

func TestNewMinterValidatesAllowlist(t *testing.T) {
	for _, entry := range []string{"", "*", "arn:aws:iam::*", "role/x", "arn:aws:iam::111111111111:role/a*b"} {
		if _, err := NewMinter(Options{AllowedRoleARNs: []string{entry}}); err == nil {
			t.Errorf("allowlist entry %q accepted", entry)
		}
	}
}

// fakeSTS answers AssumeRole with fixed credentials and counts the calls.
func fakeSTS(t *testing.T, calls *atomic.Int32, gotRole *atomic.Value) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil || r.Form.Get("Action") != "AssumeRole" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		calls.Add(1)
		gotRole.Store(r.Form.Get("RoleArn") + "|" + r.Form.Get("RoleSessionName"))
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>AKIDASSUMED</AccessKeyId>
      <SecretAccessKey>secret</SecretAccessKey>
      <SessionToken>session</SessionToken>
      <Expiration>%s</Expiration>
    </Credentials>
    <AssumedRoleUser><Arn>arn:aws:sts::222222222222:assumed-role/vela-hub/cluster-gateway</Arn><AssumedRoleId>AROA:cluster-gateway</AssumedRoleId></AssumedRoleUser>
  </AssumeRoleResult>
</AssumeRoleResponse>`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
}

func TestMintWithAssumedRole(t *testing.T) {
	var calls atomic.Int32
	var gotRole atomic.Value
	srv := fakeSTS(t, &calls, &gotRole)
	defer srv.Close()

	m := newTestMinter(t, Options{AllowedRoleARNs: []string{"arn:aws:iam::222222222222:role/*"}, SessionName: "cluster-gateway"})
	m.assumeRoleEndpoint = srv.URL

	config := `{"region":"eu-west-1","clusterName":"prod","roleArn":"arn:aws:iam::222222222222:role/vela-hub"}`
	for i := 0; i < 3; i++ {
		status, err := m.Mint(context.Background(), request(config))
		if err != nil {
			t.Fatal(err)
		}
		if cred := decodeToken(t, status.Token).Query().Get("X-Amz-Credential"); !strings.HasPrefix(cred, "AKIDASSUMED/") {
			t.Fatalf("token not signed with the assumed role: %q", cred)
		}
	}
	if got := gotRole.Load(); got != "arn:aws:iam::222222222222:role/vela-hub|cluster-gateway" {
		t.Errorf("AssumeRole called with %v", got)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("assumed role credentials not cached: %d AssumeRole calls", n)
	}
}

func TestMintErrorsDoNotLeakCredentials(t *testing.T) {
	m := newTestMinter(t, Options{AllowedRoleARNs: []string{"arn:aws:iam::222222222222:role/*"}})
	m.assumeRoleEndpoint = "http://127.0.0.1:1"
	_, err := m.Mint(context.Background(), request(`{"region":"eu-west-1","clusterName":"prod","roleArn":"arn:aws:iam::222222222222:role/vela-hub"}`))
	if err == nil {
		t.Fatal("expected an error from an unreachable STS")
	}
	for _, secret := range []string{"AKIDPODIDENTITY", "SECRETKEYVALUE", "SESSIONTOKENVALUE"} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("error leaks %q: %v", secret, err)
		}
	}
}

func isForbidden(err error) bool {
	return plugin.StatusCode(err) == http.StatusForbidden
}
