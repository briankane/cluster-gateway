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

package conformance

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"sigs.k8s.io/aws-iam-authenticator/pkg/token"

	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/api"
	"github.com/oam-dev/cluster-gateway/plugins/aws/eks"
)

const (
	region      = "eu-west-1"
	clusterName = "prod"
	callerARN   = "arn:aws:sts::111111111111:assumed-role/vela-hub/cluster-gateway"
)

var signingCreds = aws.Credentials{AccessKeyID: "AKIDTEST", SecretAccessKey: "SECRETKEYVALUE", SessionToken: "SESSIONTOKENVALUE"}

// fakeSTS answers GetCallerIdentity as STS does: only if the request, as the
// verifier replays it, still carries a valid SigV4 signature for signingCreds.
func fakeSTS(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		got := q.Get("X-Amz-Signature")
		signedAt, err := time.Parse("20060102T150405Z", q.Get("X-Amz-Date"))
		if err != nil {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		q.Del("X-Amz-Signature")
		u := url.URL{Scheme: "https", Host: r.Host, Path: r.URL.Path, RawQuery: q.Encode()}
		req, _ := http.NewRequest(http.MethodGet, u.String(), nil)
		req.Header.Set("x-k8s-aws-id", r.Header.Get("x-k8s-aws-id"))
		emptyBody := sha256.Sum256(nil)
		want, _, err := v4.NewSigner().PresignHTTP(context.Background(), signingCreds, req, hex.EncodeToString(emptyBody[:]), "sts", region, signedAt)
		if err != nil {
			t.Error(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		wantURL, _ := url.Parse(want)
		if wantURL.Query().Get("X-Amz-Signature") != got {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"GetCallerIdentityResponse":{"GetCallerIdentityResult":{"Account":"111111111111","Arn":"` + callerARN + `","UserId":"AROAEXAMPLE:cluster-gateway"}}}`))
	}))
}

// routeSTS sends the verifier's requests for the real STS hostname to srv.
func routeSTS(t *testing.T, srv *httptest.Server) {
	t.Helper()
	prev := http.DefaultTransport
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		},
	}
	t.Cleanup(func() { http.DefaultTransport = prev })
}

func mint(t *testing.T) string {
	t.Helper()
	m, err := eks.NewMinter(eks.Options{
		AllowBaseIdentity: true,
		Base:              aws.Config{Credentials: credentials.StaticCredentialsProvider{Value: signingCreds}},
	})
	if err != nil {
		t.Fatal(err)
	}
	status, err := m.Mint(context.Background(), &api.CredentialRequest{
		APIVersion: api.RequestAPIVersion,
		Kind:       api.RequestKind,
		Cluster:    "gateway-name",
		Config:     json.RawMessage(`{"region":"` + region + `","clusterName":"` + clusterName + `"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	return status.Token
}

func TestEKSAcceptsToken(t *testing.T) {
	routeSTS(t, fakeSTS(t))
	id, err := token.NewVerifier(clusterName, "aws", region).Verify(mint(t))
	if err != nil {
		t.Fatalf("EKS verifier rejected the token: %v", err)
	}
	if id.ARN != callerARN {
		t.Errorf("ARN: want %s, got %s", callerARN, id.ARN)
	}
	// Access entries match the role, not the session.
	if want := "arn:aws:iam::111111111111:role/vela-hub"; id.CanonicalARN != want {
		t.Errorf("canonical ARN: want %s, got %s", want, id.CanonicalARN)
	}
}

func TestEKSRejectsTokenForAnotherCluster(t *testing.T) {
	routeSTS(t, fakeSTS(t))
	if _, err := token.NewVerifier("another-cluster", "aws", region).Verify(mint(t)); err == nil {
		t.Fatal("a token signed for one cluster was accepted by another")
	}
}

func TestEKSRejectsTamperedToken(t *testing.T) {
	routeSTS(t, fakeSTS(t))
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(mint(t), "k8s-aws-v1."))
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("X-Amz-Date", time.Now().UTC().Add(time.Minute).Format("20060102T150405Z"))
	u.RawQuery = q.Encode()
	tampered := "k8s-aws-v1." + base64.RawURLEncoding.EncodeToString([]byte(u.String()))
	if _, err := token.NewVerifier(clusterName, "aws", region).Verify(tampered); err == nil {
		t.Fatal("a token with a modified signing date was accepted")
	}
}
