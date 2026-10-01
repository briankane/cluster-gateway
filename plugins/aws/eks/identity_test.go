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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/config"
)

// These tests set the environment the chart renders onto the plugin container and
// check that the SDK's default chain, which the plugin loads, turns it into
// credentials. AWS is replaced by local endpoints.

func writeToken(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

// isolateEnv stops the developer's own AWS configuration leaking into a test.
func isolateEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{"AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
		"AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
		"AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_STS"} {
		t.Setenv(v, "")
	}
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
}

func TestIRSAEnvironment(t *testing.T) {
	isolateEnv(t)
	var gotToken, gotRole string
	sts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Form.Get("Action") != "AssumeRoleWithWebIdentity" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		gotToken, gotRole = r.Form.Get("WebIdentityToken"), r.Form.Get("RoleArn")
		w.Header().Set("Content-Type", "text/xml")
		fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <Credentials>
      <AccessKeyId>AKIDIRSA</AccessKeyId><SecretAccessKey>s</SecretAccessKey><SessionToken>t</SessionToken>
      <Expiration>%s</Expiration>
    </Credentials>
  </AssumeRoleWithWebIdentityResult>
</AssumeRoleWithWebIdentityResponse>`, time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	defer sts.Close()

	t.Setenv("AWS_REGION", "eu-west-1")
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::111111111111:role/vela-cluster-gateway")
	t.Setenv("AWS_WEB_IDENTITY_TOKEN_FILE", writeToken(t, "projected-sa-token"))
	t.Setenv("AWS_ENDPOINT_URL_STS", sts.URL)

	cfg, err := config.LoadDefaultConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "AKIDIRSA" {
		t.Errorf("credentials not from web identity: %s via %s", creds.AccessKeyID, creds.Source)
	}
	if gotToken != "projected-sa-token" || gotRole != "arn:aws:iam::111111111111:role/vela-cluster-gateway" {
		t.Errorf("AssumeRoleWithWebIdentity got token %q, role %q", gotToken, gotRole)
	}
}

func TestPodIdentityEnvironment(t *testing.T) {
	isolateEnv(t)
	var gotAuth string
	agent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"AccessKeyId":"AKIDPODIDENTITY","SecretAccessKey":"s","Token":"t","Expiration":"%s"}`,
			time.Now().Add(time.Hour).UTC().Format(time.RFC3339))
	}))
	defer agent.Close()

	// The chart points at the EKS Pod Identity Agent (169.254.170.23); the SDK
	// accepts loopback in its place.
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", agent.URL+"/v1/credentials")
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", writeToken(t, "pod-identity-token"))

	cfg, err := config.LoadDefaultConfig(context.Background(), config.WithRegion("eu-west-1"))
	if err != nil {
		t.Fatal(err)
	}
	creds, err := cfg.Credentials.Retrieve(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if creds.AccessKeyID != "AKIDPODIDENTITY" {
		t.Errorf("credentials not from the Pod Identity agent: %s via %s", creds.AccessKeyID, creds.Source)
	}
	if gotAuth != "pod-identity-token" {
		t.Errorf("agent got Authorization %q, want the projected token", gotAuth)
	}
}
