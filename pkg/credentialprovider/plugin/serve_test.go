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

package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider"
	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/api"
)

func post(t *testing.T, h http.Handler, method, path string, body any) *httptest.ResponseRecorder {
	t.Helper()
	raw, err := json.Marshal(body)
	require.NoError(t, err)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, bytes.NewReader(raw)))
	return rec
}

func validRequest() *api.CredentialRequest {
	return &api.CredentialRequest{
		APIVersion: api.RequestAPIVersion,
		Kind:       api.RequestKind,
		Cluster:    "prod",
		Config:     json.RawMessage(`{"region":"eu-west-1"}`),
	}
}

func TestHandler(t *testing.T) {
	expiry := time.Date(2026, 1, 1, 0, 15, 0, 0, time.UTC)
	h := Handler(MinterFunc(func(_ context.Context, req *api.CredentialRequest) (*api.ExecCredentialStatus, error) {
		switch req.Cluster {
		case "denied":
			return nil, Forbidden(errors.New("role not in allowlist"))
		case "invalid":
			return nil, BadRequest(errors.New("region is required"))
		case "broken":
			return nil, errors.New("sts unavailable")
		}
		return &api.ExecCredentialStatus{Token: "tok-" + req.Cluster, ExpirationTimestamp: &expiry}, nil
	}))

	rec := post(t, h, http.MethodPost, api.CredentialPath, validRequest())
	require.Equal(t, http.StatusOK, rec.Code)
	ec := &api.ExecCredential{}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), ec))
	assert.Equal(t, api.ExecCredentialAPIVersion, ec.APIVersion)
	assert.Equal(t, api.ExecCredentialKind, ec.Kind)
	assert.Equal(t, "tok-prod", ec.Status.Token)

	cases := []struct {
		name    string
		method  string
		path    string
		body    any
		code    int
		message string
	}{
		{"wrong path", http.MethodPost, "/other", validRequest(), http.StatusNotFound, ""},
		{"wrong method", http.MethodGet, api.CredentialPath, validRequest(), http.StatusMethodNotAllowed, ""},
		{"not json", http.MethodPost, api.CredentialPath, "nope", http.StatusBadRequest, "malformed request"},
		{"wrong kind", http.MethodPost, api.CredentialPath, &api.CredentialRequest{APIVersion: "v1", Kind: "Pod", Cluster: "prod"}, http.StatusBadRequest, "unsupported request"},
		{"no cluster", http.MethodPost, api.CredentialPath, &api.CredentialRequest{APIVersion: api.RequestAPIVersion, Kind: api.RequestKind}, http.StatusBadRequest, "cluster is required"},
		{"forbidden", http.MethodPost, api.CredentialPath, func() any { r := validRequest(); r.Cluster = "denied"; return r }(), http.StatusForbidden, "role not in allowlist"},
		{"bad request", http.MethodPost, api.CredentialPath, func() any { r := validRequest(); r.Cluster = "invalid"; return r }(), http.StatusBadRequest, "region is required"},
		{"internal", http.MethodPost, api.CredentialPath, func() any { r := validRequest(); r.Cluster = "broken"; return r }(), http.StatusInternalServerError, "sts unavailable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := post(t, h, c.method, c.path, c.body)
			assert.Equal(t, c.code, rec.Code)
			if c.message != "" {
				e := &api.Error{}
				require.NoError(t, json.Unmarshal(rec.Body.Bytes(), e))
				assert.Contains(t, e.Message, c.message)
			}
		})
	}
}

func TestServeOverSocket(t *testing.T) {
	dir, err := os.MkdirTemp("", "cgp")
	require.NoError(t, err)
	defer os.RemoveAll(dir)
	socket := filepath.Join(dir, "fake.sock")
	// A socket left behind by a previous run must not stop the plugin starting.
	require.NoError(t, os.WriteFile(socket, nil, 0600))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		done <- Serve(ctx, socket, MinterFunc(func(_ context.Context, req *api.CredentialRequest) (*api.ExecCredentialStatus, error) {
			expiry := time.Now().Add(time.Hour)
			return &api.ExecCredentialStatus{Token: "tok-" + req.Cluster, ExpirationTimestamp: &expiry}, nil
		}))
	}()

	c := credentialprovider.NewClient(dir)
	var cred *credentialprovider.Credential
	require.Eventually(t, func() bool {
		cred, err = c.Get(context.Background(), "fake", "prod", nil)
		return err == nil
	}, 5*time.Second, 20*time.Millisecond)
	assert.Equal(t, "tok-prod", cred.Token)

	info, err := os.Stat(socket)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0660), info.Mode().Perm())

	cancel()
	require.NoError(t, <-done)
	_, err = os.Stat(socket)
	assert.True(t, os.IsNotExist(err), "socket removed on shutdown")
}
