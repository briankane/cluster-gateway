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

// Package plugin serves the credential plugin protocol, so a plugin only has to
// mint credentials. It depends on the standard library only.
package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/api"
)

const maxRequestSize = 1 << 20

// Minter mints a credential for one request. The returned status must carry an
// ExpirationTimestamp; the gateway rejects credentials without one.
type Minter interface {
	Mint(ctx context.Context, req *api.CredentialRequest) (*api.ExecCredentialStatus, error)
}

// MinterFunc adapts a function to Minter.
type MinterFunc func(ctx context.Context, req *api.CredentialRequest) (*api.ExecCredentialStatus, error)

func (f MinterFunc) Mint(ctx context.Context, req *api.CredentialRequest) (*api.ExecCredentialStatus, error) {
	return f(ctx, req)
}

type statusError struct {
	code int
	err  error
}

func (e *statusError) Error() string { return e.err.Error() }
func (e *statusError) Unwrap() error { return e.err }

// BadRequest marks err as caused by the request, typically invalid provider-config.
func BadRequest(err error) error { return &statusError{code: http.StatusBadRequest, err: err} }

// Forbidden marks err as a refusal by the plugin's own policy, such as an allowlist.
func Forbidden(err error) error { return &statusError{code: http.StatusForbidden, err: err} }

// Handler serves api.CredentialPath with m. Errors from m are returned to the
// gateway as their message; they must never contain a credential.
func Handler(m Minter) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(api.CredentialPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		req := &api.CredentialRequest{}
		if err := json.NewDecoder(io.LimitReader(r.Body, maxRequestSize)).Decode(req); err != nil {
			writeError(w, http.StatusBadRequest, fmt.Errorf("malformed request: %v", err))
			return
		}
		if req.APIVersion != api.RequestAPIVersion || req.Kind != api.RequestKind {
			writeError(w, http.StatusBadRequest, fmt.Errorf("unsupported request %s, Kind=%s", req.APIVersion, req.Kind))
			return
		}
		if req.Cluster == "" {
			writeError(w, http.StatusBadRequest, errors.New("cluster is required"))
			return
		}
		status, err := m.Mint(r.Context(), req)
		if err != nil {
			code := http.StatusInternalServerError
			var se *statusError
			if errors.As(err, &se) {
				code = se.code
			}
			log.Printf("cluster %q: %v", req.Cluster, err)
			writeError(w, code, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(&api.ExecCredential{
			APIVersion: api.ExecCredentialAPIVersion,
			Kind:       api.ExecCredentialKind,
			Status:     status,
		})
	})
	return mux
}

func writeError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(&api.Error{Message: err.Error()})
}

// Serve listens on socket until ctx is done. The socket is created with mode
// 0660, so the gateway reaches it through a shared group (the pod's fsGroup)
// rather than by running as the plugin's user.
func Serve(ctx context.Context, socket string, m Minter) error {
	if err := os.Remove(socket); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing stale socket %s: %w", socket, err)
	}
	l, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(socket, 0660); err != nil {
		_ = l.Close()
		return fmt.Errorf("setting socket permissions: %w", err)
	}
	srv := &http.Server{Handler: Handler(m), ReadHeaderTimeout: 10 * time.Second}
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(l) }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}
