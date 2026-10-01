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

// Package api defines the protocol between cluster-gateway and its credential
// plugins. It depends on the standard library only, so that plugins can import
// it without the gateway's dependencies.
//
// A plugin listens on a unix socket named <provider>.sock in the gateway's plugin
// directory and serves POST CredentialPath. The request body is a
// CredentialRequest; a successful response is an ExecCredential with an
// expirationTimestamp, the same shape a kubeconfig exec plugin prints. Any other
// status carries an Error.
package api

import (
	"encoding/json"
	"time"
)

const (
	// CredentialPath is the HTTP path a plugin serves.
	CredentialPath = "/v1alpha1/credential"

	// RequestAPIVersion and RequestKind identify a CredentialRequest.
	RequestAPIVersion = "credentialprovider.cluster.core.oam.dev/v1alpha1"
	RequestKind       = "CredentialRequest"

	// ExecCredentialAPIVersion and ExecCredentialKind identify the response.
	ExecCredentialAPIVersion = "client.authentication.k8s.io/v1"
	ExecCredentialKind       = "ExecCredential"
)

// CredentialRequest asks a plugin for a credential to one cluster.
type CredentialRequest struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	// Cluster is the ClusterGateway name.
	Cluster string `json:"cluster"`
	// Config is the cluster Secret's provider-config, passed through verbatim.
	// Its schema belongs to the plugin.
	Config json.RawMessage `json:"config,omitempty"`
}

// ExecCredential mirrors client.authentication.k8s.io/v1 ExecCredential.
type ExecCredential struct {
	APIVersion string                `json:"apiVersion"`
	Kind       string                `json:"kind"`
	Status     *ExecCredentialStatus `json:"status,omitempty"`
}

// ExecCredentialStatus holds either a bearer token or a client certificate and key.
type ExecCredentialStatus struct {
	ExpirationTimestamp   *time.Time `json:"expirationTimestamp,omitempty"`
	Token                 string     `json:"token,omitempty"`
	ClientCertificateData string     `json:"clientCertificateData,omitempty"`
	ClientKeyData         string     `json:"clientKeyData,omitempty"`
}

// Error is the body of a non-200 response.
type Error struct {
	Message string `json:"message"`
}
