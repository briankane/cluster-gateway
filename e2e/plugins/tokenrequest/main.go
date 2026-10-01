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

// Command tokenrequest is a credential plugin for e2e tests. It mints short-lived
// tokens for one ServiceAccount of the cluster it runs in, so the Provider
// credential type can be exercised without a cloud account.
package main

import (
	"context"
	"flag"
	"log"
	"os/signal"
	"syscall"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/ptr"

	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/api"
	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/plugin"
)

func main() {
	socket := flag.String("socket", "/var/run/cluster-gateway/plugins/tokenrequest.sock", "unix socket to serve on")
	namespace := flag.String("namespace", "vela-system", "namespace of the ServiceAccount")
	serviceAccount := flag.String("service-account", "e2e-provider-spoke", "ServiceAccount to mint tokens for")
	expiration := flag.Int64("expiration-seconds", 600, "requested token lifetime")
	flag.Parse()

	cfg, err := rest.InClusterConfig()
	if err != nil {
		log.Fatal(err)
	}
	client := kubernetes.NewForConfigOrDie(cfg)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err = plugin.Serve(ctx, *socket, plugin.MinterFunc(func(ctx context.Context, _ *api.CredentialRequest) (*api.ExecCredentialStatus, error) {
		tr, err := client.CoreV1().ServiceAccounts(*namespace).CreateToken(ctx, *serviceAccount, &authenticationv1.TokenRequest{
			Spec: authenticationv1.TokenRequestSpec{ExpirationSeconds: ptr.To(*expiration)},
		}, metav1.CreateOptions{})
		if err != nil {
			return nil, err
		}
		expiry := tr.Status.ExpirationTimestamp.Time
		return &api.ExecCredentialStatus{Token: tr.Status.Token, ExpirationTimestamp: &expiry}, nil
	}))
	if err != nil {
		log.Fatal(err)
	}
}
