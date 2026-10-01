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

// Command aws is a cluster-gateway credential plugin that mints EKS bearer
// tokens from the pod's AWS identity (IRSA or EKS Pod Identity), optionally
// assuming an allowlisted role per cluster.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/aws/aws-sdk-go-v2/config"

	"github.com/oam-dev/cluster-gateway/pkg/credentialprovider/plugin"
	"github.com/oam-dev/cluster-gateway/plugins/aws/eks"
)

func main() {
	socket := flag.String("socket", "/var/run/cluster-gateway/plugins/aws.sock", "unix socket to serve on")
	allowBaseIdentity := flag.Bool("allow-base-identity", false, "sign for clusters without a roleArn using the plugin's own AWS identity (IRSA or EKS Pod Identity)")
	allowedRoles := flag.String("allowed-role-arns", "", "comma-separated role ARNs clusters may assume; {cluster} in a role name matches only the requesting cluster's name, e.g. arn:aws:iam::123456789012:role/vela-{cluster}")
	sessionName := flag.String("session-name", "cluster-gateway", "prefix of the RoleSessionName, which is <prefix>-<cluster>")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	base, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		log.Fatalf("loading AWS configuration: %v", err)
	}
	var roles []string
	for _, r := range strings.Split(*allowedRoles, ",") {
		if r = strings.TrimSpace(r); r != "" {
			roles = append(roles, r)
		}
	}
	m, err := eks.NewMinter(eks.Options{Base: base, AllowBaseIdentity: *allowBaseIdentity, AllowedRoleARNs: roles, SessionName: *sessionName})
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("serving on %s (base identity allowed: %v, %d allowlist entries)", *socket, *allowBaseIdentity, len(roles))
	if err := plugin.Serve(ctx, *socket, m); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
