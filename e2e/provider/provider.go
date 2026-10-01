package provider

import (
	"context"
	"encoding/json"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apimachinery/pkg/types"

	"github.com/oam-dev/cluster-gateway/e2e/framework"
	clusterv1alpha1 "github.com/oam-dev/cluster-gateway/pkg/apis/cluster/v1alpha1"
)

const (
	providerTestBasename = "provider"
	// providerCluster is registered with the Provider credential type, backed by
	// the tokenrequest test plugin.
	providerCluster = "loopback-provider"
	spokeIdentity   = "system:serviceaccount:vela-system:e2e-provider-spoke"
)

var _ = Describe("Provider credential", func() {
	f := framework.NewE2EFramework(providerTestBasename)

	It("is served without the credential", func() {
		gw := &clusterv1alpha1.ClusterGateway{}
		Expect(f.HubRuntimeClient().Get(context.TODO(), types.NamespacedName{Name: providerCluster}, gw)).To(Succeed())
		Expect(gw.Spec.Access.Credential).To(Equal(&clusterv1alpha1.ClusterAccessCredential{
			Type:     clusterv1alpha1.CredentialTypeProvider,
			Provider: "tokenrequest",
		}))
	})

	It("authenticates proxied requests with the minted token", func() {
		review, err := json.Marshal(&authenticationv1.SelfSubjectReview{})
		Expect(err).NotTo(HaveOccurred())
		resp, err := f.HubNativeClient().Discovery().RESTClient().
			Post().
			AbsPath(
				"apis/cluster.core.oam.dev/v1alpha1/clustergateways",
				providerCluster,
				"proxy",
				"apis/authentication.k8s.io/v1/selfsubjectreviews",
			).
			SetHeader("Content-Type", "application/json").
			Body(review).
			DoRaw(context.TODO())
		Expect(err).NotTo(HaveOccurred())
		result := &authenticationv1.SelfSubjectReview{}
		Expect(json.Unmarshal(resp, result)).To(Succeed())
		Expect(result.Status.UserInfo.Username).To(Equal(spokeIdentity))
	})
})
