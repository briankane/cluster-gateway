package v1alpha1

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oam-dev/cluster-gateway/pkg/common"
	"github.com/oam-dev/cluster-gateway/pkg/config"
	cpapi "github.com/oam-dev/cluster-gateway/pkg/credentialprovider/api"
	"github.com/oam-dev/cluster-gateway/pkg/featuregates"
	"github.com/oam-dev/cluster-gateway/pkg/options"
	"github.com/oam-dev/cluster-gateway/pkg/util/cert"
	"github.com/oam-dev/cluster-gateway/pkg/util/singleton"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/apis/meta/internalversion"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apiserver/pkg/util/feature"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/component-base/featuregate"
	k8stesting "k8s.io/component-base/featuregate/testing"
	"k8s.io/utils/pointer"
	ocmclientfake "open-cluster-management.io/api/client/cluster/clientset/versioned/fake"
	clusterv1 "open-cluster-management.io/api/cluster/v1"
)

var (
	testNamespace          = "foo"
	testName               = "bar"
	testCAData             = "caData"
	testCertData           = "certData"
	testKeyData            = "keyData"
	testToken              = "token"
	testEndpoint           = "https://localhost:443"
	testExecConfigForToken = `{
  "apiVersion": "client.authentication.k8s.io/v1beta1",
  "kind": "ExecConfig",
  "command": "echo",
  "args": [
    "{\"apiVersion\": \"client.authentication.k8s.io/v1beta1\", \"kind\": \"ExecCredential\", \"status\": {\"token\": \"token\"}}"
  ]
}`
	testExecConfigForX509 = `{
  "apiVersion": "client.authentication.k8s.io/v1beta1",
  "kind": "ExecConfig",
  "command": "echo",
  "args": [
    "{\"apiVersion\": \"client.authentication.k8s.io/v1beta1\", \"kind\": \"ExecCredential\", \"status\": {\"clientCertificateData\": \"certData\", \"clientKeyData\": \"keyData\"}}"
  ]
}`
)

func TestConvertSecretToGateway(t *testing.T) {
	cases := []struct {
		name            string
		featureGate     featuregate.Feature
		inputSecret     *corev1.Secret
		expectedFailure bool
		expected        *ClusterGateway
	}{
		{
			name: "missing credential type label should fail",
			inputSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      testName,
				},
				Data: map[string][]byte{},
			},
			expectedFailure: true,
		},
		{
			name: "service-account token conversion",
			inputSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      testName,
					Labels: map[string]string{
						common.LabelKeyClusterCredentialType: string(CredentialTypeServiceAccountToken),
					},
				},
				Data: map[string][]byte{
					"ca.crt":   []byte(testCAData),
					"token":    []byte(testToken),
					"endpoint": []byte(testEndpoint),
				},
			},
			expected: &ClusterGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: testName,
				},
				Spec: ClusterGatewaySpec{
					Access: ClusterAccess{
						Credential: &ClusterAccessCredential{
							Type:                CredentialTypeServiceAccountToken,
							ServiceAccountToken: testToken,
						},
						Endpoint: &ClusterEndpoint{
							Type: ClusterEndpointTypeConst,
							Const: &ClusterEndpointConst{
								CABundle: []byte(testCAData),
								Address:  testEndpoint,
							},
						},
					},
				},
			},
		},
		{
			name: "x509 certificate conversion",
			inputSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      testName,
					Labels: map[string]string{
						common.LabelKeyClusterCredentialType: string(CredentialTypeX509Certificate),
					},
				},
				Data: map[string][]byte{
					"ca.crt":   []byte(testCAData),
					"tls.crt":  []byte(testCertData),
					"tls.key":  []byte(testKeyData),
					"endpoint": []byte(testEndpoint),
				},
			},
			expected: &ClusterGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: testName,
				},
				Spec: ClusterGatewaySpec{
					Access: ClusterAccess{
						Credential: &ClusterAccessCredential{
							Type: CredentialTypeX509Certificate,
							X509: &X509{
								Certificate: []byte(testCertData),
								PrivateKey:  []byte(testKeyData),
							},
						},
						Endpoint: &ClusterEndpoint{
							Type: ClusterEndpointTypeConst,
							Const: &ClusterEndpointConst{
								CABundle: []byte(testCAData),
								Address:  testEndpoint,
							},
						},
					},
				},
			},
		},
		{
			name: "cluster proxy egress conversion",
			inputSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      testName,
					Labels: map[string]string{
						common.LabelKeyClusterCredentialType: string(CredentialTypeX509Certificate),
						common.LabelKeyClusterEndpointType:   string(ClusterEndpointTypeClusterProxy),
					},
				},
				Data: map[string][]byte{
					"ca.crt":  []byte(testCAData),
					"tls.crt": []byte(testCertData),
					"tls.key": []byte(testKeyData),
				},
			},
			expected: &ClusterGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: testName,
				},
				Spec: ClusterGatewaySpec{
					Access: ClusterAccess{
						Credential: &ClusterAccessCredential{
							Type: CredentialTypeX509Certificate,
							X509: &X509{
								Certificate: []byte(testCertData),
								PrivateKey:  []byte(testKeyData),
							},
						},
						Endpoint: &ClusterEndpoint{
							Type: ClusterEndpointTypeClusterProxy,
						},
					},
				},
			},
		},
		{
			name: "insecure conversion",
			inputSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      testName,
					Labels: map[string]string{
						common.LabelKeyClusterCredentialType: string(CredentialTypeX509Certificate),
					},
				},
				Data: map[string][]byte{
					"tls.crt":  []byte(testCertData),
					"tls.key":  []byte(testKeyData),
					"endpoint": []byte(testEndpoint),
				},
			},
			expected: &ClusterGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: testName,
				},
				Spec: ClusterGatewaySpec{
					Access: ClusterAccess{
						Credential: &ClusterAccessCredential{
							Type: CredentialTypeX509Certificate,
							X509: &X509{
								Certificate: []byte(testCertData),
								PrivateKey:  []byte(testKeyData),
							},
						},
						Endpoint: &ClusterEndpoint{
							Type: ClusterEndpointTypeConst,
							Const: &ClusterEndpointConst{
								Address:  testEndpoint,
								Insecure: pointer.Bool(true),
							},
						},
					},
				},
			},
		},
		{
			name:        "healthiness conversion (x509)",
			featureGate: featuregates.HealthinessCheck,
			inputSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      testName,
					Annotations: map[string]string{
						AnnotationKeyClusterGatewayStatusHealthy:       "True",
						AnnotationKeyClusterGatewayStatusHealthyReason: "MyReason",
					},
					Labels: map[string]string{
						common.LabelKeyClusterCredentialType: string(CredentialTypeX509Certificate),
					},
				},
				Data: map[string][]byte{
					"ca.crt":   []byte(testCAData),
					"tls.crt":  []byte(testCertData),
					"tls.key":  []byte(testKeyData),
					"endpoint": []byte(testEndpoint),
				},
			},
			expected: &ClusterGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: testName,
				},
				Spec: ClusterGatewaySpec{
					Access: ClusterAccess{
						Credential: &ClusterAccessCredential{
							Type: CredentialTypeX509Certificate,
							X509: &X509{
								Certificate: []byte(testCertData),
								PrivateKey:  []byte(testKeyData),
							},
						},
						Endpoint: &ClusterEndpoint{
							Type: ClusterEndpointTypeConst,
							Const: &ClusterEndpointConst{
								CABundle: []byte(testCAData),
								Address:  testEndpoint,
							},
						},
					},
				},
				Status: ClusterGatewayStatus{
					Healthy:       true,
					HealthyReason: "MyReason",
				},
			},
		},
		{
			name: "dynamic credential is not issued on conversion (token exec config)",
			inputSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testName,
					Namespace: testNamespace,
					Labels: map[string]string{
						common.LabelKeyClusterCredentialType: string(CredentialTypeDynamic),
					},
				},
				Data: map[string][]byte{
					"endpoint": []byte(testEndpoint),
					"ca.crt":   []byte(testCAData),
					"exec":     []byte(testExecConfigForToken),
				},
			},
			expected: &ClusterGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: testName,
				},
				Spec: ClusterGatewaySpec{
					Access: ClusterAccess{
						Credential: &ClusterAccessCredential{
							Type: CredentialTypeDynamic,
						},
						Endpoint: &ClusterEndpoint{
							Type: ClusterEndpointTypeConst,
							Const: &ClusterEndpointConst{
								CABundle: []byte(testCAData),
								Address:  testEndpoint,
							},
						},
					},
				},
			},
		},
		{
			name: "dynamic credential is not issued on conversion (x509 exec config)",
			inputSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testName,
					Namespace: testNamespace,
					Labels: map[string]string{
						common.LabelKeyClusterCredentialType: string(CredentialTypeDynamic),
					},
				},
				Data: map[string][]byte{
					"endpoint": []byte(testEndpoint),
					"ca.crt":   []byte(testCAData),
					"exec":     []byte(testExecConfigForX509),
				},
			},
			expected: &ClusterGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: testName,
				},
				Spec: ClusterGatewaySpec{
					Access: ClusterAccess{
						Credential: &ClusterAccessCredential{
							Type: CredentialTypeDynamic,
						},
						Endpoint: &ClusterEndpoint{
							Type: ClusterEndpointTypeConst,
							Const: &ClusterEndpointConst{
								CABundle: []byte(testCAData),
								Address:  testEndpoint,
							},
						},
					},
				},
			},
		},
		{
			name: "invalid dynamic exec config does not fail conversion",
			inputSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testName,
					Namespace: testNamespace,
					Labels: map[string]string{
						common.LabelKeyClusterCredentialType: string(CredentialTypeDynamic),
					},
				},
				Data: map[string][]byte{
					"endpoint": []byte(testEndpoint),
					"ca.crt":   []byte(testCAData),
					"exec":     []byte("invalid exec config format"),
				},
			},
			expected: &ClusterGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: testName,
				},
				Spec: ClusterGatewaySpec{
					Access: ClusterAccess{
						Credential: &ClusterAccessCredential{
							Type: CredentialTypeDynamic,
						},
						Endpoint: &ClusterEndpoint{
							Type: ClusterEndpointTypeConst,
							Const: &ClusterEndpointConst{
								CABundle: []byte(testCAData),
								Address:  testEndpoint,
							},
						},
					},
				},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if len(c.featureGate) > 0 {
				k8stesting.SetFeatureGateDuringTest(t, feature.DefaultMutableFeatureGate, c.featureGate, true)
			}
			gw, err := convertFromSecret(c.inputSecret)
			if c.expectedFailure {
				assert.True(t, err != nil)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, c.expected, gw)
		})
	}
}

func TestConvertSecretAndClusterToGateway(t *testing.T) {
	cases := []struct {
		name            string
		inputSecret     *corev1.Secret
		inputCluster    *clusterv1.ManagedCluster
		expectedFailure bool
		expected        *ClusterGateway
	}{
		{
			name: "x509 certificate conversion",
			inputSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      testName,
					Labels: map[string]string{
						common.LabelKeyClusterCredentialType: string(CredentialTypeX509Certificate),
					},
				},
				Data: map[string][]byte{
					"tls.crt": []byte(testCertData),
					"tls.key": []byte(testKeyData),
				},
			},
			inputCluster: &clusterv1.ManagedCluster{
				Spec: clusterv1.ManagedClusterSpec{

					ManagedClusterClientConfigs: []clusterv1.ClientConfig{
						{
							URL:      testEndpoint,
							CABundle: []byte(testCAData),
						},
					},
					HubAcceptsClient: true,
				},
			},
			expected: &ClusterGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: testName,
				},
				Spec: ClusterGatewaySpec{
					Access: ClusterAccess{
						Credential: &ClusterAccessCredential{
							Type: CredentialTypeX509Certificate,
							X509: &X509{
								Certificate: []byte(testCertData),
								PrivateKey:  []byte(testKeyData),
							},
						},
						Endpoint: &ClusterEndpoint{
							Type: ClusterEndpointTypeConst,
							Const: &ClusterEndpointConst{
								CABundle: []byte(testCAData),
								Address:  testEndpoint,
							},
						},
					},
				},
			},
		},
		{
			name: "service-account token conversion",
			inputSecret: &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Namespace: testNamespace,
					Name:      testName,
					Labels: map[string]string{
						common.LabelKeyClusterCredentialType: string(CredentialTypeServiceAccountToken),
					},
				},
				Data: map[string][]byte{
					"token":  []byte(testToken),
					"ca.crt": []byte("should be overrided"),
				},
			},
			inputCluster: &clusterv1.ManagedCluster{
				Spec: clusterv1.ManagedClusterSpec{

					ManagedClusterClientConfigs: []clusterv1.ClientConfig{
						{
							URL:      testEndpoint,
							CABundle: []byte(testCAData),
						},
					},
					HubAcceptsClient: true,
				},
			},
			expected: &ClusterGateway{
				ObjectMeta: metav1.ObjectMeta{
					Name: testName,
				},
				Spec: ClusterGatewaySpec{
					Access: ClusterAccess{
						Credential: &ClusterAccessCredential{
							Type:                CredentialTypeServiceAccountToken,
							ServiceAccountToken: testToken,
						},
						Endpoint: &ClusterEndpoint{
							Type: ClusterEndpointTypeConst,
							Const: &ClusterEndpointConst{
								CABundle: []byte(testCAData),
								Address:  testEndpoint,
							},
						},
					},
				},
			},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gw, err := convertFromManagedClusterAndSecret(c.inputCluster, c.inputSecret)
			if c.expectedFailure {
				assert.True(t, err != nil)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, c.expected, gw)
		})
	}
}

func TestGetClusterGateway(t *testing.T) {
	options.OCMIntegration = false
	config.SecretNamespace = testNamespace
	input := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testName,
			Labels: map[string]string{
				common.LabelKeyClusterCredentialType: string(CredentialTypeServiceAccountToken),
			},
		},
		Data: map[string][]byte{
			"ca.crt":   []byte(testCAData),
			"token":    []byte(testToken),
			"endpoint": []byte(testEndpoint),
		},
	}
	fakeKubeClient := fake.NewSimpleClientset(input)
	singleton.SetSecretControl(cert.NewDirectApiSecretControl(testNamespace, fakeKubeClient))
	expected, err := convertFromSecret(input)
	require.NoError(t, err)
	expected.Spec.Access.Credential = &ClusterAccessCredential{Type: CredentialTypeServiceAccountToken}
	storage := &ClusterGateway{}
	gwRaw, err := storage.Get(context.TODO(), testName, &metav1.GetOptions{})
	assert.NoError(t, err)
	assert.Equal(t, expected, gwRaw)
}

func TestListClusterGateway(t *testing.T) {
	options.OCMIntegration = false
	config.SecretNamespace = testNamespace
	input := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testName,
			Labels: map[string]string{
				common.LabelKeyClusterCredentialType: string(CredentialTypeX509Certificate),
			},
		},
		Data: map[string][]byte{
			"ca.crt":   []byte(testCAData),
			"tls.crt":  []byte(testCertData),
			"tls.key":  []byte(testKeyData),
			"endpoint": []byte(testEndpoint),
		},
	}
	fakeKubeClient := fake.NewSimpleClientset(input)
	singleton.SetSecretControl(cert.NewDirectApiSecretControl(testNamespace, fakeKubeClient))

	storage := &ClusterGateway{}
	gws, err := storage.List(context.TODO(), &internalversion.ListOptions{})
	require.Equal(t, 1, len(gws.(*ClusterGatewayList).Items))
	assert.NoError(t, err)
	expected, err := convertFromSecret(input)
	assert.NoError(t, err)
	expected.Spec.Access.Credential = &ClusterAccessCredential{Type: CredentialTypeX509Certificate}
	gw := gws.(*ClusterGatewayList).Items[0]
	assert.Equal(t, expected, &gw)
}

func TestListHybridClusterGateway(t *testing.T) {
	testNoClusterName := "no cluster connected"
	inputWithCluster := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testName,
			Labels: map[string]string{
				common.LabelKeyClusterCredentialType: string(CredentialTypeX509Certificate),
			},
		},
		Data: map[string][]byte{
			"ca.crt":   []byte(testCAData),
			"tls.crt":  []byte(testCertData),
			"tls.key":  []byte(testKeyData),
			"endpoint": []byte(testEndpoint),
		},
	}
	inputNoCluster := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      testNoClusterName,
			Labels: map[string]string{
				common.LabelKeyClusterCredentialType: string(CredentialTypeX509Certificate),
			},
		},
		Data: map[string][]byte{
			"ca.crt":   []byte(testCAData),
			"tls.crt":  []byte(testCertData),
			"tls.key":  []byte(testKeyData),
			"endpoint": []byte(testEndpoint),
		},
	}
	inputDummy := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      "dummy",
			Labels:    map[string]string{},
		},
		Data: map[string][]byte{},
	}
	cluster := &clusterv1.ManagedCluster{
		Spec: clusterv1.ManagedClusterSpec{

			ManagedClusterClientConfigs: []clusterv1.ClientConfig{
				{
					URL:      testEndpoint,
					CABundle: []byte(testCAData),
				},
			},
			HubAcceptsClient: true,
		},
	}
	fakeKubeClient := fake.NewSimpleClientset(inputWithCluster, inputNoCluster, inputDummy)
	fakeOcmClient := ocmclientfake.NewSimpleClientset(cluster)
	singleton.SetSecretControl(cert.NewDirectApiSecretControl(testNamespace, fakeKubeClient))
	singleton.SetOCMClient(fakeOcmClient)

	storage := &ClusterGateway{}
	gws, err := storage.List(context.TODO(), &internalversion.ListOptions{})
	require.NoError(t, err)
	require.Equal(t, 2, len(gws.(*ClusterGatewayList).Items))
	expectedNames := sets.NewString(testName, testNoClusterName)
	actualNames := sets.NewString()
	for _, gw := range gws.(*ClusterGatewayList).Items {
		actualNames.Insert(gw.Name)
	}
	assert.Equal(t, expectedNames, actualNames)
}

func TestBuildCredentialFromExecConfig(t *testing.T) {
	cases := []struct {
		name          string
		secret        func(s *corev1.Secret) *corev1.Secret
		cluster       func(ce *ClusterEndpoint) *ClusterEndpoint
		expectedError string
		expected      *ClusterAccessCredential
	}{
		{
			name:          "missing exec config",
			expectedError: "missing secret data key: exec",
		},

		{
			name: "invalid exec config format",
			secret: func(s *corev1.Secret) *corev1.Secret {
				s.Data["exec"] = []byte("some invalid exec config")
				return s
			},
			expectedError: "failed to decode exec config JSON from secret data: invalid character 's' looking for beginning of value",
		},

		{
			name: "returns successfully a service account token",
			secret: func(s *corev1.Secret) *corev1.Secret {
				s.Data["exec"] = []byte(`{"apiVersion": "client.authentication.k8s.io/v1", "command": "echo", "args": ["{\"apiVersion\": \"client.authentication.k8s.io/v1\", \"status\": {\"token\": \"token\"}}"]}`)
				return s
			},
			expected: &ClusterAccessCredential{
				Type:                CredentialTypeDynamic,
				ServiceAccountToken: testToken,
			},
		},

		{
			name: "returns successfully a X509 client certificate",
			secret: func(s *corev1.Secret) *corev1.Secret {
				s.Data["exec"] = []byte(`{"apiVersion": "client.authentication.k8s.io/v1", "command": "echo", "args": ["{\"apiVersion\": \"client.authentication.k8s.io/v1\", \"status\": {\"clientCertificateData\": \"certData\", \"clientKeyData\": \"keyData\"}}"]}`)
				return s
			},
			expected: &ClusterAccessCredential{
				Type: CredentialTypeDynamic,
				X509: &X509{
					Certificate: []byte(testCertData),
					PrivateKey:  []byte(testKeyData),
				},
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			secret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      testName,
					Namespace: testNamespace,
				},
				Data: map[string][]byte{},
			}
			if tt.secret != nil {
				secret = tt.secret(secret)
			}

			got, err := buildCredentialFromExecConfig(secret)
			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.EqualError(t, err, tt.expectedError)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func newClusterSecret(name string, credType CredentialType, data map[string][]byte) *corev1.Secret {
	data["endpoint"] = []byte(testEndpoint)
	data["ca.crt"] = []byte(testCAData)
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: testNamespace,
			Name:      name,
			Labels: map[string]string{
				common.LabelKeyClusterCredentialType: string(credType),
			},
		},
		Data: data,
	}
}

func TestClusterGatewayAPIRedactsCredential(t *testing.T) {
	options.OCMIntegration = false
	config.SecretNamespace = testNamespace
	secrets := []*corev1.Secret{
		newClusterSecret("sa", CredentialTypeServiceAccountToken, map[string][]byte{"token": []byte(testToken)}),
		newClusterSecret("x509", CredentialTypeX509Certificate, map[string][]byte{"tls.crt": []byte(testCertData), "tls.key": []byte(testKeyData)}),
		newClusterSecret("dynamic", CredentialTypeDynamic, map[string][]byte{"exec": []byte(testExecConfigForToken)}),
		newClusterSecret("dynamic-broken", CredentialTypeDynamic, map[string][]byte{"exec": []byte("invalid exec config format")}),
	}
	expected := map[string]CredentialType{
		"sa":             CredentialTypeServiceAccountToken,
		"x509":           CredentialTypeX509Certificate,
		"dynamic":        CredentialTypeDynamic,
		"dynamic-broken": CredentialTypeDynamic,
	}
	fakeKubeClient := fake.NewSimpleClientset(secrets[0], secrets[1], secrets[2], secrets[3])
	singleton.SetSecretControl(cert.NewDirectApiSecretControl(testNamespace, fakeKubeClient))
	storage := &ClusterGateway{}

	for name, credType := range expected {
		t.Run("get "+name, func(t *testing.T) {
			raw, err := storage.Get(context.TODO(), name, &metav1.GetOptions{})
			require.NoError(t, err)
			assert.Equal(t, &ClusterAccessCredential{Type: credType}, raw.(*ClusterGateway).Spec.Access.Credential)
		})
	}

	t.Run("list", func(t *testing.T) {
		raw, err := storage.List(context.TODO(), &internalversion.ListOptions{})
		require.NoError(t, err)
		items := raw.(*ClusterGatewayList).Items
		require.Len(t, items, len(expected))
		for _, gw := range items {
			assert.Equal(t, &ClusterAccessCredential{Type: expected[gw.Name]}, gw.Spec.Access.Credential, gw.Name)
		}
	})
}

func TestClusterGatewayGetWithCredential(t *testing.T) {
	options.OCMIntegration = false
	config.SecretNamespace = testNamespace
	fakeKubeClient := fake.NewSimpleClientset(
		newClusterSecret("sa", CredentialTypeServiceAccountToken, map[string][]byte{"token": []byte(testToken)}),
		newClusterSecret("dynamic", CredentialTypeDynamic, map[string][]byte{"exec": []byte(testExecConfigForToken)}),
		newClusterSecret("dynamic-broken", CredentialTypeDynamic, map[string][]byte{"exec": []byte("invalid exec config format")}),
	)
	singleton.SetSecretControl(cert.NewDirectApiSecretControl(testNamespace, fakeKubeClient))
	storage := &ClusterGateway{}

	gw, err := storage.getWithCredential(context.TODO(), "sa")
	require.NoError(t, err)
	assert.Equal(t, &ClusterAccessCredential{Type: CredentialTypeServiceAccountToken, ServiceAccountToken: testToken}, gw.Spec.Access.Credential)

	gw, err = storage.getWithCredential(context.TODO(), "dynamic")
	require.NoError(t, err)
	assert.Equal(t, &ClusterAccessCredential{Type: CredentialTypeDynamic, ServiceAccountToken: testToken}, gw.Spec.Access.Credential)

	_, err = storage.getWithCredential(context.TODO(), "dynamic-broken")
	assert.ErrorContains(t, err, "failed to issue credential from external command")
}

func TestConvertProviderSecret(t *testing.T) {
	gw, err := convertFromSecret(newClusterSecret("eks", CredentialTypeProvider, map[string][]byte{
		"provider":        []byte("aws"),
		"provider-config": []byte(`{"region":"eu-west-1"}`),
	}))
	require.NoError(t, err)
	assert.Equal(t, &ClusterAccessCredential{Type: CredentialTypeProvider, Provider: "aws"}, gw.Spec.Access.Credential)

	_, err = convertFromSecret(newClusterSecret("eks", CredentialTypeProvider, map[string][]byte{}))
	assert.ErrorContains(t, err, "missing secret data key: provider")

	_, err = convertFromSecret(newClusterSecret("eks", CredentialTypeProvider, map[string][]byte{
		"provider":        []byte("aws"),
		"provider-config": []byte(`["not", "an", "object"]`),
	}))
	assert.ErrorContains(t, err, "provider-config must be a JSON object")
}

// startProviderPlugin serves a fake credential plugin named name in a fresh
// plugin directory and points the gateway at it.
func startProviderPlugin(t *testing.T, name string, handler http.HandlerFunc) {
	t.Helper()
	dir, err := os.MkdirTemp("", "cgp")
	require.NoError(t, err)
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	l, err := net.Listen("unix", filepath.Join(dir, name+".sock"))
	require.NoError(t, err)
	srv := &http.Server{Handler: handler}
	go func() { _ = srv.Serve(l) }()
	t.Cleanup(func() { _ = srv.Close() })
	prev := config.CredentialPluginDir
	config.CredentialPluginDir = dir
	t.Cleanup(func() { config.CredentialPluginDir = prev })
}

func TestClusterGatewayProviderCredential(t *testing.T) {
	options.OCMIntegration = false
	config.SecretNamespace = testNamespace
	var received cpapi.CredentialRequest
	startProviderPlugin(t, "aws", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&received)
		expiry := time.Now().Add(15 * time.Minute)
		_ = json.NewEncoder(w).Encode(&cpapi.ExecCredential{
			APIVersion: cpapi.ExecCredentialAPIVersion,
			Kind:       cpapi.ExecCredentialKind,
			Status:     &cpapi.ExecCredentialStatus{Token: "k8s-aws-v1.minted", ExpirationTimestamp: &expiry},
		})
	})
	insecure := newClusterSecret("insecure", CredentialTypeProvider, map[string][]byte{"provider": []byte("aws")})
	delete(insecure.Data, "ca.crt")
	fakeKubeClient := fake.NewSimpleClientset(
		newClusterSecret("eks", CredentialTypeProvider, map[string][]byte{
			"provider":        []byte("aws"),
			"provider-config": []byte(`{"region":"eu-west-1"}`),
		}),
		insecure,
	)
	singleton.SetSecretControl(cert.NewDirectApiSecretControl(testNamespace, fakeKubeClient))
	storage := &ClusterGateway{}

	raw, err := storage.Get(context.TODO(), "eks", &metav1.GetOptions{})
	require.NoError(t, err)
	assert.Equal(t, &ClusterAccessCredential{Type: CredentialTypeProvider, Provider: "aws"}, raw.(*ClusterGateway).Spec.Access.Credential)

	gw, err := storage.getWithCredential(context.TODO(), "eks")
	require.NoError(t, err)
	assert.Equal(t, &ClusterAccessCredential{Type: CredentialTypeProvider, Provider: "aws", ServiceAccountToken: "k8s-aws-v1.minted"}, gw.Spec.Access.Credential)
	assert.Equal(t, "eks", received.Cluster)
	assert.JSONEq(t, `{"region":"eu-west-1"}`, string(received.Config))

	cfg, err := NewConfigFromCluster(context.TODO(), gw)
	require.NoError(t, err)
	assert.Equal(t, "k8s-aws-v1.minted", cfg.BearerToken)

	_, err = storage.getWithCredential(context.TODO(), "insecure")
	assert.ErrorContains(t, err, "requires a CA bundle")
}
