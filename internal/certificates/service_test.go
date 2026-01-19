/*
Copyright 2026 The Butler Authors.

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

package certificates

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

func TestService_CategorizeSecret(t *testing.T) {
	s := &Service{}

	tests := []struct {
		name       string
		secretName string
		component  string
		want       CertificateCategory
	}{
		// Test with component labels
		{"api-server-certificate by label", "my-cluster-api-server-certificate", "api-server-certificate", CertCategoryAPIServer},
		{"admin-kubeconfig by label", "my-cluster-admin-kubeconfig", "admin-kubeconfig", CertCategoryKubeconfig},
		{"ca by label", "my-cluster-ca", "ca", CertCategoryCA},
		{"front-proxy-ca by label", "my-cluster-front-proxy-ca-certificate", "front-proxy-ca-certificate", CertCategoryCA},
		{"front-proxy-client by label", "my-cluster-front-proxy-client-certificate", "front-proxy-client-certificate", CertCategoryFrontProxy},
		{"sa-certificate by label", "my-cluster-sa-certificate", "sa-certificate", CertCategoryServiceAccount},
		{"datastore-certificate by label", "my-cluster-datastore-certificate", "datastore-certificate", CertCategoryDatastore},
		{"konnectivity-certificate by label", "my-cluster-konnectivity-certificate", "konnectivity-certificate", CertCategoryKonnectivity},
		{"scheduler-kubeconfig by label", "my-cluster-scheduler-kubeconfig", "scheduler-kubeconfig", CertCategoryKubeconfig},

		// Test name-based fallback (no component label)
		{"api-server by name", "my-cluster-api-server-certificate", "", CertCategoryAPIServer},
		{"kubeconfig by name", "my-cluster-admin-kubeconfig", "", CertCategoryKubeconfig},
		{"ca by name", "my-cluster-ca", "", CertCategoryCA},
		{"datastore by name", "my-cluster-datastore-certs", "", CertCategoryDatastore},
		{"etcd by name", "my-cluster-etcd-client", "", CertCategoryDatastore},
		{"konnectivity by name", "my-cluster-konnectivity-server", "", CertCategoryKonnectivity},
		{"unknown defaults to apiserver", "my-cluster-unknown", "", CertCategoryAPIServer},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secret := corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: tt.secretName,
				},
			}
			if tt.component != "" {
				secret.Labels = map[string]string{
					KamajiComponentLabel: tt.component,
				}
			}

			got := s.categorizeSecret(secret)
			if got != tt.want {
				t.Errorf("categorizeSecret(%q, component=%q) = %q, want %q",
					tt.secretName, tt.component, got, tt.want)
			}
		})
	}
}

func TestService_SecretBelongsToCluster(t *testing.T) {
	s := &Service{}

	tests := []struct {
		name        string
		secret      corev1.Secret
		clusterName string
		want        bool
	}{
		{
			name: "matches by label",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-cluster-api-server",
					Labels: map[string]string{
						KamajiTenantLabel: "my-cluster",
					},
				},
			},
			clusterName: "my-cluster",
			want:        true,
		},
		{
			name: "matches by prefix",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "my-cluster-api-server",
				},
			},
			clusterName: "my-cluster",
			want:        true,
		},
		{
			name: "does not match - different cluster in label",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "other-cluster-api-server",
					Labels: map[string]string{
						KamajiTenantLabel: "other-cluster",
					},
				},
			},
			clusterName: "my-cluster",
			want:        false,
		},
		{
			name: "does not match - different prefix",
			secret: corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name: "other-cluster-api-server",
				},
			},
			clusterName: "my-cluster",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := s.secretBelongsToCluster(tt.secret, tt.clusterName)
			if got != tt.want {
				t.Errorf("secretBelongsToCluster() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestService_GetSecretsForRotation(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create fake secrets with proper Kamaji labels
	secrets := []runtime.Object{
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-api-server-certificate",
				Namespace: "test-ns",
				Labels: map[string]string{
					KamajiProjectLabel:   "kamaji",
					KamajiComponentLabel: "api-server-certificate",
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-admin-kubeconfig",
				Namespace: "test-ns",
				Labels: map[string]string{
					KamajiProjectLabel:   "kamaji",
					KamajiComponentLabel: "admin-kubeconfig",
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-ca",
				Namespace: "test-ns",
				Labels: map[string]string{
					KamajiProjectLabel:   "kamaji",
					KamajiComponentLabel: "ca",
				},
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "other-cluster-api-server",
				Namespace: "test-ns",
				Labels: map[string]string{
					KamajiProjectLabel:   "kamaji",
					KamajiComponentLabel: "api-server-certificate",
				},
			},
		},
	}

	client := fake.NewSimpleClientset(secrets...)
	service := NewService(client, nil, logger)

	tests := []struct {
		name         string
		rotationType RotationType
		wantCount    int
		wantContains []string
		wantExcludes []string
	}{
		{
			name:         "all - excludes CA",
			rotationType: RotateAllCerts,
			wantCount:    2,
			wantContains: []string{"test-cluster-api-server-certificate", "test-cluster-admin-kubeconfig"},
			wantExcludes: []string{"test-cluster-ca"},
		},
		{
			name:         "kubeconfigs only",
			rotationType: RotateKubeconfigs,
			wantCount:    1,
			wantContains: []string{"test-cluster-admin-kubeconfig"},
			wantExcludes: []string{"test-cluster-api-server-certificate", "test-cluster-ca"},
		},
		{
			name:         "CA only",
			rotationType: RotateCA,
			wantCount:    1,
			wantContains: []string{"test-cluster-ca"},
			wantExcludes: []string{"test-cluster-api-server-certificate", "test-cluster-admin-kubeconfig"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			secrets, err := service.getSecretsForRotation(ctx, "test-ns", "test-cluster", tt.rotationType)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(secrets) != tt.wantCount {
				t.Errorf("got %d secrets, want %d", len(secrets), tt.wantCount)
			}

			for _, want := range tt.wantContains {
				found := false
				for _, s := range secrets {
					if s == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected secrets to contain %q", want)
				}
			}

			for _, notWant := range tt.wantExcludes {
				for _, s := range secrets {
					if s == notWant {
						t.Errorf("expected secrets to NOT contain %q", notWant)
					}
				}
			}
		})
	}
}

func TestService_RotateCertificates(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create a fake TenantCluster
	tc := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "TenantCluster",
			"metadata": map[string]interface{}{
				"name":      "test-cluster",
				"namespace": "test-ns",
			},
			"status": map[string]interface{}{
				"tenantNamespace": "test-ns",
			},
		},
	}

	// Create fake secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-cluster-api-server-certificate",
			Namespace: "test-ns",
			Labels: map[string]string{
				KamajiProjectLabel:   "kamaji",
				KamajiComponentLabel: "api-server-certificate",
			},
		},
		Data: map[string][]byte{
			"tls.crt": generateTestCertPEM(365),
		},
	}

	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme)

	client := fake.NewSimpleClientset(secret)
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme, tc)

	service := NewService(client, dynamicClient, logger)

	// Test rotation
	event, err := service.RotateCertificates(ctx, "test-ns", "test-cluster", RotateAllCerts, "test-user")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if event.Status != RotationStatusInProgress {
		t.Errorf("expected status %q, got %q", RotationStatusInProgress, event.Status)
	}

	if event.InitiatedBy != "test-user" {
		t.Errorf("expected initiatedBy %q, got %q", "test-user", event.InitiatedBy)
	}

	if len(event.AffectedSecrets) != 1 {
		t.Errorf("expected 1 affected secret, got %d", len(event.AffectedSecrets))
	}

	// Verify annotation was applied
	updated, err := client.CoreV1().Secrets("test-ns").Get(ctx, secret.Name, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get updated secret: %v", err)
	}

	if _, ok := updated.Annotations[KamajiRotateAnnotation]; !ok {
		t.Error("expected rotation annotation to be set")
	}
}

func TestService_GetClusterCertificates(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelError}))

	// Create fake TenantCluster
	tc := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "TenantCluster",
			"metadata": map[string]interface{}{
				"name":      "test-cluster",
				"namespace": "test-ns",
			},
			"status": map[string]interface{}{
				"tenantNamespace": "test-ns",
			},
		},
	}

	// Create fake secrets with certificates
	secrets := []runtime.Object{
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-api-server-certificate",
				Namespace: "test-ns",
				Labels: map[string]string{
					KamajiProjectLabel:   "kamaji",
					KamajiComponentLabel: "api-server-certificate",
				},
			},
			Data: map[string][]byte{
				"tls.crt": generateTestCertPEM(365),
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-admin-kubeconfig",
				Namespace: "test-ns",
				Labels: map[string]string{
					KamajiProjectLabel:   "kamaji",
					KamajiComponentLabel: "admin-kubeconfig",
				},
			},
			Data: map[string][]byte{
				"tls.crt": generateTestCertPEM(20), // Warning threshold
			},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-cluster-ca",
				Namespace: "test-ns",
				Labels: map[string]string{
					KamajiProjectLabel:   "kamaji",
					KamajiComponentLabel: "ca",
				},
			},
			Data: map[string][]byte{
				"ca.crt": generateTestCACertPEM(730),
			},
		},
	}

	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme)

	client := fake.NewSimpleClientset(secrets...)
	dynamicClient := dynamicfake.NewSimpleDynamicClient(scheme, tc)

	service := NewService(client, dynamicClient, logger)

	certs, err := service.GetClusterCertificates(ctx, "test-ns", "test-cluster")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify basic structure
	if certs.ClusterName != "test-cluster" {
		t.Errorf("expected clusterName %q, got %q", "test-cluster", certs.ClusterName)
	}

	if certs.CertificateCount != 3 {
		t.Errorf("expected 3 certificates, got %d", certs.CertificateCount)
	}

	// Overall health should be Warning (due to 20-day cert)
	if certs.OverallHealth != CertHealthWarning {
		t.Errorf("expected overall health %q, got %q", CertHealthWarning, certs.OverallHealth)
	}

	// Verify categories
	if len(certs.Categories[CertCategoryAPIServer]) != 1 {
		t.Errorf("expected 1 API server cert, got %d", len(certs.Categories[CertCategoryAPIServer]))
	}

	if len(certs.Categories[CertCategoryKubeconfig]) != 1 {
		t.Errorf("expected 1 kubeconfig cert, got %d", len(certs.Categories[CertCategoryKubeconfig]))
	}

	if len(certs.Categories[CertCategoryCA]) != 1 {
		t.Errorf("expected 1 CA cert, got %d", len(certs.Categories[CertCategoryCA]))
	}

	// Verify earliest expiry is set
	if certs.EarliestExpiry == nil {
		t.Error("expected earliest expiry to be set")
	}
}

// Helper functions

func generateTestCertPEM(daysValid int) []byte {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Duration(daysValid) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

func generateTestCACertPEM(daysValid int) []byte {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(daysValid) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}
