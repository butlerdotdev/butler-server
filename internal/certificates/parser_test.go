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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"
)

// generateTestCert creates a self-signed certificate for testing.
func generateTestCert(daysValid int, opts ...certOption) []byte {
	config := &certConfig{
		commonName: "test",
		dnsNames:   nil,
		ips:        nil,
		isCA:       false,
		notBefore:  time.Now(),
	}

	for _, opt := range opts {
		opt(config)
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	subject := pkix.Name{CommonName: config.commonName}
	if config.organization != "" {
		subject.Organization = []string{config.organization}
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      subject,
		NotBefore:    config.notBefore,
		NotAfter:     config.notBefore.Add(time.Duration(daysValid) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		IsCA:         config.isCA,
		DNSNames:     config.dnsNames,
		IPAddresses:  config.ips,
	}

	if config.isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
		template.BasicConstraintsValid = true
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)

	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
}

type certConfig struct {
	commonName   string
	organization string
	dnsNames     []string
	ips          []net.IP
	isCA         bool
	notBefore    time.Time
}

type certOption func(*certConfig)

func withCommonName(cn string) certOption {
	return func(c *certConfig) { c.commonName = cn }
}

func withOrganization(org string) certOption {
	return func(c *certConfig) { c.organization = org }
}

func withDNSNames(names ...string) certOption {
	return func(c *certConfig) { c.dnsNames = names }
}

func withIPs(ips ...net.IP) certOption {
	return func(c *certConfig) { c.ips = ips }
}

func withCA(isCA bool) certOption {
	return func(c *certConfig) { c.isCA = isCA }
}

func withNotBefore(t time.Time) certOption {
	return func(c *certConfig) { c.notBefore = t }
}

func TestParseCertificateFromPEM(t *testing.T) {
	tests := []struct {
		name         string
		pemData      []byte
		wantSubject  string
		wantErr      bool
		wantHealthy  CertHealthStatus
		wantIsCA     bool
		wantDNSCount int
		wantIPCount  int
	}{
		{
			name:        "healthy certificate",
			pemData:     generateTestCert(365),
			wantSubject: "CN=test",
			wantHealthy: CertHealthHealthy,
		},
		{
			name:        "warning certificate (25 days)",
			pemData:     generateTestCert(25),
			wantHealthy: CertHealthWarning,
		},
		{
			name:        "critical certificate (5 days)",
			pemData:     generateTestCert(5),
			wantHealthy: CertHealthCritical,
		},
		{
			name:        "expired certificate",
			pemData:     generateTestCert(-5, withNotBefore(time.Now().Add(-10*24*time.Hour))),
			wantHealthy: CertHealthExpired,
		},
		{
			name:        "CA certificate",
			pemData:     generateTestCert(365, withCA(true)),
			wantIsCA:    true,
			wantHealthy: CertHealthHealthy,
		},
		{
			name:         "certificate with DNS SANs",
			pemData:      generateTestCert(365, withDNSNames("kubernetes", "kubernetes.default", "api.local")),
			wantDNSCount: 3,
			wantHealthy:  CertHealthHealthy,
		},
		{
			name:        "certificate with IP SANs",
			pemData:     generateTestCert(365, withIPs(net.ParseIP("10.96.0.1"), net.ParseIP("192.168.1.100"))),
			wantIPCount: 2,
			wantHealthy: CertHealthHealthy,
		},
		{
			name:        "custom subject with org",
			pemData:     generateTestCert(365, withCommonName("kube-apiserver"), withOrganization("system:masters")),
			wantSubject: "CN=kube-apiserver,O=system:masters",
			wantHealthy: CertHealthHealthy,
		},
		{
			name:    "invalid PEM data",
			pemData: []byte("not a certificate"),
			wantErr: true,
		},
		{
			name:    "empty data",
			pemData: []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := ParseCertificateFromPEM(tt.pemData)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tt.wantSubject != "" && info.Subject != tt.wantSubject {
				t.Errorf("subject = %q, want %q", info.Subject, tt.wantSubject)
			}

			if info.HealthStatus != tt.wantHealthy {
				t.Errorf("healthStatus = %q, want %q", info.HealthStatus, tt.wantHealthy)
			}

			if info.IsCA != tt.wantIsCA {
				t.Errorf("isCA = %v, want %v", info.IsCA, tt.wantIsCA)
			}

			if tt.wantDNSCount > 0 && len(info.DNSNames) != tt.wantDNSCount {
				t.Errorf("DNS names count = %d, want %d", len(info.DNSNames), tt.wantDNSCount)
			}

			if tt.wantIPCount > 0 && len(info.IPAddresses) != tt.wantIPCount {
				t.Errorf("IP addresses count = %d, want %d", len(info.IPAddresses), tt.wantIPCount)
			}
		})
	}
}

func TestParseAllCertificatesFromPEM(t *testing.T) {
	// Create a certificate chain
	cert1 := generateTestCert(365, withCommonName("leaf"))
	cert2 := generateTestCert(730, withCommonName("intermediate"), withCA(true))

	chain := append(cert1, cert2...)

	certs, err := ParseAllCertificatesFromPEM(chain)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(certs) != 2 {
		t.Errorf("got %d certificates, want 2", len(certs))
	}

	if certs[0].Subject != "CN=leaf" {
		t.Errorf("first cert subject = %q, want CN=leaf", certs[0].Subject)
	}

	if certs[1].Subject != "CN=intermediate" {
		t.Errorf("second cert subject = %q, want CN=intermediate", certs[1].Subject)
	}

	if !certs[1].IsCA {
		t.Error("second cert should be CA")
	}
}

func TestComputeHealthStatus(t *testing.T) {
	tests := []struct {
		daysUntilExpiry int
		want            CertHealthStatus
	}{
		{-1, CertHealthExpired},
		{-30, CertHealthExpired},
		{0, CertHealthCritical},
		{1, CertHealthCritical},
		{6, CertHealthCritical},
		{7, CertHealthWarning},
		{15, CertHealthWarning},
		{29, CertHealthWarning},
		{30, CertHealthHealthy},
		{365, CertHealthHealthy},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := computeHealthStatus(tt.daysUntilExpiry)
			if got != tt.want {
				t.Errorf("computeHealthStatus(%d) = %q, want %q", tt.daysUntilExpiry, got, tt.want)
			}
		})
	}
}

func TestWorstHealth(t *testing.T) {
	tests := []struct {
		a, b CertHealthStatus
		want CertHealthStatus
	}{
		{CertHealthHealthy, CertHealthHealthy, CertHealthHealthy},
		{CertHealthHealthy, CertHealthWarning, CertHealthWarning},
		{CertHealthWarning, CertHealthHealthy, CertHealthWarning},
		{CertHealthWarning, CertHealthCritical, CertHealthCritical},
		{CertHealthCritical, CertHealthWarning, CertHealthCritical},
		{CertHealthCritical, CertHealthExpired, CertHealthExpired},
		{CertHealthExpired, CertHealthHealthy, CertHealthExpired},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			got := WorstHealth(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("WorstHealth(%q, %q) = %q, want %q", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

func TestIsCertificateKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"tls.crt", true},
		{"ca.crt", true},
		{"client.crt", true},
		{"server.crt", true},
		{"apiserver.crt", true},
		{"cert.pem", true},
		{"ca.pem", true},
		{"tls.key", false},
		{"ca.key", false},
		{"config", false},
		{"kubeconfig", true},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := IsCertificateKey(tt.key)
			if got != tt.want {
				t.Errorf("IsCertificateKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestCertificateInfo_DaysCalculation(t *testing.T) {
	// Certificate issued yesterday, valid for 30 days
	yesterday := time.Now().Add(-24 * time.Hour)
	pemData := generateTestCert(30, withNotBefore(yesterday))

	info, err := ParseCertificateFromPEM(pemData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Age should be ~1 day
	if info.AgeInDays < 1 || info.AgeInDays > 2 {
		t.Errorf("AgeInDays = %d, want ~1", info.AgeInDays)
	}

	// Days until expiry should be ~29 days
	if info.DaysUntilExpiry < 28 || info.DaysUntilExpiry > 30 {
		t.Errorf("DaysUntilExpiry = %d, want ~29", info.DaysUntilExpiry)
	}
}
