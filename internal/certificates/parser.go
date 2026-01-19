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
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ParseCertificateFromPEM extracts certificate metadata from PEM-encoded data.
// It returns the first certificate found in the PEM data.
func ParseCertificateFromPEM(pemData []byte) (*CertificateInfo, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Handle different PEM types
	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("PEM block is not a certificate: %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse X.509 certificate: %w", err)
	}

	return buildCertificateInfo(cert), nil
}

// ParseAllCertificatesFromPEM extracts all certificates from PEM data.
// This is useful for certificate chains.
func ParseAllCertificatesFromPEM(pemData []byte) ([]*CertificateInfo, error) {
	var certs []*CertificateInfo
	remaining := pemData

	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			break
		}
		remaining = rest

		if block.Type != "CERTIFICATE" {
			continue
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue // Skip unparseable certificates
		}

		certs = append(certs, buildCertificateInfo(cert))
	}

	if len(certs) == 0 {
		return nil, fmt.Errorf("no valid certificates found in PEM data")
	}

	return certs, nil
}

// kubeconfigData represents the structure of a kubeconfig file
type kubeconfigData struct {
	Users []struct {
		User struct {
			ClientCertificateData string `yaml:"client-certificate-data"`
		} `yaml:"user"`
	} `yaml:"users"`
}

// ParseCertificateFromKubeconfig extracts the client certificate from kubeconfig YAML.
func ParseCertificateFromKubeconfig(kubeconfigYAML []byte) (*CertificateInfo, error) {
	var kc kubeconfigData
	if err := yaml.Unmarshal(kubeconfigYAML, &kc); err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig YAML: %w", err)
	}

	if len(kc.Users) == 0 {
		return nil, fmt.Errorf("no users found in kubeconfig")
	}

	certDataB64 := kc.Users[0].User.ClientCertificateData
	if certDataB64 == "" {
		return nil, fmt.Errorf("no client-certificate-data found in kubeconfig")
	}

	// Decode base64
	certPEM, err := base64.StdEncoding.DecodeString(certDataB64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode client-certificate-data: %w", err)
	}

	return ParseCertificateFromPEM(certPEM)
}

// ParseCertificateFromSecretData attempts to parse certificate data from a secret key.
// It handles both raw PEM certificates and kubeconfig YAML files.
func ParseCertificateFromSecretData(key string, data []byte) (*CertificateInfo, error) {
	// Check if this is a kubeconfig file
	if IsKubeconfigKey(key) {
		return ParseCertificateFromKubeconfig(data)
	}

	// Otherwise treat as raw PEM
	return ParseCertificateFromPEM(data)
}

// buildCertificateInfo creates a CertificateInfo from a parsed X.509 certificate.
func buildCertificateInfo(cert *x509.Certificate) *CertificateInfo {
	now := time.Now()

	// Calculate days until expiry (can be negative if expired)
	daysUntilExpiry := int(cert.NotAfter.Sub(now).Hours() / 24)

	// Calculate age in days
	ageInDays := int(now.Sub(cert.NotBefore).Hours() / 24)
	if ageInDays < 0 {
		ageInDays = 0 // Certificate not yet valid
	}

	info := &CertificateInfo{
		Subject:         cert.Subject.String(),
		Issuer:          cert.Issuer.String(),
		NotBefore:       cert.NotBefore,
		NotAfter:        cert.NotAfter,
		SerialNumber:    cert.SerialNumber.String(),
		IsCA:            cert.IsCA,
		DaysUntilExpiry: daysUntilExpiry,
		AgeInDays:       ageInDays,
		HealthStatus:    computeHealthStatus(daysUntilExpiry),
	}

	// Extract DNS SANs
	if len(cert.DNSNames) > 0 {
		info.DNSNames = make([]string, len(cert.DNSNames))
		copy(info.DNSNames, cert.DNSNames)
	}

	// Extract IP SANs
	if len(cert.IPAddresses) > 0 {
		info.IPAddresses = make([]string, 0, len(cert.IPAddresses))
		for _, ip := range cert.IPAddresses {
			info.IPAddresses = append(info.IPAddresses, ip.String())
		}
	}

	return info
}

// computeHealthStatus determines health based on days until expiry.
func computeHealthStatus(daysUntilExpiry int) CertHealthStatus {
	switch {
	case daysUntilExpiry < 0:
		return CertHealthExpired
	case daysUntilExpiry < HealthThresholdCritical:
		return CertHealthCritical
	case daysUntilExpiry < HealthThresholdWarning:
		return CertHealthWarning
	default:
		return CertHealthHealthy
	}
}

// WorstHealth returns the worst health status between two statuses.
func WorstHealth(a, b CertHealthStatus) CertHealthStatus {
	order := map[CertHealthStatus]int{
		CertHealthHealthy:  0,
		CertHealthWarning:  1,
		CertHealthCritical: 2,
		CertHealthExpired:  3,
	}

	if order[b] > order[a] {
		return b
	}
	return a
}

// IsCertificateKey checks if a secret data key is likely to contain a certificate.
func IsCertificateKey(key string) bool {
	// Direct matches for known certificate keys
	certKeys := []string{
		"tls.crt",
		"ca.crt",
		"client.crt",
		"server.crt",
	}

	for _, k := range certKeys {
		if key == k {
			return true
		}
	}

	// Check for kubeconfig files
	if IsKubeconfigKey(key) {
		return true
	}

	// Check for .crt or .pem extensions
	if strings.HasSuffix(key, ".crt") || strings.HasSuffix(key, ".pem") {
		return true
	}

	return false
}

// IsKubeconfigKey checks if a key represents a kubeconfig file.
func IsKubeconfigKey(key string) bool {
	kubeconfigKeys := []string{
		"admin.conf",
		"controller-manager.conf",
		"scheduler.conf",
		"super-admin.conf",
		"kubeconfig",
	}

	for _, k := range kubeconfigKeys {
		if key == k {
			return true
		}
	}

	// Also check for .conf suffix as kubeconfigs often use this
	if strings.HasSuffix(key, ".conf") {
		return true
	}

	return false
}
