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
	"time"
)

// Steward-specific labels and annotations
const (
	// StewardProjectLabel identifies secrets belonging to Steward
	StewardProjectLabel = "steward.butlerlabs.dev/project"

	// StewardTenantLabel identifies which tenant a secret belongs to
	StewardTenantLabel = "steward.butlerlabs.dev/name"

	// StewardComponentLabel identifies the certificate component type
	StewardComponentLabel = "steward.butlerlabs.dev/component"

	// RotationTimeoutMinutes is how long to wait for rotation to complete
	RotationTimeoutMinutes = 5
)

// Health status thresholds (used by parser.go)
const (
	// HealthThresholdCritical - certificates expiring within this many days are critical
	HealthThresholdCritical = 7
	// HealthThresholdWarning - certificates expiring within this many days are warnings
	HealthThresholdWarning = 30
)

// CertHealthStatus represents the health status of a certificate
type CertHealthStatus string

const (
	CertHealthHealthy  CertHealthStatus = "Healthy"
	CertHealthWarning  CertHealthStatus = "Warning"
	CertHealthCritical CertHealthStatus = "Critical"
	CertHealthExpired  CertHealthStatus = "Expired"
)

// CertificateCategory represents the type/category of a certificate
type CertificateCategory string

const (
	CertCategoryCA             CertificateCategory = "ca"
	CertCategoryKubeconfig     CertificateCategory = "kubeconfig"
	CertCategoryAPIServer      CertificateCategory = "apiserver"
	CertCategoryFrontProxy     CertificateCategory = "front-proxy"
	CertCategoryServiceAccount CertificateCategory = "service-account"
	CertCategoryDatastore      CertificateCategory = "datastore"
	CertCategoryKonnectivity   CertificateCategory = "konnectivity"
)

// RotationType defines what kind of rotation to perform
type RotationType string

const (
	RotateAllCerts    RotationType = "all"
	RotateKubeconfigs RotationType = "kubeconfigs"
	RotateCA          RotationType = "ca"
)

// RotationStatus represents the current status of a rotation operation
type RotationStatus string

const (
	RotationStatusUnknown    RotationStatus = "unknown"
	RotationStatusInProgress RotationStatus = "in_progress"
	RotationStatusCompleted  RotationStatus = "completed"
	RotationStatusFailed     RotationStatus = "failed"
)

// CertificateInfo holds parsed information about a single certificate
type CertificateInfo struct {
	// Subject is the certificate subject (CN, O, etc)
	Subject string `json:"subject"`

	// Issuer is the certificate issuer
	Issuer string `json:"issuer"`

	// SerialNumber is the certificate serial number (hex string)
	SerialNumber string `json:"serialNumber"`

	// NotBefore is when the certificate becomes valid
	NotBefore time.Time `json:"notBefore"`

	// NotAfter is when the certificate expires
	NotAfter time.Time `json:"notAfter"`

	// DaysUntilExpiry is calculated from NotAfter
	DaysUntilExpiry int `json:"daysUntilExpiry"`

	// AgeInDays is how old the certificate is (days since NotBefore)
	AgeInDays int `json:"ageInDays"`

	// HealthStatus based on expiry
	HealthStatus CertHealthStatus `json:"healthStatus"`

	// SecretName is the Kubernetes secret containing this cert
	SecretName string `json:"secretName"`

	// SecretKey is the key within the secret (e.g., "tls.crt", "ca.crt")
	SecretKey string `json:"secretKey"`

	// Category is the certificate category
	Category CertificateCategory `json:"category"`

	// IsCA indicates if this is a CA certificate
	IsCA bool `json:"isCA"`

	// DNSNames contains the DNS SANs from the certificate
	DNSNames []string `json:"dnsNames,omitempty"`

	// IPAddresses contains the IP SANs from the certificate
	IPAddresses []string `json:"ipAddresses,omitempty"`
}

// ClusterCertificates holds all certificate information for a cluster
type ClusterCertificates struct {
	// ClusterName is the name of the cluster
	ClusterName string `json:"clusterName"`

	// Namespace is the Butler namespace where TenantCluster lives
	Namespace string `json:"namespace"`

	// TCPNamespace is the Steward namespace where TenantControlPlane lives
	TCPNamespace string `json:"tcpNamespace,omitempty"`

	// Categories maps certificate category to list of certs
	Categories map[CertificateCategory][]CertificateInfo `json:"categories"`

	// OverallHealth is the worst health status across all certs
	OverallHealth CertHealthStatus `json:"overallHealth"`

	// CertificateCount is total number of certificates
	CertificateCount int `json:"certificateCount"`

	// EarliestExpiry is the soonest expiring certificate
	EarliestExpiry *time.Time `json:"earliestExpiry,omitempty"`

	// RotationInProgress indicates if a rotation is currently happening
	RotationInProgress bool `json:"rotationInProgress"`

	// LastRotation is the most recent rotation event
	LastRotation *RotationEvent `json:"lastRotation,omitempty"`
}

// RotationEvent represents a certificate rotation operation
type RotationEvent struct {
	// Type is what kind of rotation was performed
	Type RotationType `json:"type"`

	// InitiatedBy is the user who triggered the rotation
	InitiatedBy string `json:"initiatedBy,omitempty"`

	// InitiatedAt is when rotation was triggered
	InitiatedAt time.Time `json:"initiatedAt"`

	// CompletedAt is when rotation finished (nil if in progress)
	CompletedAt *time.Time `json:"completedAt,omitempty"`

	// Status is the current status of the rotation
	Status RotationStatus `json:"status"`

	// AffectedSecrets lists the secrets that were rotated
	AffectedSecrets []string `json:"affectedSecrets,omitempty"`

	// Message provides additional details
	Message string `json:"message,omitempty"`
}

// CategoryDisplayName returns a human-readable name for a category
func CategoryDisplayName(cat CertificateCategory) string {
	names := map[CertificateCategory]string{
		CertCategoryCA:             "Certificate Authorities",
		CertCategoryKubeconfig:     "Kubeconfigs",
		CertCategoryAPIServer:      "API Server Certificates",
		CertCategoryFrontProxy:     "Front Proxy Certificates",
		CertCategoryServiceAccount: "Service Account Keys",
		CertCategoryDatastore:      "Datastore Certificates",
		CertCategoryKonnectivity:   "Konnectivity Certificates",
	}

	if name, ok := names[cat]; ok {
		return name
	}
	return string(cat)
}

// CategorySortOrder returns the display order for a category (lower = first)
func CategorySortOrder(cat CertificateCategory) int {
	order := map[CertificateCategory]int{
		CertCategoryCA:             1,
		CertCategoryAPIServer:      2,
		CertCategoryKubeconfig:     3,
		CertCategoryFrontProxy:     4,
		CertCategoryKonnectivity:   5,
		CertCategoryDatastore:      6,
		CertCategoryServiceAccount: 7,
	}

	if o, ok := order[cat]; ok {
		return o
	}
	return 99
}
