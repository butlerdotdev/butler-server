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
	"fmt"
	"log/slog"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// TenantControlPlane GVR for Steward
var TenantControlPlaneGVR = schema.GroupVersionResource{
	Group:    "steward.butlerlabs.dev",
	Version:  "v1alpha1",
	Resource: "tenantcontrolplanes",
}

const (
	// StewardNamespace is the namespace where Steward controller runs
	StewardNamespace = "steward-system"
	// StewardDeploymentName is the name of the Steward controller deployment
	StewardDeploymentName = "steward"

	// ButlerRotationAnnotation tracks when Butler initiated a rotation
	ButlerRotationAnnotation = "butler.butlerlabs.dev/rotation-initiated"
	// ButlerRotationByAnnotation tracks who initiated the rotation
	ButlerRotationByAnnotation = "butler.butlerlabs.dev/rotation-initiated-by"
	// ButlerRotationTypeAnnotation tracks what type of rotation
	ButlerRotationTypeAnnotation = "butler.butlerlabs.dev/rotation-type"
	// ButlerRotationSecretsAnnotation stores the list of secrets being rotated
	ButlerRotationSecretsAnnotation = "butler.butlerlabs.dev/rotation-secrets"

	// RotationCompletionTimeout is the maximum time to wait for rotation to complete
	// before marking it as failed. Actual completion is detected when secrets are recreated.
	RotationCompletionTimeout = 5 * time.Minute
)

// Service handles certificate lifecycle operations.
type Service struct {
	clientset     kubernetes.Interface
	dynamicClient dynamic.Interface
	logger        *slog.Logger
}

// NewService creates a new certificate service.
func NewService(clientset kubernetes.Interface, dynamicClient dynamic.Interface, logger *slog.Logger) *Service {
	return &Service{
		clientset:     clientset,
		dynamicClient: dynamicClient,
		logger:        logger.With("component", "certificates-service"),
	}
}

// GetClusterCertificates retrieves all certificate information for a cluster.
func (s *Service) GetClusterCertificates(ctx context.Context, namespace, clusterName string) (*ClusterCertificates, error) {
	// Find the TCP namespace (where Steward resources live)
	tcpNamespace, err := s.findTCPNamespace(ctx, namespace, clusterName)
	if err != nil {
		s.logger.Warn("Could not find TCP namespace, using cluster namespace",
			"cluster", clusterName,
			"namespace", namespace,
			"error", err,
		)
		tcpNamespace = namespace
	}

	s.logger.Debug("Discovering certificates",
		"cluster", clusterName,
		"tcpNamespace", tcpNamespace,
	)

	// List all secrets with Steward project label
	secrets, err := s.clientset.CoreV1().Secrets(tcpNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=steward", StewardProjectLabel),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list certificate secrets: %w", err)
	}

	result := &ClusterCertificates{
		ClusterName:   clusterName,
		Namespace:     namespace,
		TCPNamespace:  tcpNamespace,
		Categories:    make(map[CertificateCategory][]CertificateInfo),
		OverallHealth: CertHealthHealthy,
	}

	var earliestExpiry *time.Time
	var certCount int

	for _, secret := range secrets.Items {
		// Filter to secrets belonging to this cluster
		if !s.secretBelongsToCluster(secret, clusterName) {
			continue
		}

		// Skip secrets that don't contain certificates
		// datastore-config contains connection info, not certs
		if strings.HasSuffix(secret.Name, "-datastore-config") {
			continue
		}

		category := s.categorizeSecret(secret)

		// Parse certificates from the secret
		for key, data := range secret.Data {
			if !IsCertificateKey(key) {
				continue
			}

			certInfo, err := ParseCertificateFromSecretData(key, data)
			if err != nil {
				s.logger.Debug("Failed to parse certificate",
					"secret", secret.Name,
					"key", key,
					"error", err,
				)
				continue
			}

			certInfo.SecretName = secret.Name
			certInfo.SecretKey = key
			certInfo.Category = category

			result.Categories[category] = append(result.Categories[category], *certInfo)
			certCount++

			// Track earliest expiry
			if earliestExpiry == nil || certInfo.NotAfter.Before(*earliestExpiry) {
				earliestExpiry = &certInfo.NotAfter
			}

			// Update overall health (worst wins)
			result.OverallHealth = WorstHealth(result.OverallHealth, certInfo.HealthStatus)
		}
	}

	result.EarliestExpiry = earliestExpiry
	result.CertificateCount = certCount

	// Check for active rotation using TCP annotation
	rotationInProgress, lastRotation := s.checkRotationStatus(ctx, tcpNamespace, clusterName)
	result.RotationInProgress = rotationInProgress
	result.LastRotation = lastRotation

	s.logger.Info("Certificate discovery complete",
		"cluster", clusterName,
		"totalCerts", certCount,
		"overallHealth", result.OverallHealth,
		"rotationInProgress", rotationInProgress,
	)

	return result, nil
}

// checkRotationStatus determines if a rotation is in progress by checking TCP annotations
// and verifying if secrets have been recreated.
func (s *Service) checkRotationStatus(ctx context.Context, tcpNamespace, clusterName string) (bool, *RotationEvent) {
	tcp, err := s.getTenantControlPlane(ctx, tcpNamespace, clusterName)
	if err != nil {
		s.logger.Debug("Could not get TCP for rotation status", "error", err)
		return false, nil
	}

	annotations := tcp.GetAnnotations()
	if annotations == nil {
		return false, nil
	}

	rotationTimeStr := annotations[ButlerRotationAnnotation]
	if rotationTimeStr == "" {
		return false, nil
	}

	rotationTime, err := time.Parse(time.RFC3339, rotationTimeStr)
	if err != nil {
		s.logger.Debug("Invalid rotation timestamp", "value", rotationTimeStr, "error", err)
		return false, nil
	}

	event := &RotationEvent{
		InitiatedAt: rotationTime,
		InitiatedBy: annotations[ButlerRotationByAnnotation],
	}

	// Parse rotation type
	switch annotations[ButlerRotationTypeAnnotation] {
	case string(RotateKubeconfigs):
		event.Type = RotateKubeconfigs
	case string(RotateCA):
		event.Type = RotateCA
	default:
		event.Type = RotateAllCerts
	}

	// Get the list of secrets that were rotated from annotation
	secretsStr := annotations[ButlerRotationSecretsAnnotation]
	var affectedSecrets []string
	if secretsStr != "" {
		affectedSecrets = strings.Split(secretsStr, ",")
	}
	event.AffectedSecrets = affectedSecrets

	s.logger.Debug("Read rotation state from TCP",
		"cluster", clusterName,
		"rotationTime", rotationTime,
		"rotationType", event.Type,
		"secretsAnnotation", secretsStr,
		"parsedSecrets", len(affectedSecrets),
	)

	// Check if secrets have been recreated after rotation started
	// This is the real completion signal - Steward has regenerated the certs
	secretsRecreated, recreationTime := s.checkSecretsRecreated(ctx, tcpNamespace, affectedSecrets, rotationTime)

	if secretsRecreated {
		// Rotation is complete - secrets exist with timestamps after rotation
		event.Status = RotationStatusCompleted
		event.CompletedAt = recreationTime
		s.logger.Debug("Rotation complete - secrets recreated",
			"cluster", clusterName,
			"rotationStarted", rotationTime,
			"secretsRecreated", recreationTime,
		)
		return false, event
	}

	// Secrets not yet recreated - check if we've hit the max timeout
	if time.Since(rotationTime) > RotationCompletionTimeout {
		// Timeout exceeded but secrets still not recreated - something may be wrong
		event.Status = RotationStatusFailed
		event.Message = "Rotation timed out - secrets were not recreated within expected time"
		s.logger.Warn("Rotation timeout exceeded",
			"cluster", clusterName,
			"rotationStarted", rotationTime,
			"elapsed", time.Since(rotationTime),
		)
		return false, event
	}

	// Still waiting for secrets to be recreated
	event.Status = RotationStatusInProgress
	return true, event
}

// checkSecretsRecreated verifies if the rotated secrets have been recreated after the rotation started.
func (s *Service) checkSecretsRecreated(ctx context.Context, tcpNamespace string, secretNames []string, rotationStarted time.Time) (bool, *time.Time) {
	s.logger.Debug("Checking if secrets were recreated",
		"secretCount", len(secretNames),
		"secrets", secretNames,
		"rotationStarted", rotationStarted,
	)

	if len(secretNames) == 0 {
		// No secrets to check - can't determine completion without knowing what was rotated
		s.logger.Warn("No secret names stored for rotation check - annotation may not have been saved")
		return false, nil
	}

	var latestCreation time.Time
	allRecreated := true
	missingSecrets := []string{}
	oldSecrets := []string{}

	for _, secretName := range secretNames {
		secret, err := s.clientset.CoreV1().Secrets(tcpNamespace).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			// Secret doesn't exist yet - still being recreated
			s.logger.Debug("Secret not yet recreated", "secret", secretName, "error", err)
			missingSecrets = append(missingSecrets, secretName)
			allRecreated = false
			continue
		}

		secretCreated := secret.CreationTimestamp.Time
		threshold := rotationStarted.Add(-5 * time.Second)

		// Check if this secret was created AFTER rotation started
		if secretCreated.Before(threshold) {
			// Secret exists but wasn't recreated - this is the old secret
			s.logger.Debug("Secret exists but predates rotation",
				"secret", secretName,
				"secretCreated", secretCreated,
				"rotationStarted", rotationStarted,
				"threshold", threshold,
			)
			oldSecrets = append(oldSecrets, secretName)
			allRecreated = false
			continue
		}

		s.logger.Debug("Secret successfully recreated",
			"secret", secretName,
			"secretCreated", secretCreated,
		)

		// Track the latest creation time
		if secretCreated.After(latestCreation) {
			latestCreation = secretCreated
		}
	}

	if len(missingSecrets) > 0 || len(oldSecrets) > 0 {
		s.logger.Debug("Secrets not yet fully recreated",
			"missing", missingSecrets,
			"oldTimestamps", oldSecrets,
			"total", len(secretNames),
		)
	}

	if allRecreated && !latestCreation.IsZero() {
		s.logger.Info("All secrets recreated successfully",
			"secretCount", len(secretNames),
			"latestCreation", latestCreation,
		)
		return true, &latestCreation
	}

	return false, nil
}

// RotateCertificates triggers certificate rotation by deleting secrets and restarting Steward.
func (s *Service) RotateCertificates(ctx context.Context, namespace, clusterName string, rotationType RotationType, initiatedBy string) (*RotationEvent, error) {
	tcpNamespace, err := s.findTCPNamespace(ctx, namespace, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to find TCP namespace: %w", err)
	}

	// Get secrets to rotate based on type
	secretNames, err := s.getSecretsForRotation(ctx, tcpNamespace, clusterName, rotationType)
	if err != nil {
		return nil, fmt.Errorf("failed to get secrets for rotation: %w", err)
	}

	if len(secretNames) == 0 {
		return nil, fmt.Errorf("no secrets found for rotation type %s", rotationType)
	}

	event := &RotationEvent{
		Type:            rotationType,
		InitiatedBy:     initiatedBy,
		InitiatedAt:     time.Now().UTC(),
		Status:          RotationStatusInProgress,
		AffectedSecrets: secretNames,
	}

	s.logger.Info("Initiating certificate rotation",
		"cluster", clusterName,
		"namespace", namespace,
		"tcpNamespace", tcpNamespace,
		"type", rotationType,
		"initiatedBy", initiatedBy,
		"secretCount", len(secretNames),
		"secrets", secretNames,
	)

	// Mark rotation on TCP for tracking (include affected secrets for later verification)
	if err := s.markRotationStarted(ctx, tcpNamespace, clusterName, rotationType, initiatedBy, secretNames); err != nil {
		s.logger.Warn("Failed to mark rotation on TCP", "error", err)
		// Continue anyway - this is just for tracking
	}

	// Delete each secret to trigger rotation
	for _, secretName := range secretNames {
		s.logger.Debug("Deleting secret for rotation", "secret", secretName, "namespace", tcpNamespace)

		err := s.clientset.CoreV1().Secrets(tcpNamespace).Delete(ctx, secretName, metav1.DeleteOptions{})
		if err != nil {
			s.logger.Error("Failed to delete secret",
				"secret", secretName,
				"error", err,
			)
			return nil, fmt.Errorf("failed to delete secret %s for rotation: %w", secretName, err)
		}

		s.logger.Info("Deleted secret for rotation",
			"secret", secretName,
			"namespace", tcpNamespace,
		)
	}

	// Restart Steward deployment to trigger fresh certificate generation
	s.logger.Info("Attempting to restart Steward deployment")
	if err := s.restartStewardDeployment(ctx); err != nil {
		s.logger.Error("Failed to restart Steward deployment",
			"error", err,
		)
		event.Message = fmt.Sprintf("Secrets deleted but Steward restart failed: %v. Manual restart may be required.", err)
		// Don't fail the rotation - secrets are deleted, but warn the user
	} else {
		s.logger.Info("Steward deployment restart triggered successfully")
	}

	return event, nil
}

// markRotationStarted adds annotations to TCP to track rotation state.
func (s *Service) markRotationStarted(ctx context.Context, tcpNamespace, clusterName string, rotationType RotationType, initiatedBy string, affectedSecrets []string) error {
	// Store affected secrets as comma-separated list for later verification
	secretsList := strings.Join(affectedSecrets, ",")

	s.logger.Debug("Marking rotation started on TCP",
		"cluster", clusterName,
		"namespace", tcpNamespace,
		"rotationType", rotationType,
		"initiatedBy", initiatedBy,
		"secretCount", len(affectedSecrets),
		"secretsList", secretsList,
	)

	patch := fmt.Sprintf(`{
		"metadata": {
			"annotations": {
				"%s": "%s",
				"%s": "%s",
				"%s": "%s",
				"%s": "%s"
			}
		}
	}`,
		ButlerRotationAnnotation, time.Now().UTC().Format(time.RFC3339),
		ButlerRotationByAnnotation, initiatedBy,
		ButlerRotationTypeAnnotation, string(rotationType),
		ButlerRotationSecretsAnnotation, secretsList,
	)

	_, err := s.dynamicClient.Resource(TenantControlPlaneGVR).Namespace(tcpNamespace).Patch(
		ctx,
		clusterName,
		types.MergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		s.logger.Error("Failed to mark rotation on TCP", "error", err)
	}
	return err
}

// restartStewardDeployment triggers a rollout restart of the Steward controller deployment.
// This forces Steward to regenerate certificates with fresh key material instead of
// restoring from its internal cache.
func (s *Service) restartStewardDeployment(ctx context.Context) error {
	s.logger.Debug("Patching Steward deployment to trigger restart",
		"namespace", StewardNamespace,
		"deployment", StewardDeploymentName,
	)

	// Patch the deployment to trigger a rollout restart
	// This adds/updates an annotation on the pod template, forcing a new rollout
	patch := fmt.Sprintf(`{"spec":{"template":{"metadata":{"annotations":{"kubectl.kubernetes.io/restartedAt":"%s"}}}}}`,
		time.Now().Format(time.RFC3339))

	_, err := s.clientset.AppsV1().Deployments(StewardNamespace).Patch(
		ctx,
		StewardDeploymentName,
		types.StrategicMergePatchType,
		[]byte(patch),
		metav1.PatchOptions{},
	)
	if err != nil {
		return fmt.Errorf("failed to patch Steward deployment: %w", err)
	}

	s.logger.Info("Triggered Steward deployment rollout restart",
		"namespace", StewardNamespace,
		"deployment", StewardDeploymentName,
	)

	return nil
}

// CheckRotationStatus checks if a rotation is complete by examining TCP conditions.
func (s *Service) CheckRotationStatus(ctx context.Context, namespace, clusterName string) (*RotationEvent, error) {
	tcpNamespace, err := s.findTCPNamespace(ctx, namespace, clusterName)
	if err != nil {
		tcpNamespace = namespace
	}

	inProgress, event := s.checkRotationStatus(ctx, tcpNamespace, clusterName)
	if event == nil {
		return &RotationEvent{Status: RotationStatusUnknown}, nil
	}

	if inProgress {
		event.Status = RotationStatusInProgress
	} else {
		event.Status = RotationStatusCompleted
	}

	return event, nil
}

// GetSecretsForCategory returns the secrets that belong to a specific category.
func (s *Service) GetSecretsForCategory(ctx context.Context, namespace, clusterName string, category CertificateCategory) ([]string, error) {
	tcpNamespace, err := s.findTCPNamespace(ctx, namespace, clusterName)
	if err != nil {
		tcpNamespace = namespace
	}

	secrets, err := s.clientset.CoreV1().Secrets(tcpNamespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=steward", StewardProjectLabel),
	})
	if err != nil {
		return nil, err
	}

	var result []string
	for _, secret := range secrets.Items {
		if !s.secretBelongsToCluster(secret, clusterName) {
			continue
		}

		secretCategory := s.categorizeSecret(secret)
		if secretCategory == category {
			result = append(result, secret.Name)
		}
	}

	return result, nil
}

// findTCPNamespace finds the namespace containing the TenantControlPlane for a cluster.
func (s *Service) findTCPNamespace(ctx context.Context, tcNamespace, clusterName string) (string, error) {
	// First, try to get the TenantCluster to find the tenantNamespace
	tcGVR := schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "tenantclusters",
	}

	tc, err := s.dynamicClient.Resource(tcGVR).Namespace(tcNamespace).Get(ctx, clusterName, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to get TenantCluster: %w", err)
	}

	// Check status.tenantNamespace first
	if tenantNS, found, _ := unstructured.NestedString(tc.Object, "status", "tenantNamespace"); found && tenantNS != "" {
		return tenantNS, nil
	}

	// Fall back to a generated namespace pattern
	return fmt.Sprintf("%s-%s", clusterName, tcNamespace), nil
}

// getTenantControlPlane retrieves the Steward TenantControlPlane resource.
func (s *Service) getTenantControlPlane(ctx context.Context, namespace, name string) (*unstructured.Unstructured, error) {
	return s.dynamicClient.Resource(TenantControlPlaneGVR).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
}

// secretBelongsToCluster checks if a secret belongs to a specific cluster.
func (s *Service) secretBelongsToCluster(secret corev1.Secret, clusterName string) bool {
	// Check Steward tenant label
	if tenantName, ok := secret.Labels[StewardTenantLabel]; ok {
		return tenantName == clusterName
	}

	// Fall back to name prefix matching
	return strings.HasPrefix(secret.Name, clusterName+"-")
}

// categorizeSecret determines the category of a certificate secret.
func (s *Service) categorizeSecret(secret corev1.Secret) CertificateCategory {
	// Prefer using the component label if available
	component := secret.Labels[StewardComponentLabel]
	if component != "" {
		switch {
		case strings.HasSuffix(component, "-kubeconfig"):
			return CertCategoryKubeconfig
		case component == "ca":
			return CertCategoryCA
		case strings.HasPrefix(component, "front-proxy-ca"):
			return CertCategoryCA
		case strings.HasPrefix(component, "front-proxy"):
			return CertCategoryFrontProxy
		case component == "sa-certificate":
			return CertCategoryServiceAccount
		case strings.HasPrefix(component, "datastore"):
			return CertCategoryDatastore
		case strings.HasPrefix(component, "konnectivity"):
			return CertCategoryKonnectivity
		case strings.HasPrefix(component, "api-server"):
			return CertCategoryAPIServer
		}
	}

	// Fall back to name-based matching
	name := secret.Name

	switch {
	case strings.Contains(name, "kubeconfig"):
		return CertCategoryKubeconfig
	case strings.HasSuffix(name, "-ca") || strings.Contains(name, "-ca-"):
		return CertCategoryCA
	case strings.Contains(name, "front-proxy"):
		return CertCategoryFrontProxy
	case strings.Contains(name, "sa-"):
		return CertCategoryServiceAccount
	case strings.Contains(name, "datastore") || strings.Contains(name, "etcd"):
		return CertCategoryDatastore
	case strings.Contains(name, "konnectivity"):
		return CertCategoryKonnectivity
	default:
		return CertCategoryAPIServer
	}
}

// getSecretsForRotation returns the list of secrets to rotate based on rotation type.
func (s *Service) getSecretsForRotation(ctx context.Context, namespace, clusterName string, rotationType RotationType) ([]string, error) {
	secrets, err := s.clientset.CoreV1().Secrets(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("%s=steward", StewardProjectLabel),
	})
	if err != nil {
		return nil, err
	}

	var result []string
	for _, secret := range secrets.Items {
		if !s.secretBelongsToCluster(secret, clusterName) {
			continue
		}

		// Skip secrets that don't contain certificates
		// datastore-config contains connection info, not certs
		if strings.HasSuffix(secret.Name, "-datastore-config") {
			continue
		}

		category := s.categorizeSecret(secret)

		switch rotationType {
		case RotateAllCerts:
			// Exclude CA from "all" rotation
			if category != CertCategoryCA {
				result = append(result, secret.Name)
			}

		case RotateKubeconfigs:
			if category == CertCategoryKubeconfig {
				result = append(result, secret.Name)
			}

		case RotateCA:
			// CA rotation MUST include ALL certificates, not just CAs
			// All leaf certs are signed by the CA, so they become invalid
			// when the CA changes and must be regenerated
			result = append(result, secret.Name)
		}
	}

	return result, nil
}
