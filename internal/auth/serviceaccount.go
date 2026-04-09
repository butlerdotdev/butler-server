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

package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	clientcmd "k8s.io/client-go/tools/clientcmd"
)

const (
	// CLIServiceAccountPrefix is the naming prefix for CLI-issued ServiceAccounts.
	CLIServiceAccountPrefix = "butler-cli-"

	// CLIUserLabel marks a ServiceAccount as managed by the CLI auth flow.
	CLIUserLabel = "butler.butlerlabs.dev/cli-user"

	// CLIEmailAnnotation stores the user's email on the ServiceAccount.
	CLIEmailAnnotation = "butler.butlerlabs.dev/cli-email"

	// CLILastLoginAnnotation tracks when the SA was last used.
	CLILastLoginAnnotation = "butler.butlerlabs.dev/cli-last-login"

	// CLIClusterRolePlatformAdmin is bound to platform admins.
	CLIClusterRolePlatformAdmin = "butler-cli-platform-admin"

	// CLIClusterRoleAdmin is bound for team-admin access.
	CLIClusterRoleAdmin = "butler-cli-admin"

	// CLIClusterRoleOperator is bound for team-operator access.
	CLIClusterRoleOperator = "butler-cli-operator"

	// CLIClusterRoleViewer is bound for team-viewer access.
	CLIClusterRoleViewer = "butler-cli-viewer"
)

// CLIServiceAccountManager handles ServiceAccount lifecycle for CLI users.
type CLIServiceAccountManager struct {
	clientset   kubernetes.Interface
	config      *rest.Config
	logger      *slog.Logger
	namespace   string
	tokenExpiry time.Duration
}

// NewCLIServiceAccountManager creates a new manager.
func NewCLIServiceAccountManager(
	clientset kubernetes.Interface,
	config *rest.Config,
	logger *slog.Logger,
	namespace string,
	tokenExpiry time.Duration,
) *CLIServiceAccountManager {
	return &CLIServiceAccountManager{
		clientset:   clientset,
		config:      config,
		logger:      logger,
		namespace:   namespace,
		tokenExpiry: tokenExpiry,
	}
}

// saNameForEmail derives a deterministic ServiceAccount name from an email address.
func saNameForEmail(email string) string {
	h := sha256.Sum256([]byte(email))
	return CLIServiceAccountPrefix + hex.EncodeToString(h[:])[:12]
}

// EnsureServiceAccount creates or updates a ServiceAccount for the given user.
func (m *CLIServiceAccountManager) EnsureServiceAccount(ctx context.Context, email string) (*corev1.ServiceAccount, error) {
	name := saNameForEmail(email)
	now := time.Now().UTC().Format(time.RFC3339)

	sa, err := m.clientset.CoreV1().ServiceAccounts(m.namespace).Get(ctx, name, metav1.GetOptions{})
	if err == nil {
		// Update last-login annotation
		if sa.Annotations == nil {
			sa.Annotations = make(map[string]string)
		}
		sa.Annotations[CLILastLoginAnnotation] = now
		updated, updateErr := m.clientset.CoreV1().ServiceAccounts(m.namespace).Update(ctx, sa, metav1.UpdateOptions{})
		if updateErr != nil {
			return nil, fmt.Errorf("failed to update service account: %w", updateErr)
		}
		m.logger.Info("Updated CLI service account", "name", name, "email", email)
		return updated, nil
	}

	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get service account: %w", err)
	}

	// Create new SA
	sa = &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: m.namespace,
			Labels: map[string]string{
				CLIUserLabel:                    "true",
				"app.kubernetes.io/managed-by":  "butler",
				"app.kubernetes.io/component":   "cli-auth",
			},
			Annotations: map[string]string{
				CLIEmailAnnotation:     email,
				CLILastLoginAnnotation: now,
			},
		},
	}

	created, err := m.clientset.CoreV1().ServiceAccounts(m.namespace).Create(ctx, sa, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create service account: %w", err)
	}

	m.logger.Info("Created CLI service account", "name", name, "email", email)
	return created, nil
}

// EnsureRoleBindings creates or updates RoleBindings in each team namespace for
// the user, and a ClusterRoleBinding for platform admins. Stale bindings for
// teams the user no longer belongs to are cleaned up.
func (m *CLIServiceAccountManager) EnsureRoleBindings(
	ctx context.Context,
	saName string,
	email string,
	teams []TeamMembership,
	isPlatformAdmin bool,
) error {
	// Build the set of desired team namespaces so we can GC stale bindings
	desiredNamespaces := make(map[string]bool, len(teams))

	for _, tm := range teams {
		ns := tm.Name // Team namespace follows the team name convention
		desiredNamespaces[ns] = true

		clusterRole := clusterRoleForTeamRole(tm.Role)
		rbName := fmt.Sprintf("%s-%s", saName, tm.Name)

		desired := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      rbName,
				Namespace: ns,
				Labels: map[string]string{
					CLIUserLabel:                   "true",
					"app.kubernetes.io/managed-by": "butler",
				},
				Annotations: map[string]string{
					CLIEmailAnnotation: email,
				},
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      saName,
					Namespace: m.namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     clusterRole,
			},
		}

		existing, err := m.clientset.RbacV1().RoleBindings(ns).Get(ctx, rbName, metav1.GetOptions{})
		if err == nil {
			// Update if the role ref changed (requires delete+create since RoleRef is immutable)
			if existing.RoleRef.Name != clusterRole {
				if delErr := m.clientset.RbacV1().RoleBindings(ns).Delete(ctx, rbName, metav1.DeleteOptions{}); delErr != nil {
					m.logger.Warn("Failed to delete stale role binding for update", "name", rbName, "namespace", ns, "error", delErr)
				}
				if _, createErr := m.clientset.RbacV1().RoleBindings(ns).Create(ctx, desired, metav1.CreateOptions{}); createErr != nil {
					return fmt.Errorf("failed to recreate role binding %s/%s: %w", ns, rbName, createErr)
				}
			}
			continue
		}

		if !apierrors.IsNotFound(err) {
			return fmt.Errorf("failed to get role binding %s/%s: %w", ns, rbName, err)
		}

		if _, err := m.clientset.RbacV1().RoleBindings(ns).Create(ctx, desired, metav1.CreateOptions{}); err != nil {
			if !apierrors.IsAlreadyExists(err) {
				return fmt.Errorf("failed to create role binding %s/%s: %w", ns, rbName, err)
			}
		}
	}

	// Platform admin ClusterRoleBinding
	crbName := saName + "-platform-admin"
	if isPlatformAdmin {
		desired := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name: crbName,
				Labels: map[string]string{
					CLIUserLabel:                   "true",
					"app.kubernetes.io/managed-by": "butler",
				},
				Annotations: map[string]string{
					CLIEmailAnnotation: email,
				},
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      saName,
					Namespace: m.namespace,
				},
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: "rbac.authorization.k8s.io",
				Kind:     "ClusterRole",
				Name:     CLIClusterRolePlatformAdmin,
			},
		}

		_, err := m.clientset.RbacV1().ClusterRoleBindings().Get(ctx, crbName, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			if _, createErr := m.clientset.RbacV1().ClusterRoleBindings().Create(ctx, desired, metav1.CreateOptions{}); createErr != nil {
				if !apierrors.IsAlreadyExists(createErr) {
					return fmt.Errorf("failed to create cluster role binding %s: %w", crbName, createErr)
				}
			}
		} else if err != nil {
			return fmt.Errorf("failed to get cluster role binding %s: %w", crbName, err)
		}
	} else {
		// Remove platform admin CRB if user is no longer an admin
		err := m.clientset.RbacV1().ClusterRoleBindings().Delete(ctx, crbName, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			m.logger.Warn("Failed to delete stale platform admin cluster role binding", "name", crbName, "error", err)
		}
	}

	// Clean up stale RoleBindings for teams the user is no longer in.
	// List all RBs with our label and SA annotation matching this email.
	allRBs, err := m.clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{
		LabelSelector: CLIUserLabel + "=true",
	})
	if err != nil {
		m.logger.Warn("Failed to list role bindings for cleanup", "error", err)
		return nil // non-fatal
	}

	for _, rb := range allRBs.Items {
		if rb.Annotations[CLIEmailAnnotation] != email {
			continue
		}
		if desiredNamespaces[rb.Namespace] {
			continue
		}
		// This binding is for a team the user no longer belongs to
		if delErr := m.clientset.RbacV1().RoleBindings(rb.Namespace).Delete(ctx, rb.Name, metav1.DeleteOptions{}); delErr != nil {
			m.logger.Warn("Failed to delete stale role binding", "name", rb.Name, "namespace", rb.Namespace, "error", delErr)
		} else {
			m.logger.Info("Cleaned up stale CLI role binding", "name", rb.Name, "namespace", rb.Namespace, "email", email)
		}
	}

	return nil
}

// CreateToken creates a short-lived ServiceAccount token via the TokenRequest API.
func (m *CLIServiceAccountManager) CreateToken(ctx context.Context, saName string) (string, time.Time, error) {
	expirationSeconds := int64(m.tokenExpiry.Seconds())
	req := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &expirationSeconds,
		},
	}

	resp, err := m.clientset.CoreV1().ServiceAccounts(m.namespace).CreateToken(ctx, saName, req, metav1.CreateOptions{})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to create token: %w", err)
	}

	return resp.Status.Token, resp.Status.ExpirationTimestamp.Time, nil
}

// BuildKubeconfig assembles a kubeconfig YAML from the SA token and the
// management cluster's CA and server URL.
func (m *CLIServiceAccountManager) BuildKubeconfig(token, saName string) ([]byte, error) {
	clusterName := "butler"
	contextName := "butler"
	userName := saName

	kubeconfig := clientcmdapi.NewConfig()
	kubeconfig.Clusters[clusterName] = &clientcmdapi.Cluster{
		Server:                   m.config.Host,
		CertificateAuthorityData: m.config.CAData,
	}
	// If no CA data but a CA file is set, reference it
	if len(kubeconfig.Clusters[clusterName].CertificateAuthorityData) == 0 && m.config.CAFile != "" {
		kubeconfig.Clusters[clusterName].CertificateAuthority = m.config.CAFile
	}

	kubeconfig.AuthInfos[userName] = &clientcmdapi.AuthInfo{
		Token: token,
	}

	kubeconfig.Contexts[contextName] = &clientcmdapi.Context{
		Cluster:  clusterName,
		AuthInfo: userName,
	}
	kubeconfig.CurrentContext = contextName

	return clientcmd.Write(*kubeconfig)
}

// CleanupStaleSAs deletes CLI ServiceAccounts whose last-login annotation is
// older than maxAge.
func (m *CLIServiceAccountManager) CleanupStaleSAs(ctx context.Context, maxAge time.Duration) error {
	saList, err := m.clientset.CoreV1().ServiceAccounts(m.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: CLIUserLabel + "=true",
	})
	if err != nil {
		return fmt.Errorf("failed to list CLI service accounts: %w", err)
	}

	cutoff := time.Now().Add(-maxAge)
	for _, sa := range saList.Items {
		lastLogin := sa.Annotations[CLILastLoginAnnotation]
		if lastLogin == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339, lastLogin)
		if err != nil {
			m.logger.Warn("Invalid last-login annotation", "sa", sa.Name, "value", lastLogin)
			continue
		}
		if t.Before(cutoff) {
			m.logger.Info("Cleaning up stale CLI service account", "name", sa.Name, "lastLogin", lastLogin)

			// Delete associated RoleBindings
			email := sa.Annotations[CLIEmailAnnotation]
			if email != "" {
				rbs, listErr := m.clientset.RbacV1().RoleBindings("").List(ctx, metav1.ListOptions{
					LabelSelector: CLIUserLabel + "=true",
				})
				if listErr == nil {
					for _, rb := range rbs.Items {
						if rb.Annotations[CLIEmailAnnotation] == email {
							_ = m.clientset.RbacV1().RoleBindings(rb.Namespace).Delete(ctx, rb.Name, metav1.DeleteOptions{})
						}
					}
				}

				// Delete ClusterRoleBinding
				crbName := sa.Name + "-platform-admin"
				_ = m.clientset.RbacV1().ClusterRoleBindings().Delete(ctx, crbName, metav1.DeleteOptions{})
			}

			if delErr := m.clientset.CoreV1().ServiceAccounts(m.namespace).Delete(ctx, sa.Name, metav1.DeleteOptions{}); delErr != nil {
				m.logger.Warn("Failed to delete stale service account", "name", sa.Name, "error", delErr)
			}
		}
	}

	return nil
}

// clusterRoleForTeamRole maps a Butler team role to the corresponding ClusterRole name.
func clusterRoleForTeamRole(role string) string {
	switch role {
	case RoleAdmin:
		return CLIClusterRoleAdmin
	case RoleOperator:
		return CLIClusterRoleOperator
	default:
		return CLIClusterRoleViewer
	}
}
