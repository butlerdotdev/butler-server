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

package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/certificates"
	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/go-chi/chi/v5"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// CertificateHandler handles certificate-related endpoints.
type CertificateHandler struct {
	certService *certificates.Service
	k8sClient   *k8s.Client
	config      *config.Config
	logger      *slog.Logger
}

// NewCertificateHandler creates a new certificate handler.
func NewCertificateHandler(k8sClient *k8s.Client, cfg *config.Config, logger *slog.Logger) *CertificateHandler {
	return &CertificateHandler{
		certService: certificates.NewService(
			k8sClient.Clientset(),
			k8sClient.Dynamic(),
			logger.With("component", "certificates-service"),
		),
		k8sClient: k8sClient,
		config:    cfg,
		logger:    logger,
	}
}

// GetCertificates returns certificate information for a cluster.
// GET /api/clusters/{namespace}/{name}/certificates
func (h *CertificateHandler) GetCertificates(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	h.logger.Debug("Getting certificates",
		"namespace", namespace,
		"cluster", name,
		"user", getUserIdentifier(user),
	)

	// Check cluster access
	tc, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	if user != nil {
		if err := h.checkClusterAccess(user, tc); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	certs, err := h.certService.GetClusterCertificates(r.Context(), namespace, name)
	if err != nil {
		h.logger.Error("Failed to get certificates",
			"namespace", namespace,
			"cluster", name,
			"error", err,
		)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get certificates: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, certs)
}

// RotateCertificatesRequest defines the rotation request body.
type RotateCertificatesRequest struct {
	// Type is the rotation scope: "all", "kubeconfigs", or "ca"
	Type certificates.RotationType `json:"type"`

	// Acknowledge must be true for CA rotation (explicit confirmation required)
	Acknowledge bool `json:"acknowledge"`
}

// RotateCertificates triggers certificate rotation.
// POST /api/clusters/{namespace}/{name}/certificates/rotate
func (h *CertificateHandler) RotateCertificates(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	h.logger.Info("Certificate rotation requested",
		"namespace", namespace,
		"cluster", name,
		"user", getUserIdentifier(user),
	)

	// Check cluster access
	tc, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	if user != nil {
		if err := h.checkClusterAccess(user, tc); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}

		// Rotation requires operator role (admin or operator, not viewer)
		if !h.canRotateCertificates(user, tc) {
			writeError(w, http.StatusForbidden, "certificate rotation requires operator role")
			return
		}
	}

	var req RotateCertificatesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate rotation type
	switch req.Type {
	case certificates.RotateAllCerts, certificates.RotateKubeconfigs:
		// OK - operator role is sufficient

	case certificates.RotateCA:
		// CA rotation requires explicit acknowledgment
		if !req.Acknowledge {
			writeError(w, http.StatusBadRequest, "CA rotation requires explicit acknowledgment (acknowledge: true)")
			return
		}
		// CA rotation requires admin role
		if user != nil && !h.canRotateCA(user, tc) {
			writeError(w, http.StatusForbidden, "CA rotation requires admin role")
			return
		}

	default:
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid rotation type: %s (must be 'all', 'kubeconfigs', or 'ca')", req.Type))
		return
	}

	// Check for rotation already in progress
	certs, err := h.certService.GetClusterCertificates(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to check rotation status: %v", err))
		return
	}

	if certs.RotationInProgress {
		writeError(w, http.StatusConflict, "rotation already in progress")
		return
	}

	// Determine who initiated the rotation
	initiatedBy := "anonymous"
	if user != nil {
		initiatedBy = user.Email
		if initiatedBy == "" {
			initiatedBy = user.Name
		}
	}

	// Initiate rotation
	event, err := h.certService.RotateCertificates(r.Context(), namespace, name, req.Type, initiatedBy)
	if err != nil {
		h.logger.Error("Failed to initiate rotation",
			"namespace", namespace,
			"cluster", name,
			"type", req.Type,
			"error", err,
		)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to initiate rotation: %v", err))
		return
	}

	h.logger.Info("Certificate rotation initiated",
		"namespace", namespace,
		"cluster", name,
		"type", req.Type,
		"initiatedBy", initiatedBy,
		"secretCount", len(event.AffectedSecrets),
	)

	// TODO: Create Kubernetes Event for audit trail
	// TODO: Store rotation event in a more persistent location

	writeJSON(w, http.StatusAccepted, event)
}

// GetRotationStatus returns the current rotation status.
// GET /api/clusters/{namespace}/{name}/certificates/rotation-status
func (h *CertificateHandler) GetRotationStatus(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	// Check cluster access
	tc, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	if user != nil {
		if err := h.checkClusterAccess(user, tc); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	status, err := h.certService.CheckRotationStatus(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get rotation status: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, status)
}

// GetCertificatesByCategory returns certificates for a specific category.
// GET /api/clusters/{namespace}/{name}/certificates/{category}
func (h *CertificateHandler) GetCertificatesByCategory(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	categoryStr := chi.URLParam(r, "category")

	// Validate category
	category := certificates.CertificateCategory(categoryStr)
	validCategories := map[certificates.CertificateCategory]bool{
		certificates.CertCategoryAPIServer:      true,
		certificates.CertCategoryKubeconfig:     true,
		certificates.CertCategoryCA:             true,
		certificates.CertCategoryFrontProxy:     true,
		certificates.CertCategoryServiceAccount: true,
		certificates.CertCategoryDatastore:      true,
		certificates.CertCategoryKonnectivity:   true,
	}

	if !validCategories[category] {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid category: %s", categoryStr))
		return
	}

	// Check cluster access
	tc, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	if user != nil {
		if err := h.checkClusterAccess(user, tc); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	certs, err := h.certService.GetClusterCertificates(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get certificates: %v", err))
		return
	}

	categoryCerts, ok := certs.Categories[category]
	if !ok {
		categoryCerts = []certificates.CertificateInfo{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"category":     category,
		"certificates": categoryCerts,
	})
}

// checkClusterAccess verifies the user has access to a cluster based on its teamRef.
func (h *CertificateHandler) checkClusterAccess(user *auth.UserSession, cluster *unstructured.Unstructured) error {
	// Platform admins can access all clusters
	if user.IsPlatformAdmin {
		return nil
	}

	// Admins can access all clusters
	if user.IsAdmin() {
		return nil
	}

	// Get the cluster's team reference
	teamRef, found, _ := unstructured.NestedString(cluster.Object, "spec", "teamRef", "name")

	// If cluster has no teamRef, it's a platform-level cluster
	if !found || teamRef == "" {
		return fmt.Errorf("forbidden: cluster is not associated with any team")
	}

	// Check if user is a member of the cluster's team
	if !user.HasTeamMembership(teamRef) {
		return fmt.Errorf("forbidden: you don't have access to team '%s'", teamRef)
	}

	return nil
}

// canRotateCertificates checks if the user has operator role for the cluster's team.
func (h *CertificateHandler) canRotateCertificates(user *auth.UserSession, cluster *unstructured.Unstructured) bool {
	// Platform admins can rotate any certificates
	if user.IsPlatformAdmin {
		return true
	}

	// Admins can rotate any certificates
	if user.IsAdmin() {
		return true
	}

	teamRef, found, _ := unstructured.NestedString(cluster.Object, "spec", "teamRef", "name")
	if !found || teamRef == "" {
		return false
	}

	// Operators and admins can rotate non-CA certificates
	return user.CanOperateTeam(teamRef)
}

// canRotateCA checks if the user has admin role for CA rotation.
func (h *CertificateHandler) canRotateCA(user *auth.UserSession, cluster *unstructured.Unstructured) bool {
	// Platform admins can rotate CA
	if user.IsPlatformAdmin {
		return true
	}

	teamRef, found, _ := unstructured.NestedString(cluster.Object, "spec", "teamRef", "name")
	if !found || teamRef == "" {
		// No team - only platform admins can rotate
		return false
	}

	// Only team admins can rotate CA
	return user.IsAdminOfTeam(teamRef)
}

// getUserIdentifier returns a user identifier for logging.
func getUserIdentifier(user *auth.UserSession) string {
	if user == nil {
		return "anonymous"
	}
	if user.Email != "" {
		return user.Email
	}
	if user.Name != "" {
		return user.Name
	}
	return user.Subject
}
