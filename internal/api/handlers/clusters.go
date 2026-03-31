/*
Copyright 2025 The Butler Authors.

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
	"regexp"
	"strings"
	"time"

	"sigs.k8s.io/yaml"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/go-chi/chi/v5"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// ClusterHandler handles cluster-related endpoints.
type ClusterHandler struct {
	k8sClient *k8s.Client
	config    *config.Config
}

// NewClusterHandler creates a new clusters handler.
func NewClusterHandler(k8sClient *k8s.Client, cfg *config.Config) *ClusterHandler {
	return &ClusterHandler{
		k8sClient: k8sClient,
		config:    cfg,
	}
}

// ClusterListResponse represents the cluster list response.
type ClusterListResponse struct {
	Clusters []map[string]interface{} `json:"clusters"`
}

// checkClusterAccess verifies the user has access to a cluster based on its teamRef.
// Returns nil if access is granted, or an error message if denied.
// When team context is set, only allows access to clusters in that team.
func (h *ClusterHandler) checkClusterAccess(user *auth.UserSession, cluster *unstructured.Unstructured) error {
	// Get the cluster's team reference
	clusterTeam, found, _ := unstructured.NestedString(cluster.Object, "spec", "teamRef", "name")

	// When user has team context selected, only allow access to clusters in that team
	if user.SelectedTeam != "" {
		if !found || clusterTeam == "" {
			return fmt.Errorf("forbidden: cluster is not associated with any team")
		}
		if clusterTeam != user.SelectedTeam {
			return fmt.Errorf("forbidden: cluster belongs to team '%s', not '%s'", clusterTeam, user.SelectedTeam)
		}
		return nil
	}

	// No team context - use legacy behavior
	// Admins can access all clusters
	if user.IsAdmin() {
		return nil
	}

	// If cluster has no teamRef, it's a platform-level cluster
	// Only admins should see these (already checked above)
	if !found || clusterTeam == "" {
		return fmt.Errorf("forbidden: cluster is not associated with any team")
	}

	// Check if user is a member of the cluster's team
	if !user.HasTeamMembership(clusterTeam) {
		return fmt.Errorf("forbidden: you don't have access to team '%s'", clusterTeam)
	}

	return nil
}

// checkOperatePermission verifies the user can perform mutations (create/delete/scale).
// Returns nil if allowed, or an error message if denied.
func (h *ClusterHandler) checkOperatePermission(user *auth.UserSession, teamRef string, operation string) error {
	// When team context is selected, enforce team role
	if user.SelectedTeam != "" {
		// Viewer role cannot perform mutations
		if user.SelectedTeamRole == auth.RoleViewer {
			return fmt.Errorf("viewer role cannot %s clusters", operation)
		}
		// Must be operating on selected team's cluster
		if teamRef != "" && teamRef != user.SelectedTeam {
			return fmt.Errorf("cannot %s cluster for team '%s' while scoped to team '%s'", operation, teamRef, user.SelectedTeam)
		}
		return nil
	}

	// No team context - use legacy behavior
	if user.IsAdmin() {
		return nil
	}

	// Non-admin without team context must specify team and have operator role
	if teamRef == "" {
		return fmt.Errorf("teamRef is required for non-admin users")
	}
	if !user.CanOperateTeam(teamRef) {
		return fmt.Errorf("you don't have permission to %s clusters for team '%s'", operation, teamRef)
	}

	return nil
}

// List returns all tenant clusters.
// Query params:
//   - namespace: filter by namespace
//   - team: filter by spec.teamRef.name (for team-scoped views)
func (h *ClusterHandler) List(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := r.URL.Query().Get("namespace")
	team := r.URL.Query().Get("team")

	clusters, err := h.k8sClient.ListTenantClusters(r.Context(), namespace)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list clusters: %v", err))
		return
	}

	response := ClusterListResponse{
		Clusters: make([]map[string]interface{}, 0, len(clusters.Items)),
	}

	for _, cluster := range clusters.Items {
		clusterTeam, _, _ := unstructured.NestedString(cluster.Object, "spec", "teamRef", "name")

		// If team filter is provided, only include clusters belonging to that team
		if team != "" {
			if clusterTeam != team {
				continue
			}
		}

		// Authorization check based on team context
		if user != nil {
			// When team context is selected, only show clusters from that team
			if user.SelectedTeam != "" {
				if clusterTeam != user.SelectedTeam {
					continue
				}
			} else if !user.IsAdmin() {
				// No team context and not admin - filter by team membership
				if clusterTeam == "" {
					continue
				}
				if !user.HasTeamMembership(clusterTeam) {
					continue
				}
			}
		}

		response.Clusters = append(response.Clusters, cluster.Object)
	}

	writeJSON(w, http.StatusOK, response)
}

// CreateClusterRequest represents a cluster creation request.
type CreateClusterRequest struct {
	Name              string `json:"name"`
	Namespace         string `json:"namespace,omitempty"`
	KubernetesVersion string `json:"kubernetesVersion"`
	ProviderConfigRef string `json:"providerConfigRef"`
	WorkerReplicas    int    `json:"workerReplicas"`
	WorkerCPU         int    `json:"workerCPU"`
	WorkerMemory      string `json:"workerMemory"`
	WorkerDiskSize    string `json:"workerDiskSize"`
	LoadBalancerStart string `json:"loadBalancerStart"`
	LoadBalancerEnd   string `json:"loadBalancerEnd"`

	// Team association - when set, cluster belongs to this team
	TeamRef string `json:"teamRef,omitempty"`

	// Harvester-specific
	HarvesterNamespace   string `json:"harvesterNamespace,omitempty"`
	HarvesterNetworkName string `json:"harvesterNetworkName,omitempty"`
	HarvesterImageName   string `json:"harvesterImageName,omitempty"`

	// Nutanix-specific
	NutanixClusterUUID          string `json:"nutanixClusterUUID,omitempty"`
	NutanixSubnetUUID           string `json:"nutanixSubnetUUID,omitempty"`
	NutanixImageUUID            string `json:"nutanixImageUUID,omitempty"`
	NutanixStorageContainerUUID string `json:"nutanixStorageContainerUUID,omitempty"`

	// Proxmox-specific
	ProxmoxNode       string `json:"proxmoxNode,omitempty"`
	ProxmoxStorage    string `json:"proxmoxStorage,omitempty"`
	ProxmoxTemplateID int    `json:"proxmoxTemplateID,omitempty"`

	// OS type (derived from selected image)
	OSType string `json:"osType,omitempty"`

	// Workspaces
	WorkspacesEnabled bool `json:"workspacesEnabled,omitempty"`

	// Control plane resource overrides (optional)
	ControlPlaneResources *ControlPlaneResourcesRequest `json:"controlPlaneResources,omitempty"`
}

// ControlPlaneResourcesRequest defines optional control plane resource overrides.
type ControlPlaneResourcesRequest struct {
	APIServer         *ComponentResourcesRequest `json:"apiServer,omitempty"`
	ControllerManager *ComponentResourcesRequest `json:"controllerManager,omitempty"`
	Scheduler         *ComponentResourcesRequest `json:"scheduler,omitempty"`
}

// ComponentResourcesRequest defines CPU and memory requests/limits for a component.
type ComponentResourcesRequest struct {
	Requests *ResourceQuantitiesRequest `json:"requests,omitempty"`
	Limits   *ResourceQuantitiesRequest `json:"limits,omitempty"`
}

// ResourceQuantitiesRequest defines CPU and memory quantities.
type ResourceQuantitiesRequest struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// Create creates a new tenant cluster.
func (h *ClusterHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())

	var req CreateClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.ProviderConfigRef == "" {
		writeError(w, http.StatusBadRequest, "providerConfigRef is required")
		return
	}

	// Authorization: Check team-scoped permissions for cluster creation
	if user != nil {
		// When team context is set, auto-populate teamRef and enforce role
		if user.SelectedTeam != "" {
			if req.TeamRef == "" {
				req.TeamRef = user.SelectedTeam
			}
		}

		if err := h.checkOperatePermission(user, req.TeamRef, "create"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	if req.Namespace == "" {
		req.Namespace = h.config.TenantNamespace
	}
	if req.KubernetesVersion == "" {
		req.KubernetesVersion = "v1.32.2"
	}
	if req.WorkerReplicas == 0 {
		req.WorkerReplicas = 1
	}
	if req.WorkerCPU == 0 {
		req.WorkerCPU = 4
	}
	if req.WorkerMemory == "" {
		req.WorkerMemory = "8Gi"
	}
	if req.WorkerDiskSize == "" {
		req.WorkerDiskSize = "50Gi"
	}

	spec := map[string]interface{}{
		"kubernetesVersion": req.KubernetesVersion,
		"providerConfigRef": map[string]interface{}{
			"name": req.ProviderConfigRef,
		},
		"workers": map[string]interface{}{
			"replicas": req.WorkerReplicas,
			"machineTemplate": func() map[string]interface{} {
				mt := map[string]interface{}{
					"cpu":      req.WorkerCPU,
					"memory":   req.WorkerMemory,
					"diskSize": req.WorkerDiskSize,
				}
				if req.OSType != "" {
					mt["os"] = map[string]interface{}{
						"type": req.OSType,
					}
				}
				return mt
			}(),
		},
		"networking": map[string]interface{}{
			"loadBalancerPool": map[string]interface{}{
				"start": req.LoadBalancerStart,
				"end":   req.LoadBalancerEnd,
			},
		},
	}

	// Add teamRef if provided - this associates the cluster with a team
	if req.TeamRef != "" {
		spec["teamRef"] = map[string]interface{}{
			"name": req.TeamRef,
		}
	}

	if req.WorkspacesEnabled {
		spec["workspaces"] = map[string]interface{}{
			"enabled":      true,
			"defaultImage": "ghcr.io/butlerdotdev/workspace-base:latest",
		}
	}

	if req.HarvesterNetworkName != "" {
		infraOverride := map[string]interface{}{
			"networkName": req.HarvesterNetworkName,
		}
		if req.HarvesterNamespace != "" {
			infraOverride["namespace"] = req.HarvesterNamespace
		}
		if req.HarvesterImageName != "" {
			infraOverride["imageName"] = req.HarvesterImageName
		}
		spec["infrastructureOverride"] = map[string]interface{}{
			"harvester": infraOverride,
		}
	}

	if req.NutanixClusterUUID != "" || req.NutanixSubnetUUID != "" {
		infraOverride := map[string]interface{}{}
		if req.NutanixClusterUUID != "" {
			infraOverride["clusterUUID"] = req.NutanixClusterUUID
		}
		if req.NutanixSubnetUUID != "" {
			infraOverride["subnetUUID"] = req.NutanixSubnetUUID
		}
		if req.NutanixImageUUID != "" {
			infraOverride["imageUUID"] = req.NutanixImageUUID
		}
		if req.NutanixStorageContainerUUID != "" {
			infraOverride["storageContainerUUID"] = req.NutanixStorageContainerUUID
		}
		spec["infrastructureOverride"] = map[string]interface{}{
			"nutanix": infraOverride,
		}
	}

	if req.ProxmoxNode != "" || req.ProxmoxStorage != "" {
		infraOverride := map[string]interface{}{}
		if req.ProxmoxNode != "" {
			infraOverride["node"] = req.ProxmoxNode
		}
		if req.ProxmoxStorage != "" {
			infraOverride["storage"] = req.ProxmoxStorage
		}
		if req.ProxmoxTemplateID > 0 {
			infraOverride["templateID"] = req.ProxmoxTemplateID
		}
		spec["infrastructureOverride"] = map[string]interface{}{
			"proxmox": infraOverride,
		}
	}

	// Add control plane resources if provided
	if req.ControlPlaneResources != nil {
		cpResources := map[string]interface{}{}
		if req.ControlPlaneResources.APIServer != nil {
			cpResources["apiServer"] = buildComponentResourcesMap(req.ControlPlaneResources.APIServer)
		}
		if req.ControlPlaneResources.ControllerManager != nil {
			cpResources["controllerManager"] = buildComponentResourcesMap(req.ControlPlaneResources.ControllerManager)
		}
		if req.ControlPlaneResources.Scheduler != nil {
			cpResources["scheduler"] = buildComponentResourcesMap(req.ControlPlaneResources.Scheduler)
		}
		if len(cpResources) > 0 {
			controlPlane, ok := spec["controlPlane"].(map[string]interface{})
			if !ok {
				controlPlane = map[string]interface{}{}
			}
			controlPlane["resources"] = cpResources
			spec["controlPlane"] = controlPlane
		}
	}

	cluster := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "TenantCluster",
			"metadata": map[string]interface{}{
				"name":      req.Name,
				"namespace": req.Namespace,
			},
			"spec": spec,
		},
	}

	created, err := h.k8sClient.Dynamic().Resource(k8s.TenantClusterGVR).Namespace(req.Namespace).Create(
		r.Context(), cluster, metav1.CreateOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create cluster: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, created.Object)
}

// Get returns a specific tenant cluster.
func (h *ClusterHandler) Get(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	cluster, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	// SECURITY: Check team access before returning cluster data
	if user != nil {
		if err := h.checkClusterAccess(user, cluster); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	writeJSON(w, http.StatusOK, cluster.Object)
}

// Delete deletes a tenant cluster.
func (h *ClusterHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	// Get cluster first to check access
	cluster, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	// SECURITY: Check team access and operate permission
	if user != nil {
		if err := h.checkClusterAccess(user, cluster); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}

		teamRef, _, _ := unstructured.NestedString(cluster.Object, "spec", "teamRef", "name")
		if err := h.checkOperatePermission(user, teamRef, "delete"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	if err := h.k8sClient.DeleteTenantCluster(r.Context(), namespace, name); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete cluster: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "cluster deletion initiated"})
}

// ScaleRequest represents a scale request.
type ScaleRequest struct {
	Replicas int `json:"replicas"`
}

// Scale scales cluster workers.
func (h *ClusterHandler) Scale(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	// Get cluster first to check access
	cluster, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	// SECURITY: Check team access and operate permission
	if user != nil {
		if err := h.checkClusterAccess(user, cluster); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}

		teamRef, _, _ := unstructured.NestedString(cluster.Object, "spec", "teamRef", "name")
		if err := h.checkOperatePermission(user, teamRef, "scale"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	var req ScaleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Replicas < 1 || req.Replicas > 100 {
		writeError(w, http.StatusBadRequest, "replicas must be between 1 and 100")
		return
	}

	patch := []byte(fmt.Sprintf(`{"spec":{"workers":{"replicas":%d}}}`, req.Replicas))

	patched, err := h.k8sClient.PatchTenantCluster(r.Context(), namespace, name, patch)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to scale cluster: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, patched.Object)
}

// UpdateRequest represents a cluster spec edit request.
// Only non-nil fields are applied to the existing spec.
type UpdateRequest struct {
	// ResourceVersion is required for optimistic concurrency.
	ResourceVersion string `json:"resourceVersion"`

	// KubernetesVersion changes the target K8s version. No downgrades.
	KubernetesVersion *string `json:"kubernetesVersion,omitempty"`

	// ControlPlane edits. Only provided fields are applied.
	ControlPlane *UpdateControlPlane `json:"controlPlane,omitempty"`

	// Workers edits. Only provided fields are applied.
	Workers *UpdateWorkers `json:"workers,omitempty"`

	// InfrastructureOverride edits. Admin-only.
	InfrastructureOverride map[string]interface{} `json:"infrastructureOverride,omitempty"`

	// AcknowledgeDowngrade must be true when reducing CP replicas from 3 to 1.
	AcknowledgeDowngrade bool `json:"acknowledgeDowngrade,omitempty"`
}

// UpdateControlPlane holds mutable control plane fields.
type UpdateControlPlane struct {
	Replicas  *int32                 `json:"replicas,omitempty"`
	Resources map[string]interface{} `json:"resources,omitempty"`
}

// UpdateWorkers holds mutable worker fields.
type UpdateWorkers struct {
	Replicas        *int32                 `json:"replicas,omitempty"`
	MachineTemplate map[string]interface{} `json:"machineTemplate,omitempty"`
}

// FieldError is a structured validation error for a specific field.
type FieldError struct {
	Field   string `json:"field"`
	Reason  string `json:"reason"`
	Current string `json:"current,omitempty"`
}

// Update applies spec edits to a TenantCluster with optimistic concurrency.
// PUT /api/clusters/{namespace}/{name}
func (h *ClusterHandler) Update(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	cluster, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	if user != nil {
		if err := h.checkClusterAccess(user, cluster); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		teamRef, _, _ := unstructured.NestedString(cluster.Object, "spec", "teamRef", "name")
		if err := h.checkOperatePermission(user, teamRef, "edit"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	var req UpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.ResourceVersion == "" {
		writeError(w, http.StatusBadRequest, "resourceVersion is required for optimistic concurrency")
		return
	}

	// Reject edits on clusters that aren't in a stable phase
	phase, _, _ := unstructured.NestedString(cluster.Object, "status", "phase")
	stablePhases := map[string]bool{"Ready": true, "Pending": true, "": true}
	if !stablePhases[phase] {
		writeError(w, http.StatusConflict, fmt.Sprintf("cluster is in %s phase; wait for it to stabilize", phase))
		return
	}

	// InfrastructureOverride is platform-admin-only
	if len(req.InfrastructureOverride) > 0 {
		if user == nil || !user.IsPlatformAdmin {
			writeError(w, http.StatusForbidden, "infrastructure overrides require platform admin privileges")
			return
		}
	}

	// No-op guard: if no fields are set, return the current state without writing
	if req.KubernetesVersion == nil && req.ControlPlane == nil && req.Workers == nil && len(req.InfrastructureOverride) == 0 {
		writeJSON(w, http.StatusOK, cluster.Object)
		return
	}

	// Validate and apply each field
	if errs := h.validateUpdateRequest(cluster, &req); len(errs) > 0 {
		writeJSON(w, http.StatusBadRequest, map[string]interface{}{"errors": errs})
		return
	}

	h.applyUpdateRequest(cluster, &req)

	// Set resourceVersion for optimistic concurrency
	cluster.SetResourceVersion(req.ResourceVersion)

	updated, err := h.k8sClient.UpdateTenantCluster(r.Context(), cluster)
	if err != nil {
		if apierrors.IsConflict(err) {
			// Re-fetch current state so the client can see what changed
			current, fetchErr := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
			if fetchErr != nil {
				writeError(w, http.StatusConflict, "cluster was modified by another user")
				return
			}
			writeJSON(w, http.StatusConflict, map[string]interface{}{
				"error":   "cluster was modified by another user",
				"current": current.Object,
			})
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update cluster: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, updated.Object)
}

// validateUpdateRequest checks all fields in the update request for validity.
func (h *ClusterHandler) validateUpdateRequest(cluster *unstructured.Unstructured, req *UpdateRequest) []FieldError {
	var errs []FieldError

	if req.KubernetesVersion != nil {
		current, _, _ := unstructured.NestedString(cluster.Object, "spec", "kubernetesVersion")
		if err := validateVersionUpgrade(current, *req.KubernetesVersion); err != nil {
			errs = append(errs, FieldError{
				Field:   "spec.kubernetesVersion",
				Reason:  err.Error(),
				Current: current,
			})
		}
	}

	if req.ControlPlane != nil && req.ControlPlane.Replicas != nil {
		replicas := *req.ControlPlane.Replicas
		if replicas != 1 && replicas != 3 {
			errs = append(errs, FieldError{
				Field:  "spec.controlPlane.replicas",
				Reason: "must be 1 or 3 (odd numbers required for etcd quorum)",
			})
		}
		if replicas == 1 {
			currentReplicas, _, _ := unstructured.NestedInt64(cluster.Object, "spec", "controlPlane", "replicas")
			if currentReplicas == 3 && !req.AcknowledgeDowngrade {
				errs = append(errs, FieldError{
					Field:   "spec.controlPlane.replicas",
					Reason:  "reducing from 3 to 1 requires acknowledgeDowngrade: true",
					Current: "3",
				})
			}
		}
	}

	if req.Workers != nil {
		if req.Workers.Replicas != nil {
			replicas := *req.Workers.Replicas
			if replicas < 1 || replicas > 100 {
				errs = append(errs, FieldError{
					Field:  "spec.workers.replicas",
					Reason: "must be between 1 and 100",
				})
			}
		}
		if mt, ok := req.Workers.MachineTemplate["cpu"]; ok {
			if cpu, ok := toInt64(mt); ok && cpu < 1 {
				errs = append(errs, FieldError{
					Field:  "spec.workers.machineTemplate.cpu",
					Reason: "must be at least 1",
				})
			}
		}
	}

	return errs
}

// applyUpdateRequest merges the request fields into the cluster object.
func (h *ClusterHandler) applyUpdateRequest(cluster *unstructured.Unstructured, req *UpdateRequest) {
	if req.KubernetesVersion != nil {
		_ = unstructured.SetNestedField(cluster.Object, *req.KubernetesVersion, "spec", "kubernetesVersion")
	}

	if req.ControlPlane != nil {
		if req.ControlPlane.Replicas != nil {
			_ = unstructured.SetNestedField(cluster.Object, int64(*req.ControlPlane.Replicas), "spec", "controlPlane", "replicas")
		}
		if req.ControlPlane.Resources != nil {
			_ = unstructured.SetNestedField(cluster.Object, req.ControlPlane.Resources, "spec", "controlPlane", "resources")
		}
	}

	if req.Workers != nil {
		if req.Workers.Replicas != nil {
			_ = unstructured.SetNestedField(cluster.Object, int64(*req.Workers.Replicas), "spec", "workers", "replicas")
		}
		if req.Workers.MachineTemplate != nil {
			existing, _, _ := unstructured.NestedMap(cluster.Object, "spec", "workers", "machineTemplate")
			if existing == nil {
				existing = make(map[string]interface{})
			}
			for k, v := range req.Workers.MachineTemplate {
				existing[k] = v
			}
			_ = unstructured.SetNestedField(cluster.Object, existing, "spec", "workers", "machineTemplate")
		}
	}

	if len(req.InfrastructureOverride) > 0 {
		existing, _, _ := unstructured.NestedMap(cluster.Object, "spec", "infrastructureOverride")
		if existing == nil {
			existing = make(map[string]interface{})
		}
		for k, v := range req.InfrastructureOverride {
			existing[k] = v
		}
		_ = unstructured.SetNestedField(cluster.Object, existing, "spec", "infrastructureOverride")
	}
}

// validateVersionUpgrade ensures the target version is not a downgrade.
func validateVersionUpgrade(current, target string) error {
	if current == "" || target == "" {
		return nil
	}
	currentParts := parseVersion(current)
	targetParts := parseVersion(target)
	if currentParts == nil || targetParts == nil {
		return nil // let the CRD validation handle format issues
	}
	if targetParts[0] < currentParts[0] ||
		(targetParts[0] == currentParts[0] && targetParts[1] < currentParts[1]) ||
		(targetParts[0] == currentParts[0] && targetParts[1] == currentParts[1] && targetParts[2] < currentParts[2]) {
		return fmt.Errorf("downgrade from %s to %s is not permitted", current, target)
	}
	return nil
}

// parseVersion extracts major, minor, patch from a "vX.Y.Z" string.
func parseVersion(v string) []int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	if len(parts) != 3 {
		return nil
	}
	var result []int
	for _, p := range parts {
		n := 0
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil
			}
			n = n*10 + int(c-'0')
		}
		result = append(result, n)
	}
	return result
}

// toInt64 attempts to convert a JSON number to int64.
// JSON numbers decode as float64 by default.
func toInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	}
	return 0, false
}

// ToggleWorkspaces enables or disables workspaces on a cluster.
func (h *ClusterHandler) ToggleWorkspaces(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	cluster, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	if user != nil {
		if err := h.checkClusterAccess(user, cluster); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		teamRef, _, _ := unstructured.NestedString(cluster.Object, "spec", "teamRef", "name")
		if err := h.checkOperatePermission(user, teamRef, "update"); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	var patch []byte
	if req.Enabled {
		patch = []byte(`{"spec":{"workspaces":{"enabled":true,"defaultImage":"ghcr.io/butlerdotdev/workspace-base:latest"}}}`)
	} else {
		patch = []byte(`{"spec":{"workspaces":{"enabled":false}}}`)
	}

	patched, err := h.k8sClient.PatchTenantCluster(r.Context(), namespace, name, patch)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update workspaces: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, patched.Object)
}

// GetKubeconfig returns the kubeconfig for a cluster.
func (h *ClusterHandler) GetKubeconfig(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	// Get cluster first to check access
	cluster, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	// SECURITY: Check team access before returning kubeconfig
	if user != nil {
		if err := h.checkClusterAccess(user, cluster); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	kubeconfig, err := h.k8sClient.GetClusterKubeconfig(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get kubeconfig: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"kubeconfig": kubeconfig})
}

// GetNodes returns nodes for a tenant cluster.
func (h *ClusterHandler) GetNodes(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	tc, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	// SECURITY: Check team access
	if user != nil {
		if err := h.checkClusterAccess(user, tc); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	tenantNS, _, _ := unstructured.NestedString(tc.Object, "status", "tenantNamespace")
	if tenantNS == "" {
		writeError(w, http.StatusNotFound, "tenant namespace not found")
		return
	}

	kubeconfig, err := h.k8sClient.GetClusterKubeconfig(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get kubeconfig: %v", err))
		return
	}

	tenantClient, err := k8s.NewClientFromKubeconfig(kubeconfig)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create tenant client: %v", err))
		return
	}

	nodes, err := tenantClient.Clientset().CoreV1().Nodes().List(r.Context(), metav1.ListOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list nodes: %v", err))
		return
	}

	nodeList := make([]map[string]interface{}, 0, len(nodes.Items))
	for _, node := range nodes.Items {
		nodeList = append(nodeList, buildNodeInfo(node))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"nodes": nodeList})
}

// GetAddons returns installed addons for a cluster.
func (h *ClusterHandler) GetAddons(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	tc, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	// SECURITY: Check team access
	if user != nil {
		if err := h.checkClusterAccess(user, tc); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	observedState, _, _ := unstructured.NestedMap(tc.Object, "status", "observedState")
	addonsRaw, _, _ := unstructured.NestedSlice(observedState, "addons")

	addons := make([]map[string]interface{}, 0, len(addonsRaw))
	for _, a := range addonsRaw {
		addonMap, ok := a.(map[string]interface{})
		if !ok {
			continue
		}

		addonName, _ := addonMap["name"].(string)
		status, _ := addonMap["status"].(string)
		version, _ := addonMap["version"].(string)

		addons = append(addons, map[string]interface{}{
			"name":    addonName,
			"status":  MapAddonStatus(status),
			"version": version,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"addons": addons})
}

// GetEvents returns events for a cluster.
func (h *ClusterHandler) GetEvents(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	tc, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	// SECURITY: Check team access
	if user != nil {
		if err := h.checkClusterAccess(user, tc); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	tenantNS, _, _ := unstructured.NestedString(tc.Object, "status", "tenantNamespace")
	if tenantNS == "" {
		tenantNS = namespace
	}

	events, err := h.k8sClient.Clientset().CoreV1().Events(tenantNS).List(r.Context(), metav1.ListOptions{
		Limit: 50,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list events: %v", err))
		return
	}

	eventList := make([]map[string]interface{}, 0, len(events.Items))
	for _, event := range events.Items {
		eventList = append(eventList, map[string]interface{}{
			"type":           event.Type,
			"reason":         event.Reason,
			"message":        event.Message,
			"source":         event.Source.Component,
			"firstTimestamp": event.FirstTimestamp.Time.Format(time.RFC3339),
			"lastTimestamp":  event.LastTimestamp.Time.Format(time.RFC3339),
			"count":          event.Count,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"events": eventList})
}

// GetManagement returns management cluster info.
func (h *ClusterHandler) GetManagement(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	serverVersion, err := h.k8sClient.Clientset().Discovery().ServerVersion()
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get server version: %v", err))
		return
	}

	nodes, err := h.k8sClient.Clientset().CoreV1().Nodes().List(ctx, metav1.ListOptions{})
	nodeCount := 0
	nodesReady := 0
	if err == nil {
		nodeCount = len(nodes.Items)
		for _, node := range nodes.Items {
			for _, cond := range node.Status.Conditions {
				if cond.Type == corev1.NodeReady && cond.Status == corev1.ConditionTrue {
					nodesReady++
					break
				}
			}
		}
	}

	systemNamespaces := []string{"butler-system", "kamaji-system", "capi-system", "cert-manager", "kube-system"}
	namespaceStats := make([]map[string]interface{}, 0)

	for _, ns := range systemNamespaces {
		pods, err := h.k8sClient.Clientset().CoreV1().Pods(ns).List(ctx, metav1.ListOptions{})
		if err != nil {
			continue
		}

		running := 0
		total := len(pods.Items)
		for _, pod := range pods.Items {
			if pod.Status.Phase == corev1.PodRunning {
				running++
			}
		}

		namespaceStats = append(namespaceStats, map[string]interface{}{
			"namespace": ns,
			"running":   running,
			"total":     total,
		})
	}

	tcList, _ := h.k8sClient.ListTenantClusters(ctx, "")
	tcCount := 0
	tenantNamespaces := make([]map[string]interface{}, 0)

	if tcList != nil {
		tcCount = len(tcList.Items)
		for _, tc := range tcList.Items {
			tcName, _, _ := unstructured.NestedString(tc.Object, "metadata", "name")
			tcNamespace, _, _ := unstructured.NestedString(tc.Object, "metadata", "namespace")
			tenantNS, _, _ := unstructured.NestedString(tc.Object, "status", "tenantNamespace")
			phase, _, _ := unstructured.NestedString(tc.Object, "status", "phase")

			tenantNamespaces = append(tenantNamespaces, map[string]interface{}{
				"name":            tcName,
				"namespace":       tcNamespace,
				"tenantNamespace": tenantNS,
				"phase":           phase,
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":              "management",
		"kubernetesVersion": serverVersion.GitVersion,
		"phase":             "Ready",
		"nodes": map[string]interface{}{
			"total": nodeCount,
			"ready": nodesReady,
		},
		"systemNamespaces": namespaceStats,
		"tenantClusters":   tcCount,
		"tenantNamespaces": tenantNamespaces,
	})
}

// GetManagementNodes returns nodes in the management cluster.
func (h *ClusterHandler) GetManagementNodes(w http.ResponseWriter, r *http.Request) {
	nodes, err := h.k8sClient.Clientset().CoreV1().Nodes().List(r.Context(), metav1.ListOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list nodes: %v", err))
		return
	}

	nodeList := make([]map[string]interface{}, 0, len(nodes.Items))
	for _, node := range nodes.Items {
		nodeList = append(nodeList, buildNodeInfo(node))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"nodes": nodeList})
}

// GetManagementPods returns pods in a system namespace.
func (h *ClusterHandler) GetManagementPods(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")

	pods, err := h.k8sClient.Clientset().CoreV1().Pods(namespace).List(r.Context(), metav1.ListOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list pods: %v", err))
		return
	}

	podList := make([]map[string]interface{}, 0, len(pods.Items))
	for _, pod := range pods.Items {
		ready := 0
		total := len(pod.Spec.Containers)
		for _, cs := range pod.Status.ContainerStatuses {
			if cs.Ready {
				ready++
			}
		}

		podList = append(podList, map[string]interface{}{
			"name":      pod.Name,
			"namespace": pod.Namespace,
			"status":    string(pod.Status.Phase),
			"ready":     fmt.Sprintf("%d/%d", ready, total),
			"restarts":  getRestartCount(pod),
			"age":       time.Since(pod.CreationTimestamp.Time).Round(time.Second).String(),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"pods": podList})
}

func buildNodeInfo(node corev1.Node) map[string]interface{} {
	status := "Unknown"
	for _, cond := range node.Status.Conditions {
		if cond.Type == corev1.NodeReady {
			if cond.Status == corev1.ConditionTrue {
				status = "Ready"
			} else {
				status = "NotReady"
			}
			break
		}
	}

	roles := []string{}
	for label := range node.Labels {
		if strings.HasPrefix(label, "node-role.kubernetes.io/") {
			role := strings.TrimPrefix(label, "node-role.kubernetes.io/")
			if role != "" {
				roles = append(roles, role)
			}
		}
	}
	if len(roles) == 0 {
		roles = append(roles, "worker")
	}

	return map[string]interface{}{
		"name":             node.Name,
		"status":           status,
		"roles":            roles,
		"version":          node.Status.NodeInfo.KubeletVersion,
		"internalIP":       getNodeInternalIP(node),
		"os":               node.Status.NodeInfo.OSImage,
		"containerRuntime": node.Status.NodeInfo.ContainerRuntimeVersion,
		"cpu":              node.Status.Capacity.Cpu().String(),
		"memory":           node.Status.Capacity.Memory().String(),
		"age":              time.Since(node.CreationTimestamp.Time).Round(time.Second).String(),
	}
}

func getNodeInternalIP(node corev1.Node) string {
	for _, addr := range node.Status.Addresses {
		if addr.Type == corev1.NodeInternalIP {
			return addr.Address
		}
	}
	return ""
}

func getRestartCount(pod corev1.Pod) int32 {
	var restarts int32
	for _, cs := range pod.Status.ContainerStatuses {
		restarts += cs.RestartCount
	}
	return restarts
}

// buildComponentResourcesMap converts a ComponentResourcesRequest to a nested map for the CRD.
func buildComponentResourcesMap(cr *ComponentResourcesRequest) map[string]interface{} {
	result := map[string]interface{}{}
	if cr.Requests != nil {
		reqMap := map[string]interface{}{}
		if cr.Requests.CPU != "" {
			reqMap["cpu"] = cr.Requests.CPU
		}
		if cr.Requests.Memory != "" {
			reqMap["memory"] = cr.Requests.Memory
		}
		if len(reqMap) > 0 {
			result["requests"] = reqMap
		}
	}
	if cr.Limits != nil {
		limMap := map[string]interface{}{}
		if cr.Limits.CPU != "" {
			limMap["cpu"] = cr.Limits.CPU
		}
		if cr.Limits.Memory != "" {
			limMap["memory"] = cr.Limits.Memory
		}
		if len(limMap) > 0 {
			result["limits"] = limMap
		}
	}
	return result
}

// ExportYAML returns a TenantCluster as YAML for export.
func (h *ClusterHandler) ExportYAML(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	cluster, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	if user != nil {
		if err := h.checkClusterAccess(user, cluster); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	// Deep copy to avoid mutating the cached object.
	export := cluster.DeepCopy()
	obj := export.Object

	// Strip server-side fields for a clean export.
	delete(obj, "status")
	if meta, ok := obj["metadata"].(map[string]interface{}); ok {
		delete(meta, "resourceVersion")
		delete(meta, "uid")
		delete(meta, "creationTimestamp")
		delete(meta, "generation")
		delete(meta, "managedFields")
		delete(meta, "selfLink")
		delete(meta, "ownerReferences")
	}

	yamlBytes, err := yaml.Marshal(obj)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to marshal YAML: %v", err))
		return
	}

	// Sanitize filename to prevent header injection.
	safeName := sanitizeFilename(name)
	w.Header().Set("Content-Type", "application/x-yaml")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.yaml"`, safeName))
	w.WriteHeader(http.StatusOK)
	w.Write(yamlBytes)
}

// ListMachineRequests returns MachineRequests for a cluster.
func (h *ClusterHandler) ListMachineRequests(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	cluster, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	if user != nil {
		if err := h.checkClusterAccess(user, cluster); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	items := make([]map[string]interface{}, 0)
	machines, err := h.k8sClient.ListMachineRequests(r.Context(), namespace, name)
	if err != nil {
		slog.Debug("failed to list machine requests (CRD may not exist)", "cluster", name, "error", err)
	} else {
		for _, m := range machines.Items {
			items = append(items, m.Object)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"machineRequests": items})
}

// ListLoadBalancerRequests returns LoadBalancerRequests for a cluster.
func (h *ClusterHandler) ListLoadBalancerRequests(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	cluster, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	if user != nil {
		if err := h.checkClusterAccess(user, cluster); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	items := make([]map[string]interface{}, 0)
	lbs, err := h.k8sClient.ListLoadBalancerRequests(r.Context(), namespace, name)
	if err != nil {
		slog.Debug("failed to list load balancer requests (CRD may not exist)", "cluster", name, "error", err)
	} else {
		for _, lb := range lbs.Items {
			items = append(items, lb.Object)
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"loadBalancerRequests": items})
}

// sanitizeFilename strips characters that could cause header injection.
var safeFilenameRe = regexp.MustCompile(`[^a-zA-Z0-9._-]`)

func sanitizeFilename(name string) string {
	return safeFilenameRe.ReplaceAllString(name, "_")
}
