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
	"net/http"
	"strings"
	"time"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/go-chi/chi/v5"
	corev1 "k8s.io/api/core/v1"
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
