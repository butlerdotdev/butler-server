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
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
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
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/remotecommand"
)

var (
	WorkspaceGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "workspaces",
	}

	WorkspaceTemplateGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "workspacetemplates",
	}

	UserGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "users",
	}
)

// WorkspaceHandler handles workspace-related endpoints.
type WorkspaceHandler struct {
	k8sClient *k8s.Client
	config    *config.Config
	logger    *slog.Logger
}

// NewWorkspaceHandler creates a new workspace handler.
func NewWorkspaceHandler(k8sClient *k8s.Client, cfg *config.Config, logger *slog.Logger) *WorkspaceHandler {
	return &WorkspaceHandler{
		k8sClient: k8sClient,
		config:    cfg,
		logger:    logger,
	}
}

// ---- Request/Response Types ----

// CreateWorkspaceRequest is the request body for creating a workspace.
type CreateWorkspaceRequest struct {
	Name          string                     `json:"name"`
	Image         string                     `json:"image,omitempty"`
	Repository    *WorkspaceRepositoryReq    `json:"repository,omitempty"`
	Repositories  []WorkspaceRepositoryReq   `json:"repositories,omitempty"`
	EnvFrom       *WorkspaceEnvSourceReq     `json:"envFrom,omitempty"`
	Dotfiles      *DotfilesReq               `json:"dotfiles,omitempty"`
	Resources     *WorkspaceResourcesReq     `json:"resources,omitempty"`
	StorageSize   string                     `json:"storageSize,omitempty"`
	IdleTimeout   string                     `json:"idleTimeout,omitempty"`
	AutoStopAfter string                     `json:"autoStopAfter,omitempty"`
	SSHPublicKeys []string                   `json:"sshPublicKeys,omitempty"`
	EditorConfig  *EditorConfigReq           `json:"editorConfig,omitempty"`
}

type EditorConfigReq struct {
	NeovimConfigRepo string `json:"neovimConfigRepo,omitempty"`
	NeovimInitLua    string `json:"neovimInitLua,omitempty"`
}

type WorkspaceRepositoryReq struct {
	URL       string `json:"url"`
	Name      string `json:"name,omitempty"`
	Branch    string `json:"branch,omitempty"`
	SecretRef string `json:"secretRef,omitempty"`
}

type WorkspaceEnvSourceReq struct {
	Kind      string `json:"kind,omitempty"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Container string `json:"container,omitempty"`
}

type DotfilesReq struct {
	URL            string `json:"url"`
	InstallCommand string `json:"installCommand,omitempty"`
}

type WorkspaceResourcesReq struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// MirrordConfigRequest is the request for generating mirrord config.
type MirrordConfigRequest struct {
	TargetService   string `json:"targetService"`
	TargetNamespace string `json:"targetNamespace"`
}

// ---- Workspace CRUD ----

// List returns all workspaces for a cluster.
func (h *WorkspaceHandler) List(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")

	workspaces, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).List(r.Context(), metav1.ListOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list workspaces: %v", err))
		return
	}

	// Filter by cluster and owner
	var filtered []map[string]interface{}
	for _, ws := range workspaces.Items {
		wsCluster, _, _ := unstructured.NestedString(ws.Object, "spec", "clusterRef", "name")
		if wsCluster != clusterName {
			continue
		}

		// Non-admins can only see their own workspaces unless they're team admins
		if user != nil && !user.IsAdmin() && user.SelectedTeamRole != "admin" {
			wsOwner, _, _ := unstructured.NestedString(ws.Object, "spec", "owner")
			if wsOwner != user.Email {
				continue
			}
		}

		filtered = append(filtered, ws.Object)
	}

	if filtered == nil {
		filtered = []map[string]interface{}{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"workspaces": filtered})
}

// Create creates a new workspace on a cluster.
func (h *WorkspaceHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")

	// Check operate permission
	if user.SelectedTeamRole == "viewer" {
		writeError(w, http.StatusForbidden, "viewer role cannot create workspaces")
		return
	}

	var req CreateWorkspaceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}

	// Verify cluster exists and has workspaces enabled
	cluster, err := h.k8sClient.GetTenantCluster(r.Context(), namespace, clusterName)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster %s/%s not found", namespace, clusterName))
		return
	}

	wsEnabled, _, _ := unstructured.NestedBool(cluster.Object, "spec", "workspaces", "enabled")
	if !wsEnabled {
		writeError(w, http.StatusBadRequest, "workspaces not enabled on this cluster")
		return
	}

	// Resolve SSH keys: request → User CRD → 400
	sshKeys := req.SSHPublicKeys
	if len(sshKeys) == 0 {
		userKeys, err := h.resolveUserSSHKeys(r.Context(), user.Email)
		if err != nil {
			h.logger.Error("failed to resolve SSH keys", "error", err)
			writeError(w, http.StatusInternalServerError, "failed to resolve SSH keys")
			return
		}
		sshKeys = userKeys
	}
	if len(sshKeys) == 0 {
		writeError(w, http.StatusBadRequest, "No SSH keys configured. Add keys in Settings or provide them in the request.")
		return
	}

	// Default image from cluster config
	image := req.Image
	if image == "" {
		defaultImage, _, _ := unstructured.NestedString(cluster.Object, "spec", "workspaces", "defaultImage")
		if defaultImage != "" {
			image = defaultImage
		} else {
			image = "ubuntu:24.04"
		}
	}

	// Build workspace spec
	spec := map[string]interface{}{
		"clusterRef":    map[string]interface{}{"name": clusterName},
		"owner":         user.Email,
		"image":         image,
		"sshPublicKeys": toInterfaceSlice(sshKeys),
	}

	if len(req.Repositories) > 0 {
		// Multi-repo: use the repositories array
		var repos []interface{}
		for _, r := range req.Repositories {
			repo := map[string]interface{}{"url": r.URL}
			if r.Name != "" {
				repo["name"] = r.Name
			}
			if r.Branch != "" {
				repo["branch"] = r.Branch
			}
			if r.SecretRef != "" {
				repo["secretRef"] = map[string]interface{}{"name": r.SecretRef}
			}
			repos = append(repos, repo)
		}
		spec["repositories"] = repos
	} else if req.Repository != nil {
		// Single repo: legacy field
		repo := map[string]interface{}{"url": req.Repository.URL}
		if req.Repository.Name != "" {
			repo["name"] = req.Repository.Name
		}
		if req.Repository.Branch != "" {
			repo["branch"] = req.Repository.Branch
		}
		if req.Repository.SecretRef != "" {
			repo["secretRef"] = map[string]interface{}{"name": req.Repository.SecretRef}
		}
		spec["repository"] = repo
	}

	if req.EnvFrom != nil {
		envFrom := map[string]interface{}{"name": req.EnvFrom.Name}
		if req.EnvFrom.Kind != "" {
			envFrom["kind"] = req.EnvFrom.Kind
		}
		if req.EnvFrom.Namespace != "" {
			envFrom["namespace"] = req.EnvFrom.Namespace
		}
		if req.EnvFrom.Container != "" {
			envFrom["container"] = req.EnvFrom.Container
		}
		spec["envFrom"] = envFrom
	}

	if req.Dotfiles != nil {
		dotfiles := map[string]interface{}{"url": req.Dotfiles.URL}
		if req.Dotfiles.InstallCommand != "" {
			dotfiles["installCommand"] = req.Dotfiles.InstallCommand
		}
		spec["dotfiles"] = dotfiles
	}

	if req.Resources != nil {
		resources := map[string]interface{}{}
		if req.Resources.CPU != "" {
			resources["cpu"] = req.Resources.CPU
		}
		if req.Resources.Memory != "" {
			resources["memory"] = req.Resources.Memory
		}
		spec["resources"] = resources
	}

	if req.StorageSize != "" {
		spec["storageSize"] = req.StorageSize
	}
	if req.IdleTimeout != "" {
		spec["idleTimeout"] = req.IdleTimeout
	}
	if req.AutoStopAfter != "" {
		spec["autoStopAfter"] = req.AutoStopAfter
	}

	if req.EditorConfig != nil {
		ec := map[string]interface{}{}
		if req.EditorConfig.NeovimConfigRepo != "" {
			ec["neovimConfigRepo"] = req.EditorConfig.NeovimConfigRepo
		}
		if req.EditorConfig.NeovimInitLua != "" {
			ec["neovimInitLua"] = req.EditorConfig.NeovimInitLua
		}
		if len(ec) > 0 {
			spec["editorConfig"] = ec
		}
	}

	workspace := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "Workspace",
			"metadata": map[string]interface{}{
				"name":      req.Name,
				"namespace": namespace,
				"labels": map[string]interface{}{
					"butler.butlerlabs.dev/tenant":          clusterName,
					"butler.butlerlabs.dev/workspace-owner": sanitizeLabelValue(user.Email),
				},
				"annotations": map[string]interface{}{
					"butler.butlerlabs.dev/connect": "true",
				},
			},
			"spec": spec,
		},
	}

	result, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Create(r.Context(), workspace, metav1.CreateOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create workspace: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, result.Object)
}

// Get returns a specific workspace.
func (h *WorkspaceHandler) Get(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	wsName := chi.URLParam(r, "workspace")

	ws, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Get(r.Context(), wsName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}

	if err := h.checkWorkspaceAccess(user, ws); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, ws.Object)
}

// Delete deletes a workspace.
func (h *WorkspaceHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	wsName := chi.URLParam(r, "workspace")

	ws, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Get(r.Context(), wsName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}

	if err := h.checkWorkspaceAccess(user, ws); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	if err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Delete(r.Context(), wsName, metav1.DeleteOptions{}); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete workspace: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Connect sets the connect annotation to trigger SSH service creation.
func (h *WorkspaceHandler) Connect(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	wsName := chi.URLParam(r, "workspace")

	ws, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Get(r.Context(), wsName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}

	if err := h.checkWorkspaceAccess(user, ws); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	// Set connect annotation
	annotations := ws.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations["butler.butlerlabs.dev/connect"] = "true"
	ws.SetAnnotations(annotations)

	result, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Update(r.Context(), ws, metav1.UpdateOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to connect workspace: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, result.Object)
}

// Disconnect removes the connect annotation to trigger SSH service deletion.
func (h *WorkspaceHandler) Disconnect(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	wsName := chi.URLParam(r, "workspace")

	ws, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Get(r.Context(), wsName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}

	if err := h.checkWorkspaceAccess(user, ws); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	// Remove connect annotation
	annotations := ws.GetAnnotations()
	if annotations != nil {
		delete(annotations, "butler.butlerlabs.dev/connect")
		delete(annotations, "butler.butlerlabs.dev/connect-time")
		ws.SetAnnotations(annotations)
	}

	result, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Update(r.Context(), ws, metav1.UpdateOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to disconnect workspace: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, result.Object)
}

// StartWorkspace sets the connect annotation on a stopped workspace to resume it.
func (h *WorkspaceHandler) StartWorkspace(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	wsName := chi.URLParam(r, "workspace")

	ws, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Get(r.Context(), wsName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}

	if err := h.checkWorkspaceAccess(user, ws); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	phase, _, _ := unstructured.NestedString(ws.Object, "status", "phase")
	if phase != "Stopped" {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("workspace is %s, not Stopped", phase))
		return
	}

	// Set connect annotation to trigger resume
	annotations := ws.GetAnnotations()
	if annotations == nil {
		annotations = make(map[string]string)
	}
	annotations["butler.butlerlabs.dev/connect"] = "true"
	ws.SetAnnotations(annotations)

	result, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Update(r.Context(), ws, metav1.UpdateOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to start workspace: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, result.Object)
}

// ---- Cluster Services ----

// ListServices lists K8s services in a tenant cluster.
func (h *WorkspaceHandler) ListServices(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")

	tenantClient, err := h.getTenantClient(r.Context(), namespace, clusterName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get tenant client: %v", err))
		return
	}

	servicesList, err := tenantClient.CoreV1().Services("").List(r.Context(), metav1.ListOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list services: %v", err))
		return
	}

	var services []map[string]interface{}
	for _, svc := range servicesList.Items {
		// Skip system namespaces
		if svc.Namespace == "kube-system" || svc.Namespace == "kube-public" || svc.Namespace == "workspaces" {
			continue
		}

		var ports []map[string]interface{}
		for _, p := range svc.Spec.Ports {
			ports = append(ports, map[string]interface{}{
				"port":       p.Port,
				"targetPort": p.TargetPort.IntValue(),
				"protocol":   string(p.Protocol),
				"name":       p.Name,
			})
		}

		services = append(services, map[string]interface{}{
			"name":      svc.Name,
			"namespace": svc.Namespace,
			"type":      string(svc.Spec.Type),
			"clusterIP": svc.Spec.ClusterIP,
			"ports":     ports,
			"selector":  svc.Spec.Selector,
		})
	}

	if services == nil {
		services = []map[string]interface{}{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"services": services})
}

// ---- mirrord Config ----

// GenerateMirrordConfig generates a mirrord config for a target service.
func (h *WorkspaceHandler) GenerateMirrordConfig(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")

	var req MirrordConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.TargetService == "" {
		writeError(w, http.StatusBadRequest, "targetService is required")
		return
	}

	targetNs := req.TargetNamespace
	if targetNs == "" {
		targetNs = "default"
	}

	// Get tenant kubeconfig
	kubeconfigData, err := h.getTenantKubeconfig(r.Context(), namespace, clusterName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get tenant kubeconfig: %v", err))
		return
	}

	mirrordConfig := map[string]interface{}{
		"target": map[string]interface{}{
			"path":      fmt.Sprintf("deploy/%s", req.TargetService),
			"namespace": targetNs,
		},
		"feature": map[string]interface{}{
			"network": map[string]interface{}{
				"incoming": "mirror",
				"dns":      true,
			},
			"fs":  "local",
			"env": true,
		},
		"kube_context": fmt.Sprintf("mirrord-%s-%s", clusterName, targetNs),
	}

	// Format config as pretty JSON string for display
	configJSON, _ := json.MarshalIndent(mirrordConfig, "", "  ")
	configStr := string(configJSON)

	// Build VS Code deeplink
	configB64 := base64.StdEncoding.EncodeToString(configJSON)
	deeplink := fmt.Sprintf("vscode://metalbear-co.mirrord/connect?config=%s", configB64)

	filename := fmt.Sprintf("mirrord-%s-%s.json", clusterName, req.TargetService)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"config":         configStr,
		"kubeconfig":     string(kubeconfigData),
		"filename":       filename,
		"vscodeDeeplink": deeplink,
	})
}

// ---- Workspace Images ----

// ListImages returns the available workspace image catalog.
func (h *WorkspaceHandler) ListImages(w http.ResponseWriter, r *http.Request) {
	images := []map[string]interface{}{
		{
			"name":        "workspace-base",
			"image":       "ubuntu:24.04",
			"displayName": "Base (Ubuntu)",
			"language":    "general",
			"description": "Ubuntu 24.04 with core development tools",
			"tools":       []string{"git", "curl", "vim", "tmux", "jq"},
		},
		{
			"name":        "workspace-go",
			"image":       "golang:1.24",
			"displayName": "Go 1.24",
			"language":    "go",
			"description": "Go development environment",
			"tools":       []string{"go", "git"},
		},
		{
			"name":        "workspace-node",
			"image":       "node:22",
			"displayName": "Node.js 22",
			"language":    "javascript",
			"description": "Node.js with npm, yarn, pnpm, and tsx",
			"tools":       []string{"node", "npm", "git"},
		},
		{
			"name":        "workspace-python",
			"image":       "python:3.13",
			"displayName": "Python 3.13",
			"language":    "python",
			"description": "Python with pip",
			"tools":       []string{"python", "pip", "git"},
		},
		{
			"name":        "workspace-rust",
			"image":       "rust:1.84",
			"displayName": "Rust 1.84",
			"language":    "rust",
			"description": "Rust with cargo",
			"tools":       []string{"rustc", "cargo", "git"},
		},
		{
			"name":        "workspace-java",
			"image":       "eclipse-temurin:21",
			"displayName": "Java 21",
			"language":    "java",
			"description": "JDK 21 (Eclipse Temurin)",
			"tools":       []string{"java", "javac", "git"},
		},
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"images": images})
}

// ---- Templates ----

// ListTemplates returns workspace templates visible to the user.
func (h *WorkspaceHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())

	var templates []map[string]interface{}

	// Cluster-scoped templates from butler-system
	systemTemplates, err := h.k8sClient.Dynamic().Resource(WorkspaceTemplateGVR).Namespace("butler-system").List(r.Context(), metav1.ListOptions{})
	if err == nil {
		for _, t := range systemTemplates.Items {
			templates = append(templates, t.Object)
		}
	}

	// Team-scoped templates from active team namespace
	if user != nil && user.SelectedTeam != "" {
		teamNs := fmt.Sprintf("team-%s", user.SelectedTeam)
		teamTemplates, err := h.k8sClient.Dynamic().Resource(WorkspaceTemplateGVR).Namespace(teamNs).List(r.Context(), metav1.ListOptions{})
		if err == nil {
			for _, t := range teamTemplates.Items {
				templates = append(templates, t.Object)
			}
		}
	}

	if templates == nil {
		templates = []map[string]interface{}{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"templates": templates})
}

// CreateTemplate creates a new workspace template.
func (h *WorkspaceHandler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Determine namespace based on scope
	scope, _ := body["scope"].(string)
	namespace := fmt.Sprintf("team-%s", user.SelectedTeam)
	if scope == "cluster" {
		if !user.IsAdmin() {
			writeError(w, http.StatusForbidden, "only platform admins can create cluster-scoped templates")
			return
		}
		namespace = "butler-system"
	}

	template := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "WorkspaceTemplate",
			"metadata": map[string]interface{}{
				"name":      body["name"],
				"namespace": namespace,
			},
			"spec": body,
		},
	}

	result, err := h.k8sClient.Dynamic().Resource(WorkspaceTemplateGVR).Namespace(namespace).Create(r.Context(), template, metav1.CreateOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create template: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, result.Object)
}

// UpdateTemplate updates an existing workspace template.
func (h *WorkspaceHandler) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	var body map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	existing, err := h.k8sClient.Dynamic().Resource(WorkspaceTemplateGVR).Namespace(namespace).Get(r.Context(), name, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("template not found: %v", err))
		return
	}

	// Update spec fields from body
	spec, _ := existing.Object["spec"].(map[string]interface{})
	if spec == nil {
		spec = make(map[string]interface{})
	}
	if v, ok := body["displayName"]; ok {
		spec["displayName"] = v
	}
	if v, ok := body["description"]; ok {
		spec["description"] = v
	}
	if v, ok := body["icon"]; ok {
		spec["icon"] = v
	}
	if v, ok := body["category"]; ok {
		spec["category"] = v
	}
	if v, ok := body["template"]; ok {
		spec["template"] = v
	}
	existing.Object["spec"] = spec

	result, err := h.k8sClient.Dynamic().Resource(WorkspaceTemplateGVR).Namespace(namespace).Update(r.Context(), existing, metav1.UpdateOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update template: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, result.Object)
}

// DeleteTemplate deletes a workspace template.
func (h *WorkspaceHandler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	if err := h.k8sClient.Dynamic().Resource(WorkspaceTemplateGVR).Namespace(namespace).Delete(r.Context(), name, metav1.DeleteOptions{}); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete template: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ---- Metrics ----

// GetMetrics returns CPU/memory metrics for a workspace.
func (h *WorkspaceHandler) GetMetrics(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")
	wsName := chi.URLParam(r, "workspace")

	// Get workspace to find pod name
	ws, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Get(r.Context(), wsName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}

	podName, _, _ := unstructured.NestedString(ws.Object, "status", "podName")
	if podName == "" {
		writeError(w, http.StatusBadRequest, "workspace pod not running")
		return
	}

	tenantClient, err := h.getTenantClient(r.Context(), namespace, clusterName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get tenant client: %v", err))
		return
	}

	// Get pod for resource requests/limits
	pod, err := tenantClient.CoreV1().Pods("workspaces").Get(r.Context(), podName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get pod: %v", err))
		return
	}

	// Get creation time for uptime
	var uptime string
	if !pod.CreationTimestamp.IsZero() {
		duration := time.Since(pod.CreationTimestamp.Time)
		hours := int(duration.Hours())
		minutes := int(duration.Minutes()) % 60
		uptime = fmt.Sprintf("%dh%dm", hours, minutes)
	}

	// Get resource requests from pod spec
	var cpuRequest, cpuLimit, memRequest, memLimit string
	if len(pod.Spec.Containers) > 0 {
		c := pod.Spec.Containers[0]
		if q, ok := c.Resources.Requests["cpu"]; ok {
			cpuRequest = q.String()
		}
		if q, ok := c.Resources.Limits["cpu"]; ok {
			cpuLimit = q.String()
		}
		if q, ok := c.Resources.Requests["memory"]; ok {
			memRequest = q.String()
		}
		if q, ok := c.Resources.Limits["memory"]; ok {
			memLimit = q.String()
		}
	}

	// Get storage info
	storageSize, _, _ := unstructured.NestedString(ws.Object, "spec", "storageSize")
	if storageSize == "" {
		storageSize = "50Gi"
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"cpu": map[string]interface{}{
			"request": cpuRequest,
			"limit":   cpuLimit,
		},
		"memory": map[string]interface{}{
			"request": memRequest,
			"limit":   memLimit,
		},
		"storage": map[string]interface{}{
			"capacity": storageSize,
		},
		"uptime": uptime,
	})
}

// ---- SSH Key Management (on UserHandler) ----
// These are added to users.go separately.

// ---- Helper methods ----

func (h *WorkspaceHandler) checkWorkspaceAccess(user *auth.UserSession, ws *unstructured.Unstructured) error {
	if user.IsAdmin() {
		return nil
	}
	if user.SelectedTeamRole == "admin" {
		return nil
	}
	owner, _, _ := unstructured.NestedString(ws.Object, "spec", "owner")
	if owner != user.Email {
		return fmt.Errorf("forbidden: workspace belongs to %s", owner)
	}
	return nil
}

func (h *WorkspaceHandler) resolveUserSSHKeys(ctx context.Context, email string) ([]string, error) {
	users, err := h.k8sClient.Dynamic().Resource(UserGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	// Extract local part for flexible matching (e.g., abagan@butlerlabs.dev → abagan)
	emailLocalPart := email
	if idx := strings.Index(email, "@"); idx > 0 {
		emailLocalPart = email[:idx]
	}

	for _, u := range users.Items {
		userEmail, _, _ := unstructured.NestedString(u.Object, "spec", "email")
		userName := u.GetName()

		// Match on exact email, CRD name, or email local part
		matched := userEmail == email ||
			userName == emailLocalPart ||
			(userEmail != "" && strings.HasPrefix(userEmail, emailLocalPart+"@"))

		if !matched {
			continue
		}

		sshKeys, found, _ := unstructured.NestedSlice(u.Object, "spec", "sshKeys")
		if !found || len(sshKeys) == 0 {
			return nil, nil
		}

		var keys []string
		for _, k := range sshKeys {
			if keyMap, ok := k.(map[string]interface{}); ok {
				if pubKey, ok := keyMap["publicKey"].(string); ok {
					keys = append(keys, pubKey)
				}
			}
		}
		return keys, nil
	}

	return nil, nil
}

func (h *WorkspaceHandler) getTenantKubeconfig(ctx context.Context, namespace, clusterName string) ([]byte, error) {
	cluster, err := h.k8sClient.GetTenantCluster(ctx, namespace, clusterName)
	if err != nil {
		return nil, fmt.Errorf("failed to get cluster: %w", err)
	}

	tenantNs, _, _ := unstructured.NestedString(cluster.Object, "status", "tenantNamespace")
	if tenantNs == "" {
		return nil, fmt.Errorf("cluster has no tenantNamespace in status")
	}

	secretName := fmt.Sprintf("%s-admin-kubeconfig", clusterName)
	secret, err := h.k8sClient.Clientset().CoreV1().Secrets(tenantNs).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get kubeconfig secret: %w", err)
	}

	// Prefer admin.conf (external endpoint) so the server can reach the tenant
	// cluster regardless of whether it runs inside or outside the management cluster.
	if data, ok := secret.Data["admin.conf"]; ok {
		return data, nil
	}
	if data, ok := secret.Data["admin.svc"]; ok {
		return data, nil
	}

	return nil, fmt.Errorf("kubeconfig secret missing admin.conf and admin.svc keys")
}

func (h *WorkspaceHandler) getTenantClient(ctx context.Context, namespace, clusterName string) (kubernetes.Interface, error) {
	kubeconfigData, err := h.getTenantKubeconfig(ctx, namespace, clusterName)
	if err != nil {
		return nil, err
	}

	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfigData)
	if err != nil {
		return nil, fmt.Errorf("failed to build REST config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant clientset: %w", err)
	}

	return clientset, nil
}

func sanitizeLabelValue(email string) string {
	s := email
	for _, ch := range []string{"@", ".", "+"} {
		s = replaceAll(s, ch, "_")
	}
	if len(s) > 63 {
		s = s[:63]
	}
	return s
}

func replaceAll(s, old, new string) string {
	for {
		idx := indexOf(s, old)
		if idx == -1 {
			return s
		}
		s = s[:idx] + new + s[idx+len(old):]
	}
}

func indexOf(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func toInterfaceSlice(ss []string) []interface{} {
	result := make([]interface{}, len(ss))
	for i, s := range ss {
		result[i] = s
	}
	return result
}

// SyncSSHKeys syncs the current user's SSH keys to a running workspace.
// POST /clusters/{namespace}/{name}/workspaces/{workspace}/sync-ssh-keys
func (h *WorkspaceHandler) SyncSSHKeys(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	namespace := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")
	workspaceName := chi.URLParam(r, "workspace")

	// Get workspace
	ws, err := h.k8sClient.Dynamic().Resource(WorkspaceGVR).Namespace(namespace).Get(
		r.Context(), workspaceName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusNotFound, "workspace not found")
		return
	}

	// Verify access
	if err := h.checkWorkspaceAccess(user, ws); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	// Workspace must be running
	phase, _, _ := unstructured.NestedString(ws.Object, "status", "phase")
	if phase != "Running" {
		writeError(w, http.StatusBadRequest, "workspace must be running to sync SSH keys")
		return
	}

	podName, _, _ := unstructured.NestedString(ws.Object, "status", "podName")
	if podName == "" {
		writeError(w, http.StatusBadRequest, "workspace pod not running")
		return
	}

	// Resolve current SSH keys from User CRD
	owner, _, _ := unstructured.NestedString(ws.Object, "spec", "owner")
	sshKeys, err := h.resolveUserSSHKeys(r.Context(), owner)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to resolve SSH keys")
		return
	}
	if len(sshKeys) == 0 {
		writeError(w, http.StatusBadRequest, "no SSH keys found on user profile")
		return
	}

	// Update the SSH keys secret on the tenant cluster
	tenantClient, err := h.getTenantClient(r.Context(), namespace, clusterName)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to connect to tenant: %v", err))
		return
	}

	authorizedKeys := ""
	for i, key := range sshKeys {
		authorizedKeys += key
		if i < len(sshKeys)-1 {
			authorizedKeys += "\n"
		}
	}
	authorizedKeys += "\n"

	secretName := fmt.Sprintf("ws-%s-ssh-keys", workspaceName)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: "workspaces",
		},
		Data: map[string][]byte{
			"authorized_keys": []byte(authorizedKeys),
		},
	}

	_, err = tenantClient.CoreV1().Secrets("workspaces").Update(r.Context(), secret, metav1.UpdateOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update SSH secret: %v", err))
		return
	}

	// Exec into the pod to refresh authorized_keys immediately
	restConfig, err := h.getTenantRESTConfig(r.Context(), namespace, clusterName)
	if err != nil {
		// Secret was updated — keys will propagate via kubelet within ~60s
		h.logger.Warn("SSH secret updated but exec failed", "error", err)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"synced":  true,
			"keys":    len(sshKeys),
			"message": "SSH keys updated. Keys will take effect within ~60 seconds.",
		})
		return
	}

	execReq := tenantClient.CoreV1().RESTClient().Post().
		Resource("pods").
		Name(podName).
		Namespace("workspaces").
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: "workspace",
			Command:   []string{"sh", "-c", "cp /tmp/ssh-keys/authorized_keys /home/dev/.ssh/authorized_keys && chmod 600 /home/dev/.ssh/authorized_keys && chown 1000:1000 /home/dev/.ssh/authorized_keys"},
			Stdout:    true,
			Stderr:    true,
		}, scheme.ParameterCodec)

	exec, err := remotecommand.NewSPDYExecutor(restConfig, "POST", execReq.URL())
	if err != nil {
		h.logger.Warn("SSH secret updated but exec setup failed", "error", err)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"synced":  true,
			"keys":    len(sshKeys),
			"message": "SSH keys updated. Keys will take effect within ~60 seconds.",
		})
		return
	}

	if err := exec.StreamWithContext(r.Context(), remotecommand.StreamOptions{}); err != nil {
		h.logger.Warn("SSH secret updated but exec failed", "error", err)
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"synced":  true,
			"keys":    len(sshKeys),
			"message": "SSH keys updated. Keys will take effect within ~60 seconds.",
		})
		return
	}

	h.logger.Info("SSH keys synced to workspace", "workspace", workspaceName, "keys", len(sshKeys))
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"synced":  true,
		"keys":    len(sshKeys),
		"message": "SSH keys synced successfully.",
	})
}

func (h *WorkspaceHandler) getTenantRESTConfig(ctx context.Context, namespace, clusterName string) (*rest.Config, error) {
	kubeconfigData, err := h.getTenantKubeconfig(ctx, namespace, clusterName)
	if err != nil {
		return nil, err
	}

	restConfig, err := clientcmd.RESTConfigFromKubeConfig(kubeconfigData)
	if err != nil {
		return nil, fmt.Errorf("failed to build REST config: %w", err)
	}

	return restConfig, nil
}
