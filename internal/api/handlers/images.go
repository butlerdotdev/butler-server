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
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

var imageSyncGVR = schema.GroupVersionResource{
	Group:    "butler.butlerlabs.dev",
	Version:  "v1alpha1",
	Resource: "imagesyncs",
}

// ImagesHandler handles image sync and image factory proxy endpoints.
type ImagesHandler struct {
	k8sClient *k8s.Client
	config    *config.Config
	logger    *slog.Logger
}

// NewImagesHandler creates a new images handler.
func NewImagesHandler(k8sClient *k8s.Client, cfg *config.Config, logger *slog.Logger) *ImagesHandler {
	return &ImagesHandler{
		k8sClient: k8sClient,
		config:    cfg,
		logger:    logger,
	}
}

// --- Request/Response Types ---

// CreateImageSyncRequest represents an image sync creation request.
type CreateImageSyncRequest struct {
	SchematicID    string `json:"schematicID"`
	Version        string `json:"version"`
	Arch           string `json:"arch,omitempty"`
	ProviderConfig string `json:"providerConfig"` // "namespace/name" format
	Format         string `json:"format,omitempty"`
	TransferMode   string `json:"transferMode,omitempty"`
	DisplayName    string `json:"displayName,omitempty"`
}

// ImageSyncResponse represents an image sync in API responses.
type ImageSyncResponse struct {
	Name             string `json:"name"`
	Namespace        string `json:"namespace"`
	Phase            string `json:"phase"`
	SchematicID      string `json:"schematicID"`
	Version          string `json:"version"`
	Arch             string `json:"arch"`
	ProviderConfig   string `json:"providerConfig"`
	ProviderImageRef string `json:"providerImageRef,omitempty"`
	TransferMode     string `json:"transferMode"`
	Format           string `json:"format"`
	FailureReason    string `json:"failureReason,omitempty"`
	FailureMessage   string `json:"failureMessage,omitempty"`
	CreatedAt        string `json:"createdAt"`
}

// FactoryCatalogResponse represents the factory catalog proxy response.
type FactoryCatalogResponse struct {
	Entries []FactoryCatalogEntry `json:"entries"`
}

// FactoryCatalogEntry represents a single entry in the factory catalog.
type FactoryCatalogEntry struct {
	OS       string   `json:"os"`
	Versions []string `json:"versions"`
	Formats  []string `json:"formats"`
}

// --- Image Sync CRUD ---

// ListImageSyncs handles GET /api/image-syncs.
// Supports query params: ?provider=name&status=Ready&schematic=abc123
func (h *ImagesHandler) ListImageSyncs(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	ctx := r.Context()

	providerFilter := r.URL.Query().Get("provider")
	statusFilter := r.URL.Query().Get("status")
	schematicFilter := r.URL.Query().Get("schematic")

	// List all ImageSyncs across namespaces
	imageSyncs, err := h.k8sClient.Dynamic().Resource(imageSyncGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		h.logger.Error("Failed to list ImageSyncs", "error", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list image syncs: %v", err))
		return
	}

	results := make([]ImageSyncResponse, 0, len(imageSyncs.Items))
	for _, is := range imageSyncs.Items {
		resp := imageSyncFromUnstructured(&is)

		// Filter by team access for non-admin users
		if user != nil && !user.IsAdmin() {
			isNamespace := is.GetNamespace()
			// Non-admin users can only see ImageSyncs in namespaces they have access to
			if user.SelectedTeam != "" {
				teamNS := "team-" + user.SelectedTeam
				if isNamespace != teamNS && isNamespace != h.config.SystemNamespace {
					continue
				}
			}
		}

		// Apply query param filters
		if providerFilter != "" && resp.ProviderConfig != "" {
			// Match on provider config name (last segment of "namespace/name")
			parts := strings.Split(resp.ProviderConfig, "/")
			pcName := parts[len(parts)-1]
			if pcName != providerFilter && resp.ProviderConfig != providerFilter {
				continue
			}
		}
		if statusFilter != "" && resp.Phase != statusFilter {
			continue
		}
		if schematicFilter != "" && !strings.HasPrefix(resp.SchematicID, schematicFilter) {
			continue
		}

		results = append(results, resp)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"imageSyncs": results})
}

// CreateImageSync handles POST /api/image-syncs.
func (h *ImagesHandler) CreateImageSync(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	ctx := r.Context()

	var req CreateImageSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	// Validate required fields
	if req.SchematicID == "" {
		writeError(w, http.StatusBadRequest, "schematicID is required")
		return
	}
	if req.Version == "" {
		writeError(w, http.StatusBadRequest, "version is required")
		return
	}
	if req.ProviderConfig == "" {
		writeError(w, http.StatusBadRequest, "providerConfig is required (format: namespace/name)")
		return
	}

	// Parse providerConfig into namespace/name
	parts := strings.SplitN(req.ProviderConfig, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		writeError(w, http.StatusBadRequest, "providerConfig must be in 'namespace/name' format")
		return
	}
	pcNamespace := parts[0]
	pcName := parts[1]

	// Verify the referenced ProviderConfig exists
	_, err := h.k8sClient.GetProviderConfig(ctx, pcNamespace, pcName)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("provider config not found: %s/%s", pcNamespace, pcName))
		return
	}

	// Authorization: check operate permission if team context is set
	if user != nil {
		if user.SelectedTeam != "" {
			if user.SelectedTeamRole == auth.RoleViewer {
				writeError(w, http.StatusForbidden, "viewer role cannot create image syncs")
				return
			}
		} else if !user.IsAdmin() {
			writeError(w, http.StatusForbidden, "image sync creation requires admin role or team context")
			return
		}
	}

	// Set defaults
	if req.Arch == "" {
		req.Arch = "amd64"
	}
	if req.Format == "" {
		req.Format = "qcow2"
	}
	if req.TransferMode == "" {
		req.TransferMode = "direct"
	}

	// Determine the namespace for the ImageSync
	namespace := h.config.SystemNamespace
	if user != nil && user.SelectedTeam != "" {
		namespace = "team-" + user.SelectedTeam
	}

	// Generate a deterministic name from the spec
	nameBase := fmt.Sprintf("%s-%s-%s", req.SchematicID[:8], req.Version, pcName)
	nameBase = strings.ReplaceAll(nameBase, ".", "-")
	nameBase = strings.ToLower(nameBase)
	// Truncate to valid K8s name length
	if len(nameBase) > 63 {
		nameBase = nameBase[:63]
	}

	// Build the unstructured ImageSync object
	spec := map[string]interface{}{
		"factoryRef": map[string]interface{}{
			"schematicID": req.SchematicID,
			"version":     req.Version,
			"arch":        req.Arch,
		},
		"providerConfigRef": map[string]interface{}{
			"name":      pcName,
			"namespace": pcNamespace,
		},
		"format":       req.Format,
		"transferMode": req.TransferMode,
	}

	if req.DisplayName != "" {
		spec["displayName"] = req.DisplayName
	}

	imageSync := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "ImageSync",
			"metadata": map[string]interface{}{
				"name":      nameBase,
				"namespace": namespace,
			},
			"spec": spec,
		},
	}

	created, err := h.k8sClient.Dynamic().Resource(imageSyncGVR).Namespace(namespace).Create(
		ctx, imageSync, metav1.CreateOptions{},
	)
	if err != nil {
		h.logger.Error("Failed to create ImageSync", "error", err, "name", nameBase, "namespace", namespace)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create image sync: %v", err))
		return
	}

	h.logger.Info("Created ImageSync", "name", nameBase, "namespace", namespace, "schematicID", req.SchematicID)
	resp := imageSyncFromUnstructured(created)
	writeJSON(w, http.StatusCreated, resp)
}

// GetImageSync handles GET /api/image-syncs/{namespace}/{name}.
func (h *ImagesHandler) GetImageSync(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	ctx := r.Context()

	imageSync, err := h.k8sClient.Dynamic().Resource(imageSyncGVR).Namespace(namespace).Get(
		ctx, name, metav1.GetOptions{},
	)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("image sync not found: %v", err))
		return
	}

	resp := imageSyncFromUnstructured(imageSync)
	writeJSON(w, http.StatusOK, resp)
}

// DeleteImageSync handles DELETE /api/image-syncs/{namespace}/{name}.
func (h *ImagesHandler) DeleteImageSync(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")
	ctx := r.Context()

	// Verify the ImageSync exists
	_, err := h.k8sClient.Dynamic().Resource(imageSyncGVR).Namespace(namespace).Get(
		ctx, name, metav1.GetOptions{},
	)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("image sync not found: %v", err))
		return
	}

	// Authorization: require admin or operator role
	if user != nil {
		if user.SelectedTeam != "" {
			if user.SelectedTeamRole == auth.RoleViewer {
				writeError(w, http.StatusForbidden, "viewer role cannot delete image syncs")
				return
			}
		} else if !user.IsAdmin() {
			writeError(w, http.StatusForbidden, "image sync deletion requires admin role or team context")
			return
		}
	}

	err = h.k8sClient.Dynamic().Resource(imageSyncGVR).Namespace(namespace).Delete(
		ctx, name, metav1.DeleteOptions{},
	)
	if err != nil {
		h.logger.Error("Failed to delete ImageSync", "error", err, "name", name, "namespace", namespace)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete image sync: %v", err))
		return
	}

	h.logger.Info("Deleted ImageSync", "name", name, "namespace", namespace)
	writeJSON(w, http.StatusOK, map[string]string{"message": "image sync deletion initiated"})
}

// --- Factory Proxy Endpoints ---

// GetFactoryCatalog handles GET /api/image-factory/catalog.
// Proxies to the factory's /v1/catalog endpoint.
func (h *ImagesHandler) GetFactoryCatalog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	factoryURL, apiKey, err := h.getFactoryConfig(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("image factory not configured: %v", err))
		return
	}

	catalogURL := strings.TrimRight(factoryURL, "/") + "/v1/catalog"
	h.proxyFactoryRequest(w, r, catalogURL, apiKey)
}

// GetFactorySchematic handles GET /api/image-factory/schematics/{id}.
// Proxies to the factory's /v1/schematics/{id} endpoint.
func (h *ImagesHandler) GetFactorySchematic(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")

	if id == "" {
		writeError(w, http.StatusBadRequest, "schematic id is required")
		return
	}

	factoryURL, apiKey, err := h.getFactoryConfig(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("image factory not configured: %v", err))
		return
	}

	schematicURL := strings.TrimRight(factoryURL, "/") + "/v1/schematics/" + id
	h.proxyFactoryRequest(w, r, schematicURL, apiKey)
}

// --- Internal Helpers ---

// getFactoryConfig reads the image factory URL and optional API key from the ButlerConfig.
func (h *ImagesHandler) getFactoryConfig(ctx context.Context) (string, string, error) {
	bc, err := h.k8sClient.GetButlerConfigTyped(ctx)
	if err != nil {
		return "", "", fmt.Errorf("failed to get ButlerConfig: %w", err)
	}

	if !bc.IsImageFactoryConfigured() {
		return "", "", fmt.Errorf("image factory is not configured in ButlerConfig")
	}

	factoryURL := bc.GetImageFactoryURL()

	// Read API key from credentials secret if configured
	var apiKey string
	if bc.Spec.ImageFactory.CredentialsRef != nil {
		secretNamespace := bc.Spec.ImageFactory.CredentialsRef.Namespace
		if secretNamespace == "" {
			secretNamespace = h.config.SystemNamespace
		}
		secret, err := h.k8sClient.GetSecret(ctx, secretNamespace, bc.Spec.ImageFactory.CredentialsRef.Name)
		if err != nil {
			h.logger.Warn("Failed to read image factory credentials secret",
				"error", err,
				"secret", bc.Spec.ImageFactory.CredentialsRef.Name,
				"namespace", secretNamespace,
			)
			// Continue without API key -- the factory may not require auth
		} else {
			apiKey = string(secret.Data["apiKey"])
		}
	}

	return factoryURL, apiKey, nil
}

// proxyFactoryRequest proxies an HTTP GET to the factory and forwards the response.
func (h *ImagesHandler) proxyFactoryRequest(w http.ResponseWriter, r *http.Request, targetURL, apiKey string) {
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, targetURL, nil)
	if err != nil {
		h.logger.Error("Failed to create factory proxy request", "error", err, "url", targetURL)
		writeError(w, http.StatusInternalServerError, "failed to create proxy request")
		return
	}

	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		h.logger.Error("Factory proxy request failed", "error", err, "url", targetURL)
		writeError(w, http.StatusBadGateway, fmt.Sprintf("failed to reach image factory: %v", err))
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		h.logger.Warn("Factory returned non-200 status",
			"status", resp.StatusCode,
			"url", targetURL,
			"body", string(body),
		)
		writeError(w, resp.StatusCode, fmt.Sprintf("image factory error: %s", string(body)))
		return
	}

	// Forward the JSON response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := io.Copy(w, resp.Body); err != nil {
		h.logger.Error("Failed to forward factory response", "error", err)
	}
}

// imageSyncFromUnstructured converts an unstructured ImageSync to the response type.
func imageSyncFromUnstructured(obj *unstructured.Unstructured) ImageSyncResponse {
	resp := ImageSyncResponse{
		Name:      obj.GetName(),
		Namespace: obj.GetNamespace(),
		CreatedAt: obj.GetCreationTimestamp().Format(time.RFC3339),
	}

	// Spec fields
	resp.SchematicID, _, _ = unstructured.NestedString(obj.Object, "spec", "factoryRef", "schematicID")
	resp.Version, _, _ = unstructured.NestedString(obj.Object, "spec", "factoryRef", "version")
	resp.Arch, _, _ = unstructured.NestedString(obj.Object, "spec", "factoryRef", "arch")
	resp.Format, _, _ = unstructured.NestedString(obj.Object, "spec", "format")
	resp.TransferMode, _, _ = unstructured.NestedString(obj.Object, "spec", "transferMode")

	// Build providerConfig as "namespace/name"
	pcName, _, _ := unstructured.NestedString(obj.Object, "spec", "providerConfigRef", "name")
	pcNamespace, _, _ := unstructured.NestedString(obj.Object, "spec", "providerConfigRef", "namespace")
	if pcNamespace != "" && pcName != "" {
		resp.ProviderConfig = pcNamespace + "/" + pcName
	} else if pcName != "" {
		resp.ProviderConfig = pcName
	}

	// Status fields
	resp.Phase, _, _ = unstructured.NestedString(obj.Object, "status", "phase")
	resp.ProviderImageRef, _, _ = unstructured.NestedString(obj.Object, "status", "providerImageRef")
	resp.FailureReason, _, _ = unstructured.NestedString(obj.Object, "status", "failureReason")
	resp.FailureMessage, _, _ = unstructured.NestedString(obj.Object, "status", "failureMessage")

	// Default phase if empty
	if resp.Phase == "" {
		resp.Phase = "Pending"
	}

	return resp
}
