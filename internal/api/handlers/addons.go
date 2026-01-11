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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"

	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// AddonsHandler handles addon-related endpoints.
type AddonsHandler struct {
	k8sClient *k8s.Client
	config    *config.Config
}

// NewAddonsHandler creates a new addons handler.
func NewAddonsHandler(k8sClient *k8s.Client, cfg *config.Config) *AddonsHandler {
	return &AddonsHandler{
		k8sClient: k8sClient,
		config:    cfg,
	}
}

// AddonDefinitionResponse represents an addon from the catalog.
type AddonDefinitionResponse struct {
	Name              string            `json:"name"`
	DisplayName       string            `json:"displayName"`
	Description       string            `json:"description"`
	Category          string            `json:"category"`
	Icon              string            `json:"icon,omitempty"`
	ChartRepository   string            `json:"chartRepository"`
	ChartName         string            `json:"chartName"`
	DefaultVersion    string            `json:"defaultVersion"`
	AvailableVersions []string          `json:"availableVersions,omitempty"`
	DefaultNamespace  string            `json:"defaultNamespace,omitempty"`
	Platform          bool              `json:"platform"`
	DependsOn         []string          `json:"dependsOn,omitempty"`
	Source            string            `json:"source"`
	Links             map[string]string `json:"links,omitempty"`
}

// CatalogResponse is the response for the catalog endpoint.
type CatalogResponse struct {
	Addons     []AddonDefinitionResponse `json:"addons"`
	Categories []CategoryInfo            `json:"categories"`
}

// CategoryInfo provides metadata about addon categories.
type CategoryInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`
	Icon        string `json:"icon"`
}

// InstalledAddonResponse represents an installed addon's status.
type InstalledAddonResponse struct {
	Name             string                 `json:"name"`
	DisplayName      string                 `json:"displayName,omitempty"`
	Status           string                 `json:"status"`
	Phase            string                 `json:"phase,omitempty"`
	Version          string                 `json:"version,omitempty"`
	InstalledVersion string                 `json:"installedVersion,omitempty"`
	ManagedBy        string                 `json:"managedBy,omitempty"`
	Namespace        string                 `json:"namespace,omitempty"`
	Message          string                 `json:"message,omitempty"`
	HelmRelease      map[string]interface{} `json:"helmRelease,omitempty"`
	Conditions       []ConditionResponse    `json:"conditions,omitempty"`
}

// ConditionResponse represents a condition.
type ConditionResponse struct {
	Type    string `json:"type"`
	Status  string `json:"status"`
	Reason  string `json:"reason,omitempty"`
	Message string `json:"message,omitempty"`
}

// AddonsListResponse is the response for listing installed addons.
type AddonsListResponse struct {
	Addons []InstalledAddonResponse `json:"addons"`
}

// InstallAddonRequest represents an addon installation request.
type InstallAddonRequest struct {
	Addon   string                 `json:"addon,omitempty"`
	Version string                 `json:"version,omitempty"`
	Values  map[string]interface{} `json:"values,omitempty"`
	Helm    *HelmChartRequest      `json:"helm,omitempty"`
}

// HelmChartRequest represents a custom Helm chart specification.
type HelmChartRequest struct {
	Repository      string `json:"repository"`
	Chart           string `json:"chart"`
	Version         string `json:"version,omitempty"`
	ReleaseName     string `json:"releaseName,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	CreateNamespace bool   `json:"createNamespace,omitempty"`
}

// UpdateAddonRequest represents an addon update request.
type UpdateAddonRequest struct {
	Values  map[string]interface{} `json:"values,omitempty"`
	Version string                 `json:"version,omitempty"`
}

// ManagementAddonResponse represents a management addon.
type ManagementAddonResponse struct {
	Name        string                    `json:"name"`
	Addon       string                    `json:"addon"`
	DisplayName string                    `json:"displayName,omitempty"`
	Version     string                    `json:"version,omitempty"`
	Status      ManagementAddonStatusResp `json:"status"`
}

// ManagementAddonStatusResp represents management addon status.
type ManagementAddonStatusResp struct {
	Phase            string `json:"phase"`
	InstalledVersion string `json:"installedVersion,omitempty"`
	Message          string `json:"message,omitempty"`
}

// InstallManagementAddonRequest represents a request to install a management addon.
type InstallManagementAddonRequest struct {
	Name    string                 `json:"name"`
	Addon   string                 `json:"addon"`
	Version string                 `json:"version,omitempty"`
	Values  map[string]interface{} `json:"values,omitempty"`
}

var categoryMetadata = map[string]CategoryInfo{
	"cni":           {Name: "cni", DisplayName: "Networking (CNI)", Description: "Container Network Interface plugins", Icon: "🌐"},
	"loadbalancer":  {Name: "loadbalancer", DisplayName: "Load Balancer", Description: "Load balancer implementations", Icon: "⚖️"},
	"storage":       {Name: "storage", DisplayName: "Storage", Description: "Persistent storage solutions", Icon: "💾"},
	"certmanager":   {Name: "certmanager", DisplayName: "Certificate Management", Description: "TLS certificate automation", Icon: "🔐"},
	"ingress":       {Name: "ingress", DisplayName: "Ingress", Description: "Ingress controllers", Icon: "🚪"},
	"observability": {Name: "observability", DisplayName: "Observability", Description: "Monitoring, logging, and tracing", Icon: "📊"},
	"backup":        {Name: "backup", DisplayName: "Backup & Recovery", Description: "Data protection and disaster recovery", Icon: "🛡️"},
	"gitops":        {Name: "gitops", DisplayName: "GitOps", Description: "Continuous delivery and deployment automation", Icon: "🔄"},
	"security":      {Name: "security", DisplayName: "Security", Description: "Security and policy enforcement", Icon: "🔒"},
	"other":         {Name: "other", DisplayName: "Other", Description: "Other addons", Icon: "📦"},
}

// GetCatalog returns the addon catalog from AddonDefinition CRDs.
func (h *AddonsHandler) GetCatalog(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	addonDefs, err := h.k8sClient.ListAddonDefinitions(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list addon definitions: %v", err))
		return
	}

	addons := make([]AddonDefinitionResponse, 0, len(addonDefs.Items))
	categoriesUsed := make(map[string]bool)

	for _, ad := range addonDefs.Items {
		addon := h.addonDefinitionToResponse(&ad)
		addons = append(addons, addon)
		categoriesUsed[addon.Category] = true
	}

	sort.Slice(addons, func(i, j int) bool {
		if addons[i].Platform != addons[j].Platform {
			return addons[i].Platform
		}
		if addons[i].Category != addons[j].Category {
			return addons[i].Category < addons[j].Category
		}
		return addons[i].Name < addons[j].Name
	})

	categories := make([]CategoryInfo, 0)
	for cat := range categoriesUsed {
		if info, ok := categoryMetadata[cat]; ok {
			categories = append(categories, info)
		}
	}
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].Name < categories[j].Name
	})

	writeJSON(w, http.StatusOK, CatalogResponse{
		Addons:     addons,
		Categories: categories,
	})
}

// GetAddonDefinition returns a specific addon definition.
func (h *AddonsHandler) GetAddonDefinition(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	ctx := r.Context()

	ad, err := h.k8sClient.GetAddonDefinition(ctx, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("addon definition not found: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, h.addonDefinitionToResponse(ad))
}

// ListClusterAddons returns installed addons for a cluster.
func (h *AddonsHandler) ListClusterAddons(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")
	ctx := r.Context()

	tc, err := h.k8sClient.GetTenantCluster(ctx, namespace, clusterName)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	addons := make([]InstalledAddonResponse, 0)

	observedState, _, _ := unstructured.NestedMap(tc.Object, "status", "observedState")
	if observedState != nil {
		observedAddons, _, _ := unstructured.NestedSlice(observedState, "addons")
		for _, a := range observedAddons {
			addonMap, ok := a.(map[string]interface{})
			if !ok {
				continue
			}
			addonName, _ := addonMap["name"].(string)
			status, _ := addonMap["status"].(string)
			version, _ := addonMap["version"].(string)

			displayName := addonName
			if ad, err := h.k8sClient.GetAddonDefinition(ctx, addonName); err == nil {
				displayName, _, _ = unstructured.NestedString(ad.Object, "spec", "displayName")
			}

			addons = append(addons, InstalledAddonResponse{
				Name:        addonName,
				DisplayName: displayName,
				Status:      MapAddonStatus(status),
				Version:     version,
				ManagedBy:   "platform",
			})
		}
	}

	tenantAddons, err := h.k8sClient.ListTenantAddons(ctx, namespace, clusterName)
	if err == nil && tenantAddons != nil {
		for _, ta := range tenantAddons.Items {
			addon := h.tenantAddonToResponse(ctx, &ta)
			addons = append(addons, addon)
		}
	}

	writeJSON(w, http.StatusOK, AddonsListResponse{Addons: addons})
}

// InstallAddon installs an addon on a cluster.
func (h *AddonsHandler) InstallAddon(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")
	ctx := r.Context()

	var req InstallAddonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Addon == "" && req.Helm == nil {
		writeError(w, http.StatusBadRequest, "addon name or helm spec is required")
		return
	}

	_, err := h.k8sClient.GetTenantCluster(ctx, namespace, clusterName)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	var addonDefName string
	if req.Addon != "" {
		ad, err := h.k8sClient.GetAddonDefinition(ctx, req.Addon)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("addon definition not found: %s", req.Addon))
			return
		}
		addonDefName = ad.GetName()

		platform, _, _ := unstructured.NestedBool(ad.Object, "spec", "platform")
		if platform {
			writeError(w, http.StatusBadRequest, "platform addons are managed automatically and cannot be installed manually")
			return
		}

		if req.Version == "" {
			req.Version, _, _ = unstructured.NestedString(ad.Object, "spec", "chart", "defaultVersion")
		}
	}

	spec := map[string]interface{}{
		"clusterRef": map[string]interface{}{
			"name": clusterName,
		},
	}

	if req.Addon != "" {
		spec["addon"] = req.Addon
	}
	if req.Version != "" {
		spec["version"] = req.Version
	}
	if req.Helm != nil {
		helmSpec := map[string]interface{}{
			"repository": req.Helm.Repository,
			"chart":      req.Helm.Chart,
		}
		if req.Helm.Version != "" {
			helmSpec["version"] = req.Helm.Version
		}
		if req.Helm.ReleaseName != "" {
			helmSpec["releaseName"] = req.Helm.ReleaseName
		}
		if req.Helm.Namespace != "" {
			helmSpec["namespace"] = req.Helm.Namespace
		}
		if req.Helm.CreateNamespace {
			helmSpec["createNamespace"] = true
		}
		spec["helm"] = helmSpec
	}
	if req.Values != nil {
		spec["values"] = req.Values
	}

	resourceName := req.Addon
	if resourceName == "" && req.Helm != nil {
		resourceName = req.Helm.ReleaseName
		if resourceName == "" {
			resourceName = req.Helm.Chart
		}
	}

	tenantAddon := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "TenantAddon",
			"metadata": map[string]interface{}{
				"name":      resourceName,
				"namespace": namespace,
				"labels": map[string]interface{}{
					"butler.butlerlabs.dev/cluster": clusterName,
				},
			},
			"spec": spec,
		},
	}

	if addonDefName != "" {
		labels, _, _ := unstructured.NestedStringMap(tenantAddon.Object, "metadata", "labels")
		labels["butler.butlerlabs.dev/addon-definition"] = addonDefName
		unstructured.SetNestedStringMap(tenantAddon.Object, labels, "metadata", "labels")
	}

	created, err := h.k8sClient.Dynamic().Resource(k8s.TenantAddonGVR).Namespace(namespace).Create(
		ctx, tenantAddon, metav1.CreateOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create addon: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, created.Object)
}

// GetAddonDetails returns details for a specific installed addon.
func (h *AddonsHandler) GetAddonDetails(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")
	addonName := chi.URLParam(r, "addon")
	ctx := r.Context()

	_, err := h.k8sClient.GetTenantCluster(ctx, namespace, clusterName)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	ta, err := h.k8sClient.Dynamic().Resource(k8s.TenantAddonGVR).Namespace(namespace).Get(
		ctx, addonName, metav1.GetOptions{},
	)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("addon not found: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, h.tenantAddonToResponse(ctx, ta))
}

// UpdateAddonValues updates an addon's configuration.
func (h *AddonsHandler) UpdateAddonValues(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")
	addonName := chi.URLParam(r, "addon")
	ctx := r.Context()

	var req UpdateAddonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	_, err := h.k8sClient.GetTenantCluster(ctx, namespace, clusterName)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	ta, err := h.k8sClient.Dynamic().Resource(k8s.TenantAddonGVR).Namespace(namespace).Get(
		ctx, addonName, metav1.GetOptions{},
	)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("addon not found: %v", err))
		return
	}

	if req.Values != nil {
		if err := unstructured.SetNestedField(ta.Object, req.Values, "spec", "values"); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update values")
			return
		}
	}

	if req.Version != "" {
		if err := unstructured.SetNestedField(ta.Object, req.Version, "spec", "version"); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update version")
			return
		}
	}

	updated, err := h.k8sClient.Dynamic().Resource(k8s.TenantAddonGVR).Namespace(namespace).Update(
		ctx, ta, metav1.UpdateOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update addon: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, updated.Object)
}

// UninstallAddon removes an addon from a cluster.
func (h *AddonsHandler) UninstallAddon(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	clusterName := chi.URLParam(r, "name")
	addonName := chi.URLParam(r, "addon")
	ctx := r.Context()

	_, err := h.k8sClient.GetTenantCluster(ctx, namespace, clusterName)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}

	ta, err := h.k8sClient.Dynamic().Resource(k8s.TenantAddonGVR).Namespace(namespace).Get(
		ctx, addonName, metav1.GetOptions{},
	)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("addon not found: %v", err))
		return
	}

	addonDefName, _, _ := unstructured.NestedString(ta.Object, "spec", "addon")
	if addonDefName != "" {
		ad, err := h.k8sClient.GetAddonDefinition(ctx, addonDefName)
		if err == nil {
			platform, _, _ := unstructured.NestedBool(ad.Object, "spec", "platform")
			if platform {
				writeError(w, http.StatusBadRequest, "platform addons cannot be uninstalled")
				return
			}
		}
	}

	err = h.k8sClient.Dynamic().Resource(k8s.TenantAddonGVR).Namespace(namespace).Delete(
		ctx, addonName, metav1.DeleteOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete addon: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "addon uninstall initiated"})
}

// ListManagementAddons returns all ManagementAddon CRs.
func (h *AddonsHandler) ListManagementAddons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	managementAddons, err := h.k8sClient.Dynamic().Resource(k8s.ManagementAddonGVR).List(
		ctx, metav1.ListOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list management addons: %v", err))
		return
	}

	addons := make([]ManagementAddonResponse, 0, len(managementAddons.Items))
	for _, ma := range managementAddons.Items {
		addon := h.managementAddonToResponse(ctx, &ma)
		addons = append(addons, addon)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"addons": addons})
}

// InstallManagementAddon creates a ManagementAddon CR.
func (h *AddonsHandler) InstallManagementAddon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req InstallManagementAddonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Addon == "" {
		writeError(w, http.StatusBadRequest, "addon name is required")
		return
	}

	name := req.Name
	if name == "" {
		name = req.Addon
	}

	ad, err := h.k8sClient.GetAddonDefinition(ctx, req.Addon)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("addon definition not found: %s", req.Addon))
		return
	}

	platform, _, _ := unstructured.NestedBool(ad.Object, "spec", "platform")
	if platform {
		writeError(w, http.StatusBadRequest, "platform addons cannot be installed on management cluster via this API")
		return
	}

	version := req.Version
	if version == "" {
		version, _, _ = unstructured.NestedString(ad.Object, "spec", "chart", "defaultVersion")
	}

	spec := map[string]interface{}{
		"addon": req.Addon,
	}
	if version != "" {
		spec["version"] = version
	}
	if req.Values != nil {
		spec["values"] = req.Values
	}

	managementAddon := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "ManagementAddon",
			"metadata": map[string]interface{}{
				"name": name,
				"labels": map[string]interface{}{
					"butler.butlerlabs.dev/addon-definition": req.Addon,
				},
			},
			"spec": spec,
		},
	}

	created, err := h.k8sClient.Dynamic().Resource(k8s.ManagementAddonGVR).Create(
		ctx, managementAddon, metav1.CreateOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create management addon: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, h.managementAddonToResponse(ctx, created))
}

// GetManagementAddon returns details for a specific management addon.
func (h *AddonsHandler) GetManagementAddon(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	ctx := r.Context()

	ma, err := h.k8sClient.Dynamic().Resource(k8s.ManagementAddonGVR).Get(
		ctx, name, metav1.GetOptions{},
	)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("management addon not found: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, h.managementAddonToResponse(ctx, ma))
}

// UpdateManagementAddon updates a management addon's configuration.
func (h *AddonsHandler) UpdateManagementAddon(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	ctx := r.Context()

	var req UpdateAddonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	ma, err := h.k8sClient.Dynamic().Resource(k8s.ManagementAddonGVR).Get(
		ctx, name, metav1.GetOptions{},
	)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("management addon not found: %v", err))
		return
	}

	if req.Values != nil {
		if err := unstructured.SetNestedField(ma.Object, req.Values, "spec", "values"); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update values")
			return
		}
	}

	if req.Version != "" {
		if err := unstructured.SetNestedField(ma.Object, req.Version, "spec", "version"); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to update version")
			return
		}
	}

	updated, err := h.k8sClient.Dynamic().Resource(k8s.ManagementAddonGVR).Update(
		ctx, ma, metav1.UpdateOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update management addon: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, h.managementAddonToResponse(ctx, updated))
}

// UninstallManagementAddon removes a management addon.
func (h *AddonsHandler) UninstallManagementAddon(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	ctx := r.Context()

	err := h.k8sClient.Dynamic().Resource(k8s.ManagementAddonGVR).Delete(
		ctx, name, metav1.DeleteOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete management addon: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "addon uninstall initiated"})
}

func (h *AddonsHandler) addonDefinitionToResponse(ad *unstructured.Unstructured) AddonDefinitionResponse {
	spec, _, _ := unstructured.NestedMap(ad.Object, "spec")

	displayName, _ := spec["displayName"].(string)
	description, _ := spec["description"].(string)
	category, _ := spec["category"].(string)
	icon, _ := spec["icon"].(string)
	platform, _ := spec["platform"].(bool)

	chartSpec, _ := spec["chart"].(map[string]interface{})
	chartRepo, _ := chartSpec["repository"].(string)
	chartName, _ := chartSpec["name"].(string)
	defaultVersion, _ := chartSpec["defaultVersion"].(string)

	var availableVersions []string
	if versions, ok := chartSpec["availableVersions"].([]interface{}); ok {
		for _, v := range versions {
			if vs, ok := v.(string); ok {
				availableVersions = append(availableVersions, vs)
			}
		}
	}

	defaults, _ := spec["defaults"].(map[string]interface{})
	defaultNamespace, _ := defaults["namespace"].(string)

	var dependsOn []string
	if deps, ok := spec["dependsOn"].([]interface{}); ok {
		for _, d := range deps {
			if ds, ok := d.(string); ok {
				dependsOn = append(dependsOn, ds)
			}
		}
	}

	source := "custom"
	labels, _, _ := unstructured.NestedStringMap(ad.Object, "metadata", "labels")
	if labels["butler.butlerlabs.dev/source"] == "builtin" {
		source = "builtin"
	}

	links := make(map[string]string)
	if linksSpec, ok := spec["links"].(map[string]interface{}); ok {
		for k, v := range linksSpec {
			if vs, ok := v.(string); ok {
				links[k] = vs
			}
		}
	}

	return AddonDefinitionResponse{
		Name:              ad.GetName(),
		DisplayName:       displayName,
		Description:       description,
		Category:          category,
		Icon:              icon,
		ChartRepository:   chartRepo,
		ChartName:         chartName,
		DefaultVersion:    defaultVersion,
		AvailableVersions: availableVersions,
		DefaultNamespace:  defaultNamespace,
		Platform:          platform,
		DependsOn:         dependsOn,
		Source:            source,
		Links:             links,
	}
}

func (h *AddonsHandler) tenantAddonToResponse(ctx context.Context, ta *unstructured.Unstructured) InstalledAddonResponse {
	name := ta.GetName()

	addonName, _, _ := unstructured.NestedString(ta.Object, "spec", "addon")
	if addonName == "" {
		addonName = name
	}
	version, _, _ := unstructured.NestedString(ta.Object, "spec", "version")

	phase, _, _ := unstructured.NestedString(ta.Object, "status", "phase")
	installedVersion, _, _ := unstructured.NestedString(ta.Object, "status", "installedVersion")
	message, _, _ := unstructured.NestedString(ta.Object, "status", "message")
	helmRelease, _, _ := unstructured.NestedMap(ta.Object, "status", "helmRelease")

	displayName := addonName
	if ad, err := h.k8sClient.GetAddonDefinition(ctx, addonName); err == nil {
		displayName, _, _ = unstructured.NestedString(ad.Object, "spec", "displayName")
	}

	var conditions []ConditionResponse
	if condList, ok, _ := unstructured.NestedSlice(ta.Object, "status", "conditions"); ok {
		for _, c := range condList {
			if cm, ok := c.(map[string]interface{}); ok {
				cond := ConditionResponse{}
				if t, ok := cm["type"].(string); ok {
					cond.Type = t
				}
				if s, ok := cm["status"].(string); ok {
					cond.Status = s
				}
				if r, ok := cm["reason"].(string); ok {
					cond.Reason = r
				}
				if m, ok := cm["message"].(string); ok {
					cond.Message = m
				}
				conditions = append(conditions, cond)
			}
		}
	}

	namespace := ""
	if helmRelease != nil {
		namespace, _ = helmRelease["namespace"].(string)
	}

	return InstalledAddonResponse{
		Name:             name,
		DisplayName:      displayName,
		Status:           MapAddonStatus(phase),
		Phase:            phase,
		Version:          version,
		InstalledVersion: installedVersion,
		ManagedBy:        "butler",
		Namespace:        namespace,
		Message:          message,
		HelmRelease:      helmRelease,
		Conditions:       conditions,
	}
}

func (h *AddonsHandler) managementAddonToResponse(ctx context.Context, ma *unstructured.Unstructured) ManagementAddonResponse {
	name := ma.GetName()

	addonName, _, _ := unstructured.NestedString(ma.Object, "spec", "addon")
	if addonName == "" {
		addonName = name
	}
	version, _, _ := unstructured.NestedString(ma.Object, "spec", "version")

	phase, _, _ := unstructured.NestedString(ma.Object, "status", "phase")
	installedVersion, _, _ := unstructured.NestedString(ma.Object, "status", "installedVersion")
	message, _, _ := unstructured.NestedString(ma.Object, "status", "message")

	displayName := addonName
	if ad, err := h.k8sClient.GetAddonDefinition(ctx, addonName); err == nil {
		displayName, _, _ = unstructured.NestedString(ad.Object, "spec", "displayName")
	}

	return ManagementAddonResponse{
		Name:        name,
		Addon:       addonName,
		DisplayName: displayName,
		Version:     version,
		Status: ManagementAddonStatusResp{
			Phase:            phase,
			InstalledVersion: installedVersion,
			Message:          message,
		},
	}
}
