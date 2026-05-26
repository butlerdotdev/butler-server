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
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	butlerv1alpha1 "github.com/butlerdotdev/butler-api/api/v1alpha1"
	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/gitops"
)

// resolveClusterName picks the directory name to emit under clusters/.
// Priority: override > the segment after "clusters/" in engine.Path > fallback.
func resolveClusterName(override string, engine *gitops.GitOpsEngineStatus, fallback string) string {
	if override = strings.TrimSpace(override); override != "" {
		return override
	}
	if engine != nil && engine.Path != "" {
		// engine.Path can be "./clusters/butler", "clusters/butler",
		// or "./clusters/butler/" — normalize and pull the segment.
		p := strings.TrimPrefix(engine.Path, "./")
		p = strings.Trim(p, "/")
		if i := strings.Index(p, "clusters/"); i >= 0 {
			tail := p[i+len("clusters/"):]
			if slash := strings.IndexByte(tail, '/'); slash >= 0 {
				tail = tail[:slash]
			}
			if tail != "" {
				return tail
			}
		}
		if segs := strings.Split(p, "/"); len(segs) > 0 {
			last := segs[len(segs)-1]
			if last != "" {
				return last
			}
		}
	}
	return fallback
}

// gitops_cluster.go: cluster-wide v2 export handlers.
//
// Symmetric pair with the existing per-addon endpoints in gitops.go:
//   - PreviewCluster + ExportCluster (tenant: /clusters/{ns}/{name}/...)
//   - PreviewManagementCluster + ExportManagementCluster (mgmt:
//     /management/...)
//
// The preview path discovers + runs GenerateLayoutV2 + BuildCoverage
// and returns the rendered tree + the coverage report (wrapped at the
// API boundary with Source classification). No git interaction.
//
// The export path runs the same discovery + (optionally) filters by
// the operator's selection from the preview, then wraps RunExportV2
// to push to git.
//
// Gating: GitOps must be enabled on the source cluster (Flux
// discovery returns Installed=true). Same gate as the per-addon
// export.

// previewClusterRequest is the request body for preview-cluster.
type previewClusterRequest struct {
	// Env is the apps overlay name (e.g. "prd", "dev"). Defaults to
	// "prd" when empty so callers don't have to specify a value for
	// single-env clusters.
	Env string `json:"env,omitempty"`

	// ClusterName is the directory name to emit under clusters/ (the
	// shape consumed by Flux as the bootstrap path). Optional: when
	// empty, the server derives it from the cluster's existing Flux
	// root Kustomization path (e.g. ./clusters/butler -> "butler"),
	// falling back to the tenant/mgmt name. Lets operators who named
	// their bootstrap directory something other than the tenant name
	// (e.g. "butler" for mgmt) round-trip cleanly.
	ClusterName string `json:"clusterName,omitempty"`
}

// exportClusterRequest is the request body for export-cluster. Carries
// the git target plus an optional selection set from the preview
// (operator picked a subset rather than exporting everything).
type exportClusterRequest struct {
	Env           string                          `json:"env,omitempty"`
	ClusterName   string                          `json:"clusterName,omitempty"`
	Repository    string                          `json:"repository"`
	Branch        string                          `json:"branch"`
	CreatePR      bool                            `json:"createPR,omitempty"`
	PRTitle       string                          `json:"prTitle,omitempty"`
	PRBody        string                          `json:"prBody,omitempty"`
	CommitMessage string                          `json:"commitMessage,omitempty"`
	// Selection is the subset of captured items the operator chose to
	// export. Empty selection means "export all" (no filter applied).
	// Identities are matched against the freshly-discovered state at
	// export time, so a selection from a stale preview that no longer
	// exists on the cluster is silently dropped (recoverable: operator
	// re-previews to see the current state).
	Selection []gitops.CapturedItemIdentity `json:"selection,omitempty"`
}

// exportClusterResponse mirrors the per-addon ExportAddonResponse
// shape so the console can consume both via similar paths.
type exportClusterResponse struct {
	Success    bool     `json:"success"`
	Message    string   `json:"message"`
	Mode       string   `json:"mode,omitempty"`       // "direct-push" or "feature-branch-mr"
	Branch     string   `json:"branch,omitempty"`     // branch the export wrote to
	CommitSHA  string   `json:"commitSha,omitempty"`
	PRURL      string   `json:"prUrl,omitempty"`
	PRNumber   int      `json:"prNumber,omitempty"`
	FilesCount int      `json:"filesCount,omitempty"`
	Files      []string `json:"files,omitempty"`
}

// PreviewCluster handles POST /clusters/{namespace}/{name}/gitops/preview-cluster.
func (h *GitOpsHandler) PreviewCluster(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	user := auth.UserFromContext(ctx)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	cluster, err := h.k8sClient.GetTenantCluster(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}
	if err := h.checkOperatePermission(user, cluster, "preview cluster export from"); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	req := previewClusterRequest{}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
	}
	env := req.Env
	if env == "" {
		env = "prd"
	}

	kubeconfig, err := h.k8sClient.GetTenantKubeconfig(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get cluster kubeconfig")
		return
	}

	resp, err := h.runClusterPreview(ctx, kubeconfig, name, env, req.ClusterName)
	if err != nil {
		h.logger.Error("Cluster preview failed", "cluster", name, "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ExportCluster handles POST /clusters/{namespace}/{name}/gitops/export-cluster.
func (h *GitOpsHandler) ExportCluster(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	user := auth.UserFromContext(ctx)
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	cluster, err := h.k8sClient.GetTenantCluster(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("cluster not found: %v", err))
		return
	}
	if err := h.checkOperatePermission(user, cluster, "export cluster from"); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	var req exportClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Repository == "" {
		writeError(w, http.StatusBadRequest, "Repository is required")
		return
	}
	if req.Branch == "" {
		req.Branch = "main"
	}
	env := req.Env
	if env == "" {
		env = "prd"
	}

	kubeconfig, err := h.k8sClient.GetTenantKubeconfig(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get cluster kubeconfig")
		return
	}

	gp, err := h.getGitClient(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp, err := h.runClusterExport(ctx, kubeconfig, gp, name, env, req)
	if err != nil {
		h.logger.Error("Cluster export failed", "cluster", name, "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// PreviewManagementCluster handles POST /management/gitops/preview-cluster.
func (h *GitOpsHandler) PreviewManagementCluster(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	req := previewClusterRequest{}
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
	}
	env := req.Env
	if env == "" {
		env = "prd"
	}

	kubeconfig, err := h.k8sClient.GetManagementKubeconfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get management cluster kubeconfig")
		return
	}

	resp, err := h.runClusterPreview(ctx, kubeconfig, "management", env, req.ClusterName)
	if err != nil {
		h.logger.Error("Management cluster preview failed", "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// ExportManagementCluster handles POST /management/gitops/export-cluster.
func (h *GitOpsHandler) ExportManagementCluster(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req exportClusterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Repository == "" {
		writeError(w, http.StatusBadRequest, "Repository is required")
		return
	}
	if req.Branch == "" {
		req.Branch = "main"
	}
	env := req.Env
	if env == "" {
		env = "prd"
	}

	kubeconfig, err := h.k8sClient.GetManagementKubeconfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get management cluster kubeconfig")
		return
	}

	gp, err := h.getGitClient(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	resp, err := h.runClusterExport(ctx, kubeconfig, gp, "management", env, req)
	if err != nil {
		h.logger.Error("Management cluster export failed", "error", err)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// runClusterPreview is the shared discovery + layout + coverage
// pipeline that produces a PreviewClusterResponse. Called by both
// tenant and mgmt preview handlers with the appropriate kubeconfig.
//
// clusterNameOverride lets the caller force a specific name (operator
// override from the modal). When empty, the name is derived from the
// cluster's Flux root path with fallback to fallbackName.
//
// Returns errors as plain strings; callers translate to HTTP status.
func (h *GitOpsHandler) runClusterPreview(ctx context.Context, kubeconfig []byte, fallbackName, env, clusterNameOverride string) (*gitops.PreviewClusterResponse, error) {
	addonDefList, err := h.k8sClient.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		h.logger.Warn("Failed to list AddonDefinitions", "error", err)
		addonDefList = &butlerv1alpha1.AddonDefinitionList{}
	}

	helm, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefList.Items)
	if err != nil {
		return nil, fmt.Errorf("Failed to discover Helm releases: %w", err)
	}
	if helm.GitOpsEngine == nil || !helm.GitOpsEngine.Installed {
		return nil, fmt.Errorf("No GitOps engine (Flux/ArgoCD) installed on this cluster — cluster export requires Flux to be enabled")
	}

	clusterName := resolveClusterName(clusterNameOverride, helm.GitOpsEngine, fallbackName)

	native, err := gitops.DiscoverNativeResources(ctx, kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to discover native resources: %w", err)
	}

	nsNames := collectNamespaceNames(helm)
	nsMeta, err := gitops.DiscoverNamespaceMetadata(ctx, kubeconfig, nsNames)
	if err != nil {
		h.logger.Warn("Namespace metadata discovery failed; emitting bare namespaces", "error", err)
		nsMeta = gitops.NamespaceMetadataMap{}
	}

	tree, err := gitops.GenerateLayoutV2(gitops.ExportInput{
		ClusterName:   clusterName,
		Env:           env,
		Helm:          helm,
		Native:        native,
		NamespaceMeta: nsMeta,
	})
	if err != nil {
		return nil, fmt.Errorf("Failed to generate layout: %w", err)
	}

	var nativeItems []*gitops.DiscoveredNative
	if native != nil {
		nativeItems = native.Items
	}
	var inventoryWalk *gitops.InventoryWalkResult
	if native != nil {
		inventoryWalk = native.InventoryWalk
	}

	report := gitops.BuildCoverage(gitops.CoverageInput{
		ClusterName:   clusterName,
		Env:           env,
		EmittedFiles:  tree,
		Helm:          helm,
		Inventory:     inventoryWalk,
		NativeResults: nativeItems,
		NamespaceMeta: nsMeta,
	})

	// MarshalCoverage emits coverage.yaml at the tree root so the
	// preview's file tree mirrors what a real export would commit.
	covYAML, err := gitops.MarshalCoverage(report)
	if err != nil {
		return nil, fmt.Errorf("Failed to marshal coverage: %w", err)
	}
	tree["coverage.yaml"] = covYAML

	// Convert []byte file contents to string for JSON response.
	files := make(map[string]string, len(tree))
	for path, content := range tree {
		files[path] = string(content)
	}

	resp := gitops.BuildClusterPreview(files, report, helm)
	resp.ClusterName = clusterName
	gitops.SortCapturedItems(resp.Coverage.Captured)
	gitops.SortCapturedItems(resp.Coverage.FluxSelfManagement)
	return resp, nil
}

// runClusterExport extends the preview pipeline with selection
// filtering and git push via RunExportV2. Returns the
// exportClusterResponse the handler writes to the wire.
//
// fallbackName is the tenant/mgmt name; the actual cluster name used
// in the emitted layout is resolved via override > Flux root path >
// fallback.
func (h *GitOpsHandler) runClusterExport(
	ctx context.Context,
	kubeconfig []byte,
	gp gitops.GitProvider,
	fallbackName, env string,
	req exportClusterRequest,
) (*exportClusterResponse, error) {
	addonDefList, err := h.k8sClient.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		h.logger.Warn("Failed to list AddonDefinitions", "error", err)
		addonDefList = &butlerv1alpha1.AddonDefinitionList{}
	}

	helm, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefList.Items)
	if err != nil {
		return nil, fmt.Errorf("Failed to discover Helm releases: %w", err)
	}
	if helm.GitOpsEngine == nil || !helm.GitOpsEngine.Installed {
		return nil, fmt.Errorf("No GitOps engine installed on this cluster")
	}

	clusterName := resolveClusterName(req.ClusterName, helm.GitOpsEngine, fallbackName)

	native, err := gitops.DiscoverNativeResources(ctx, kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("Failed to discover native resources: %w", err)
	}

	// Apply selection filter if the operator chose a subset in the
	// preview. Empty selection = export all (no filter applied).
	helm = gitops.FilterHelmDiscoveryBySelection(helm, req.Selection)
	native = gitops.FilterNativeBySelection(native, req.Selection)

	nsNames := collectNamespaceNames(helm)
	nsMeta, err := gitops.DiscoverNamespaceMetadata(ctx, kubeconfig, nsNames)
	if err != nil {
		h.logger.Warn("Namespace metadata discovery failed; emitting bare namespaces", "error", err)
		nsMeta = gitops.NamespaceMetadataMap{}
	}

	owner, repo, err := gitops.ParseRepoFullName(req.Repository)
	if err != nil {
		return nil, fmt.Errorf("Invalid repository format: %w", err)
	}

	commitMessage := req.CommitMessage
	if commitMessage == "" {
		commitMessage = fmt.Sprintf("export cluster %s (v2)", clusterName)
	}
	prTitle := req.PRTitle
	if prTitle == "" {
		prTitle = fmt.Sprintf("Export cluster %s to GitOps", clusterName)
	}

	result, err := gitops.RunExportV2(ctx, gp, gitops.ExportV2Request{
		ClusterName:   clusterName,
		Env:           env,
		Helm:          helm,
		Native:        native,
		NamespaceMeta: nsMeta,
		Owner:         owner,
		Repo:          repo,
		Branch:        req.Branch,
		CommitMessage: commitMessage,
		PRTitle:       prTitle,
		PRBody:        req.PRBody,
		ForceMRPath:   req.CreatePR,
	})
	if err != nil {
		return nil, fmt.Errorf("Export failed: %w", err)
	}

	return &exportClusterResponse{
		Success:    true,
		Message:    fmt.Sprintf("Exported cluster %s at %s", clusterName, time.Now().UTC().Format(time.RFC3339)),
		Mode:       result.Mode,
		Branch:     result.Branch,
		CommitSHA:  result.CommitSHA,
		PRURL:      result.PRURL,
		PRNumber:   result.PRNumber,
		FilesCount: result.FilesCount,
		Files:      result.Files,
	}, nil
}

// collectNamespaceNames mirrors the cmd/gitops-export-v2 dev CLI's
// helper: collect the set of namespaces the Helm releases target so
// DiscoverNamespaceMetadata can fetch their labels/annotations.
func collectNamespaceNames(hr *gitops.DiscoveryResult) map[string]bool {
	out := map[string]bool{}
	if hr == nil {
		return out
	}
	for _, r := range hr.Matched {
		if r.Namespace != "" {
			out[r.Namespace] = true
		}
	}
	for _, r := range hr.Unmatched {
		if r.Namespace != "" {
			out[r.Namespace] = true
		}
	}
	return out
}
