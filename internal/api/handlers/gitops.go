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
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"

	butlerv1alpha1 "github.com/butlerdotdev/butler-api/api/v1alpha1"
	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/gitops"
	"github.com/butlerdotdev/butler-server/internal/k8s"
	"github.com/go-chi/chi/v5"
)

// GitOpsHandler handles GitOps-related API requests.
type GitOpsHandler struct {
	k8sClient *k8s.Client
	config    *config.Config
	logger    *slog.Logger
}

// NewGitOpsHandler creates a new GitOps handler.
func NewGitOpsHandler(k8sClient *k8s.Client, cfg *config.Config, logger *slog.Logger) *GitOpsHandler {
	return &GitOpsHandler{
		k8sClient: k8sClient,
		config:    cfg,
		logger:    logger,
	}
}

// GetConfig returns the current Git provider configuration.
func (h *GitOpsHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	gitConfig, err := h.getGitProviderConfig(ctx)
	if err != nil {
		h.logger.Debug("Git provider not configured", "error", err)
		writeJSON(w, http.StatusOK, gitops.GitProviderConfigResponse{
			Configured: false,
		})
		return
	}

	client, err := h.createGitClient(ctx, gitConfig)
	if err != nil {
		h.logger.Warn("Failed to create Git client", "error", err)
		writeJSON(w, http.StatusOK, gitops.GitProviderConfigResponse{
			Configured:   true,
			Type:         gitConfig.Type,
			URL:          gitConfig.URL,
			Organization: gitConfig.Organization,
		})
		return
	}

	validation, err := client.ValidateToken(ctx)
	if err != nil {
		h.logger.Warn("Token validation failed", "error", err)
	}

	resp := gitops.GitProviderConfigResponse{
		Configured:   true,
		Type:         gitConfig.Type,
		URL:          gitConfig.URL,
		Organization: gitConfig.Organization,
	}
	if validation != nil && validation.Valid {
		resp.Username = validation.Username
	}

	writeJSON(w, http.StatusOK, resp)
}

// SaveConfig saves Git provider configuration.
func (h *GitOpsHandler) SaveConfig(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req gitops.SaveGitProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Type == "" {
		writeError(w, http.StatusBadRequest, "Provider type is required")
		return
	}
	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "Token is required")
		return
	}

	if req.URL == "" {
		switch req.Type {
		case "github":
			req.URL = "https://api.github.com"
		case "gitlab":
			req.URL = "https://gitlab.com"
		case "bitbucket":
			req.URL = "https://api.bitbucket.org/2.0"
		}
	}

	client, err := gitops.NewProvider(gitops.ProviderConfig{
		Type:         gitops.ProviderType(req.Type),
		Token:        req.Token,
		URL:          req.URL,
		Organization: req.Organization,
	})
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid provider configuration: %v", err))
		return
	}

	validation, err := client.ValidateToken(ctx)
	if err != nil || !validation.Valid {
		writeError(w, http.StatusBadRequest, "Token validation failed - check token permissions")
		return
	}

	secretName := "butler-gitops-credentials"
	secretData := map[string][]byte{
		"token": []byte(req.Token),
	}

	if err := h.k8sClient.CreateOrUpdateSecret(ctx, h.config.SystemNamespace, secretName, secretData); err != nil {
		h.logger.Error("Failed to create secret", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to store credentials")
		return
	}

	configData := map[string]string{
		"type":         req.Type,
		"url":          req.URL,
		"organization": req.Organization,
		"secretName":   secretName,
	}

	if err := h.k8sClient.CreateOrUpdateConfigMap(ctx, h.config.SystemNamespace, "butler-gitops-config", configData); err != nil {
		h.logger.Error("Failed to create configmap", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to save configuration")
		return
	}

	h.logger.Info("Git provider configured",
		"type", req.Type,
		"url", req.URL,
		"organization", req.Organization,
		"username", validation.Username,
	)

	writeJSON(w, http.StatusOK, gitops.GitProviderConfigResponse{
		Configured:   true,
		Type:         req.Type,
		URL:          req.URL,
		Organization: req.Organization,
		Username:     validation.Username,
	})
}

// ListRepositories lists repositories from the configured provider.
func (h *GitOpsHandler) ListRepositories(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	client, err := h.getGitClient(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	repos, err := client.ListRepositories(ctx)
	if err != nil {
		h.logger.Error("Failed to list repositories", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to list repositories")
		return
	}

	writeJSON(w, http.StatusOK, repos)
}

// ListBranches lists branches for a repository.
func (h *GitOpsHandler) ListBranches(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	owner := chi.URLParam(r, "owner")
	repo := chi.URLParam(r, "repo")

	if owner == "" || repo == "" {
		writeError(w, http.StatusBadRequest, "Owner and repo are required")
		return
	}

	client, err := h.getGitClient(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	branches, err := client.ListBranches(ctx, owner, repo)
	if err != nil {
		h.logger.Error("Failed to list branches", "error", err, "owner", owner, "repo", repo)
		writeError(w, http.StatusInternalServerError, "Failed to list branches")
		return
	}

	writeJSON(w, http.StatusOK, branches)
}

// EnableGitOps enables GitOps on a cluster.
func (h *GitOpsHandler) EnableGitOps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	var req gitops.EnableGitOpsRequest
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
	if req.Path == "" {
		req.Path = fmt.Sprintf("clusters/%s", name)
	}
	if req.Provider == "" {
		req.Provider = "github"
	}

	h.logger.Info("Enabling GitOps on cluster",
		"namespace", namespace,
		"name", name,
		"repository", req.Repository,
		"branch", req.Branch,
		"path", req.Path,
	)

	kubeconfig, err := h.k8sClient.GetTenantKubeconfig(ctx, namespace, name)
	if err != nil {
		h.logger.Error("Failed to get kubeconfig", "error", err, "cluster", name)
		writeError(w, http.StatusInternalServerError, "Failed to get cluster kubeconfig")
		return
	}

	token, err := h.getGitToken(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	owner, repoName, err := gitops.ParseRepoFullName(req.Repository)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !gitops.IsFluxCLIAvailable() {
		h.logger.Error("Flux CLI not available")
		writeError(w, http.StatusInternalServerError, "Flux CLI not installed on server")
		return
	}

	bootstrapper := gitops.NewFluxBootstrapper(kubeconfig)
	result, err := bootstrapper.Bootstrap(ctx, gitops.BootstrapOptions{
		Provider:        req.Provider,
		Owner:           owner,
		Repository:      repoName,
		Branch:          req.Branch,
		Path:            req.Path,
		Token:           token,
		Private:         req.Private,
		Personal:        true,
		Cluster:         name,
		ComponentsExtra: req.ComponentsExtra,
	})
	if err != nil {
		h.logger.Error("Flux bootstrap failed", "error", err, "cluster", name)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Flux bootstrap failed: %v", err))
		return
	}

	tc, err := h.k8sClient.GetTenantClusterTyped(ctx, namespace, name)
	if err != nil {
		h.logger.Warn("Failed to get TenantCluster for status update", "error", err)
	} else {
		tc.Spec.Addons.GitOps = &butlerv1alpha1.GitOpsSpec{
			Provider: "fluxcd",
			Version:  result.Version,
			Repository: &butlerv1alpha1.GitRepositorySpec{
				URL:    fmt.Sprintf("https://github.com/%s", req.Repository),
				Branch: req.Branch,
				Path:   req.Path,
			},
		}

		if _, err := h.k8sClient.UpdateTenantClusterTyped(ctx, tc); err != nil {
			h.logger.Warn("Failed to update TenantCluster GitOps status", "error", err)
		}
	}

	h.logger.Info("GitOps enabled successfully",
		"cluster", name,
		"repository", req.Repository,
		"fluxVersion", result.Version,
	)

	writeJSON(w, http.StatusOK, gitops.EnableGitOpsResponse{
		Success:       true,
		Message:       "GitOps enabled successfully",
		RepositoryURL: fmt.Sprintf("https://github.com/%s", req.Repository),
		Provider:      "fluxcd",
		Version:       result.Version,
		Path:          req.Path,
	})
}

// GetStatus returns the GitOps status for a cluster.
func (h *GitOpsHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	tc, err := h.k8sClient.GetTenantClusterTyped(ctx, namespace, name)
	if err != nil {
		h.logger.Error("Failed to get TenantCluster", "error", err)
		writeError(w, http.StatusNotFound, "Cluster not found")
		return
	}

	if tc.Spec.Addons.GitOps == nil || tc.Spec.Addons.GitOps.Repository == nil {
		writeJSON(w, http.StatusOK, gitops.GitOpsStatusResponse{
			Enabled: false,
		})
		return
	}

	gitopsSpec := tc.Spec.Addons.GitOps
	repoURL := gitopsSpec.Repository.URL
	branch := gitopsSpec.Repository.Branch
	path := gitopsSpec.Repository.Path
	provider := gitopsSpec.Provider

	kubeconfig, err := h.k8sClient.GetTenantKubeconfig(ctx, namespace, name)
	if err != nil {
		h.logger.Warn("Failed to get kubeconfig for status check", "error", err)
		writeJSON(w, http.StatusOK, gitops.GitOpsStatusResponse{
			Enabled:    true,
			Provider:   provider,
			Repository: repoURL,
			Branch:     branch,
			Path:       path,
			Status:     "Unknown",
		})
		return
	}

	bootstrapper := gitops.NewFluxBootstrapper(kubeconfig)
	fluxStatus, err := bootstrapper.GetStatus(ctx)
	if err != nil {
		h.logger.Warn("Failed to get Flux status", "error", err)
	}

	status := "Unknown"
	fluxVersion := ""
	if fluxStatus != nil {
		fluxVersion = fluxStatus.Version
		if fluxStatus.Ready {
			status = "Healthy"
		} else if fluxStatus.Installed {
			status = "Degraded"
		}
	}

	writeJSON(w, http.StatusOK, gitops.GitOpsStatusResponse{
		Enabled:     true,
		Provider:    provider,
		Repository:  repoURL,
		Branch:      branch,
		Path:        path,
		Status:      status,
		FluxVersion: fluxVersion,
	})
}

// DisableGitOps disables GitOps on a cluster.
func (h *GitOpsHandler) DisableGitOps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	h.logger.Info("Disabling GitOps on cluster",
		"namespace", namespace,
		"name", name,
	)

	kubeconfig, err := h.k8sClient.GetTenantKubeconfig(ctx, namespace, name)
	if err != nil {
		h.logger.Error("Failed to get kubeconfig", "error", err, "cluster", name)
		writeError(w, http.StatusInternalServerError, "Failed to get cluster kubeconfig")
		return
	}

	if !gitops.IsFluxCLIAvailable() {
		h.logger.Error("Flux CLI not available")
		writeError(w, http.StatusInternalServerError, "Flux CLI not installed on server")
		return
	}

	bootstrapper := gitops.NewFluxBootstrapper(kubeconfig)
	if err := bootstrapper.Uninstall(ctx); err != nil {
		h.logger.Error("Flux uninstall failed", "error", err, "cluster", name)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Flux uninstall failed: %v", err))
		return
	}

	tc, err := h.k8sClient.GetTenantClusterTyped(ctx, namespace, name)
	if err != nil {
		h.logger.Warn("Failed to get TenantCluster for status update", "error", err)
	} else {
		tc.Spec.Addons.GitOps = nil

		if _, err := h.k8sClient.UpdateTenantClusterTyped(ctx, tc); err != nil {
			h.logger.Warn("Failed to update TenantCluster GitOps status", "error", err)
		}
	}

	h.logger.Info("GitOps disabled successfully", "cluster", name)

	writeJSON(w, http.StatusOK, gitops.DisableGitOpsResponse{
		Success: true,
		Message: "GitOps disabled successfully",
	})
}

// ExportAddon exports an addon to GitOps.
func (h *GitOpsHandler) ExportAddon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	var req gitops.ExportAddonRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.AddonName == "" {
		writeError(w, http.StatusBadRequest, "Addon name is required")
		return
	}

	kubeconfig, err := h.k8sClient.GetTenantKubeconfig(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get cluster kubeconfig")
		return
	}

	addonDefList, err := h.k8sClient.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		addonDefList = &butlerv1alpha1.AddonDefinitionList{}
	}

	discoveryResult, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefList.Items)
	if err != nil {
		h.logger.Error("Failed to check GitOps status", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to check GitOps status")
		return
	}

	if discoveryResult.GitOpsEngine == nil || !discoveryResult.GitOpsEngine.Installed {
		writeError(w, http.StatusBadRequest, "No GitOps engine (Flux/ArgoCD) installed on this cluster")
		return
	}

	tc, err := h.k8sClient.GetTenantClusterTyped(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, "Cluster not found")
		return
	}

	var repoURL, branch string

	if tc.Spec.Addons.GitOps != nil && tc.Spec.Addons.GitOps.Repository != nil {
		repoURL = tc.Spec.Addons.GitOps.Repository.URL
		branch = tc.Spec.Addons.GitOps.Repository.Branch
	} else {
		if req.Repository == "" {
			writeError(w, http.StatusBadRequest, "Repository is required (GitOps installed but not configured in Butler)")
			return
		}
		repoURL = req.Repository
		branch = req.Branch
	}

	if branch == "" {
		branch = "main"
	}

	addonDef, err := h.k8sClient.GetAddonDefinitionTyped(ctx, req.AddonName)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("Addon definition not found: %s", req.AddonName))
		return
	}

	var targetPath string
	if addonDef.Spec.Platform {
		targetPath = fmt.Sprintf("clusters/%s/infrastructure/%s", name, req.AddonName)
	} else {
		targetPath = fmt.Sprintf("clusters/%s/apps/%s", name, req.AddonName)
	}

	h.logger.Info("Exporting addon to GitOps",
		"cluster", name,
		"addon", req.AddonName,
		"path", targetPath,
		"platform", addonDef.Spec.Platform,
	)

	chartName := addonDef.Spec.Chart.Name
	chartVersion := addonDef.Spec.Chart.DefaultVersion
	chartRepo := addonDef.Spec.Chart.Repository
	targetNamespace := addonDef.Spec.Defaults.Namespace
	createNamespace := addonDef.Spec.Defaults.CreateNamespace

	if targetNamespace == "" {
		targetNamespace = req.AddonName
	}

	generator := gitops.NewManifestGenerator()
	manifests, err := generator.GenerateAddonManifests(gitops.HelmReleaseConfig{
		Name:            req.AddonName,
		Namespace:       "flux-system",
		ChartName:       chartName,
		ChartVersion:    chartVersion,
		RepoURL:         chartRepo,
		RepoName:        strings.ToLower(strings.ReplaceAll(req.AddonName, "-", "")),
		Values:          req.Values,
		CreateNamespace: createNamespace,
		TargetNamespace: targetNamespace,
	})
	if err != nil {
		h.logger.Error("Failed to generate manifests", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to generate manifests")
		return
	}

	client, err := h.getGitClient(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid repository URL: %v", err))
		return
	}

	var files []gitops.FileCommit
	var fileNames []string
	for filename, content := range manifests {
		path := fmt.Sprintf("%s/%s", targetPath, filename)
		files = append(files, gitops.FileCommit{
			Path:    path,
			Content: content,
		})
		fileNames = append(fileNames, path)
	}

	commitMessage := fmt.Sprintf("Add %s addon via Butler GitOps export", req.AddonName)

	if req.CreatePR {
		prBranch := fmt.Sprintf("butler/add-%s-%s", req.AddonName, randomSuffix())

		baseSHA, err := client.GetBranchSHA(ctx, owner, repo, branch)
		if err != nil {
			h.logger.Error("Failed to get branch SHA", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to get branch")
			return
		}

		if err := client.CreateBranch(ctx, owner, repo, prBranch, baseSHA); err != nil {
			h.logger.Error("Failed to create branch", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to create branch")
			return
		}

		_, err = client.CreateOrUpdateFiles(ctx, owner, repo, prBranch, commitMessage, files)
		if err != nil {
			h.logger.Error("Failed to commit files", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		prTitle := req.PRTitle
		if prTitle == "" {
			prTitle = fmt.Sprintf("Add %s addon", req.AddonName)
		}
		prBody := req.PRBody
		if prBody == "" {
			prBody = fmt.Sprintf("This PR adds the %s addon to the cluster.\n\nExported via Butler Console.", req.AddonName)
		}

		pr, err := client.CreatePullRequest(ctx, owner, repo, prTitle, prBody, prBranch, branch)
		if err != nil {
			h.logger.Error("Failed to create PR", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to create pull request")
			return
		}

		h.logger.Info("Created PR for addon export",
			"addon", req.AddonName,
			"pr", pr.Number,
			"url", pr.HTMLURL,
		)

		writeJSON(w, http.StatusOK, gitops.ExportAddonResponse{
			Success:  true,
			Message:  "Pull request created successfully",
			Files:    fileNames,
			PRURL:    pr.HTMLURL,
			PRNumber: pr.Number,
		})
	} else {
		result, err := client.CreateOrUpdateFiles(ctx, owner, repo, branch, commitMessage, files)
		if err != nil {
			h.logger.Error("Failed to commit files", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		h.logger.Info("Committed addon export",
			"addon", req.AddonName,
			"commit", result.SHA,
		)

		writeJSON(w, http.StatusOK, gitops.ExportAddonResponse{
			Success:   true,
			Message:   "Addon exported successfully",
			Files:     fileNames,
			CommitSHA: result.SHA,
		})
	}
}

// ExportRelease exports a single installed Helm release to GitOps.
func (h *GitOpsHandler) ExportRelease(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	var req struct {
		ReleaseName      string `json:"releaseName"`
		ReleaseNamespace string `json:"releaseNamespace"`
		Repository       string `json:"repository"`
		Branch           string `json:"branch"`
		Path             string `json:"path"`
		CreatePR         bool   `json:"createPR"`
		PRTitle          string `json:"prTitle,omitempty"`
		HelmRepoURL      string `json:"helmRepoUrl,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.ReleaseName == "" {
		writeError(w, http.StatusBadRequest, "Release name is required")
		return
	}

	if req.Repository == "" {
		writeError(w, http.StatusBadRequest, "Repository is required")
		return
	}

	h.logger.Info("Exporting release to GitOps",
		"cluster", name,
		"release", req.ReleaseName,
		"namespace", req.ReleaseNamespace,
		"repository", req.Repository,
	)

	kubeconfig, err := h.k8sClient.GetTenantKubeconfig(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get cluster kubeconfig")
		return
	}

	addonDefList, err := h.k8sClient.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		h.logger.Warn("Failed to list AddonDefinitions", "error", err)
		addonDefList = &butlerv1alpha1.AddonDefinitionList{}
	}

	discoveryResult, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefList.Items)
	if err != nil {
		h.logger.Error("Failed to discover releases", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to discover releases")
		return
	}

	if discoveryResult.GitOpsEngine == nil || !discoveryResult.GitOpsEngine.Installed {
		writeError(w, http.StatusBadRequest, "No GitOps engine (Flux/ArgoCD) installed on this cluster")
		return
	}

	var release *gitops.DiscoveredRelease
	releaseKey := fmt.Sprintf("%s/%s", req.ReleaseNamespace, req.ReleaseName)

	for i := range discoveryResult.Matched {
		key := fmt.Sprintf("%s/%s", discoveryResult.Matched[i].Namespace, discoveryResult.Matched[i].Name)
		if key == releaseKey {
			release = discoveryResult.Matched[i]
			break
		}
	}
	if release == nil {
		for i := range discoveryResult.Unmatched {
			key := fmt.Sprintf("%s/%s", discoveryResult.Unmatched[i].Namespace, discoveryResult.Unmatched[i].Name)
			if key == releaseKey {
				release = discoveryResult.Unmatched[i]
				break
			}
		}
	}

	if release == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("Release %s not found", releaseKey))
		return
	}

	if release.RepoURL == "" && req.HelmRepoURL != "" {
		release.RepoURL = req.HelmRepoURL
	}

	if release.RepoURL == "" {
		writeError(w, http.StatusBadRequest, "Helm repository URL is required for this release")
		return
	}

	generator := gitops.NewManifestGenerator()
	manifests, err := generator.GenerateFromDiscoveredRelease(*release)
	if err != nil {
		h.logger.Error("Failed to generate manifests", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to generate manifests")
		return
	}

	client, err := h.getGitClient(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	owner, repo, err := gitops.ParseRepoFullName(req.Repository)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid repository format: %v", err))
		return
	}

	branch := req.Branch
	if branch == "" {
		branch = "main"
	}

	targetPath := req.Path
	if targetPath == "" {
		if release.Category == "infrastructure" {
			targetPath = fmt.Sprintf("clusters/%s/infrastructure/%s", name, release.Name)
		} else {
			targetPath = fmt.Sprintf("clusters/%s/apps/%s", name, release.Name)
		}
	} else {
		if !strings.HasSuffix(targetPath, "/"+release.Name) {
			targetPath = fmt.Sprintf("%s/%s", targetPath, release.Name)
		}
	}

	var files []gitops.FileCommit
	var fileNames []string
	for filename, content := range manifests {
		path := fmt.Sprintf("%s/%s", targetPath, filename)
		files = append(files, gitops.FileCommit{
			Path:    path,
			Content: content,
		})
		fileNames = append(fileNames, path)
	}

	commitMessage := fmt.Sprintf("Add %s to GitOps via Butler", release.Name)

	if req.CreatePR {
		prBranch := fmt.Sprintf("butler/add-%s-%s", release.Name, randomSuffix())

		baseSHA, err := client.GetBranchSHA(ctx, owner, repo, branch)
		if err != nil {
			h.logger.Error("Failed to get branch SHA", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to get branch")
			return
		}

		if err := client.CreateBranch(ctx, owner, repo, prBranch, baseSHA); err != nil {
			h.logger.Error("Failed to create branch", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to create branch")
			return
		}

		_, err = client.CreateOrUpdateFiles(ctx, owner, repo, prBranch, commitMessage, files)
		if err != nil {
			h.logger.Error("Failed to commit files", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		prTitle := req.PRTitle
		if prTitle == "" {
			prTitle = fmt.Sprintf("Add %s to GitOps", release.Name)
		}
		prBody := fmt.Sprintf("This PR adds %s to GitOps management.\n\nExported via Butler Console.", release.Name)

		pr, err := client.CreatePullRequest(ctx, owner, repo, prTitle, prBody, prBranch, branch)
		if err != nil {
			h.logger.Error("Failed to create PR", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to create pull request")
			return
		}

		h.logger.Info("Created PR for release export",
			"cluster", name,
			"release", release.Name,
			"pr", pr.Number,
			"url", pr.HTMLURL,
		)

		writeJSON(w, http.StatusOK, gitops.ExportAddonResponse{
			Success:  true,
			Message:  "Pull request created successfully",
			Files:    fileNames,
			PRURL:    pr.HTMLURL,
			PRNumber: pr.Number,
		})
	} else {
		result, err := client.CreateOrUpdateFiles(ctx, owner, repo, branch, commitMessage, files)
		if err != nil {
			h.logger.Error("Failed to commit files", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		h.logger.Info("Committed release to GitOps",
			"cluster", name,
			"release", release.Name,
			"sha", result.SHA,
		)

		writeJSON(w, http.StatusOK, gitops.ExportAddonResponse{
			Success:   true,
			Message:   "Committed successfully",
			Files:     fileNames,
			CommitSHA: result.SHA,
		})
	}
}

// ExportAllAddons exports all addons to GitOps (migrate).
func (h *GitOpsHandler) ExportAllAddons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	var req gitops.MigrateToGitOpsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	h.logger.Info("Migrating cluster to GitOps",
		"cluster", name,
		"releaseCount", len(req.Releases),
	)

	kubeconfig, err := h.k8sClient.GetTenantKubeconfig(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get cluster kubeconfig")
		return
	}

	addonDefList, err := h.k8sClient.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		h.logger.Warn("Failed to list AddonDefinitions, proceeding without matching", "error", err)
		addonDefList = &butlerv1alpha1.AddonDefinitionList{}
	}

	discoveryResult, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefList.Items)
	if err != nil {
		h.logger.Error("Failed to check GitOps status", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to check GitOps status")
		return
	}

	if discoveryResult.GitOpsEngine == nil || !discoveryResult.GitOpsEngine.Installed {
		writeError(w, http.StatusBadRequest, "No GitOps engine (Flux/ArgoCD) installed on this cluster")
		return
	}

	tc, err := h.k8sClient.GetTenantClusterTyped(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusNotFound, "Cluster not found")
		return
	}

	var repoURL, branch string

	if tc.Spec.Addons.GitOps != nil && tc.Spec.Addons.GitOps.Repository != nil {
		repoURL = tc.Spec.Addons.GitOps.Repository.URL
		branch = tc.Spec.Addons.GitOps.Repository.Branch
	} else {
		if req.Repository == "" {
			writeError(w, http.StatusBadRequest, "Repository is required (GitOps installed but not configured in Butler)")
			return
		}
		repoURL = req.Repository
		branch = req.Branch
	}

	if branch == "" {
		branch = "main"
	}

	releaseMap := make(map[string]*gitops.DiscoveredRelease)
	for i := range discoveryResult.Matched {
		key := fmt.Sprintf("%s/%s", discoveryResult.Matched[i].Namespace, discoveryResult.Matched[i].Name)
		releaseMap[key] = discoveryResult.Matched[i]
	}
	for i := range discoveryResult.Unmatched {
		key := fmt.Sprintf("%s/%s", discoveryResult.Unmatched[i].Namespace, discoveryResult.Unmatched[i].Name)
		releaseMap[key] = discoveryResult.Unmatched[i]
	}

	generator := gitops.NewManifestGenerator()
	var allFiles []gitops.FileCommit
	var fileNames []string
	migratedCount := 0

	for _, migration := range req.Releases {
		key := fmt.Sprintf("%s/%s", migration.Namespace, migration.Name)
		release, ok := releaseMap[key]
		if !ok {
			h.logger.Warn("Release not found", "release", key)
			continue
		}

		if migration.Category != "" {
			release.Category = migration.Category
		}

		if release.RepoURL == "" && migration.RepoURL != "" {
			release.RepoURL = migration.RepoURL
		}

		if release.RepoURL == "" {
			h.logger.Warn("Skipping release without repository URL", "release", release.Name)
			continue
		}

		manifests, err := generator.GenerateFromDiscoveredRelease(*release)
		if err != nil {
			h.logger.Warn("Failed to generate manifests for release", "release", release.Name, "error", err)
			continue
		}

		var basePath string
		if release.Category == "infrastructure" {
			basePath = fmt.Sprintf("clusters/%s/infrastructure", name)
		} else {
			basePath = fmt.Sprintf("clusters/%s/apps", name)
		}
		targetPath := fmt.Sprintf("%s/%s", basePath, release.Name)

		for filename, content := range manifests {
			path := fmt.Sprintf("%s/%s", targetPath, filename)
			allFiles = append(allFiles, gitops.FileCommit{
				Path:    path,
				Content: content,
			})
			fileNames = append(fileNames, path)
		}
		migratedCount++
	}

	if len(allFiles) == 0 {
		writeError(w, http.StatusBadRequest, "No releases selected for migration")
		return
	}

	client, err := h.getGitClient(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	owner, repo, err := parseGitHubURL(repoURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid repository URL: %v", err))
		return
	}

	commitMessage := fmt.Sprintf("Migrate %d releases to GitOps via Butler", migratedCount)

	if req.CreatePR {
		prBranch := fmt.Sprintf("butler/migrate-to-gitops-%s", randomSuffix())

		baseSHA, err := client.GetBranchSHA(ctx, owner, repo, branch)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to get branch")
			return
		}

		if err := client.CreateBranch(ctx, owner, repo, prBranch, baseSHA); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to create branch")
			return
		}

		_, err = client.CreateOrUpdateFiles(ctx, owner, repo, prBranch, commitMessage, allFiles)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		pr, err := client.CreatePullRequest(ctx, owner, repo,
			"Migrate releases to GitOps",
			fmt.Sprintf("This PR migrates %d Helm releases to GitOps management.\n\nMigrated via Butler Console.", migratedCount),
			prBranch, branch)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to create pull request")
			return
		}

		writeJSON(w, http.StatusOK, gitops.MigrateToGitOpsResponse{
			Success:       true,
			Message:       "Pull request created for migration",
			MigratedCount: migratedCount,
			Files:         fileNames,
			PRURL:         pr.HTMLURL,
		})
	} else {
		result, err := client.CreateOrUpdateFiles(ctx, owner, repo, branch, commitMessage, allFiles)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		writeJSON(w, http.StatusOK, gitops.MigrateToGitOpsResponse{
			Success:       true,
			Message:       "Migration committed successfully",
			MigratedCount: migratedCount,
			Files:         fileNames,
			CommitSHA:     result.SHA,
		})
	}
}

// DiscoverReleases discovers Helm releases on a cluster for migration.
func (h *GitOpsHandler) DiscoverReleases(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	h.logger.Info("Discovering Helm releases", "cluster", name)

	kubeconfig, err := h.k8sClient.GetTenantKubeconfig(ctx, namespace, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get cluster kubeconfig")
		return
	}

	addonDefList, err := h.k8sClient.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		h.logger.Warn("Failed to list AddonDefinitions, proceeding without matching", "error", err)
		addonDefList = &butlerv1alpha1.AddonDefinitionList{}
	}

	result, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefList.Items)
	if err != nil {
		h.logger.Error("Failed to discover releases", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to discover Helm releases")
		return
	}

	if result.GitOpsEngine != nil && result.GitOpsEngine.Installed {
		tc, err := h.k8sClient.GetTenantClusterTyped(ctx, namespace, name)
		if err == nil && tc.Spec.Addons.GitOps != nil && tc.Spec.Addons.GitOps.Repository != nil {
			repoURL := tc.Spec.Addons.GitOps.Repository.URL
			if owner, repo, err := gitops.ParseRepoURL(repoURL); err == nil {
				result.GitOpsEngine.Repository = fmt.Sprintf("%s/%s", owner, repo)
			}
			result.GitOpsEngine.Branch = tc.Spec.Addons.GitOps.Repository.Branch
			result.GitOpsEngine.Path = tc.Spec.Addons.GitOps.Repository.Path
		}

		if result.GitOpsEngine.Repository == "" {
			if fluxRepo, fluxBranch, fluxPath, err := gitops.GetFluxGitRepositoryConfig(ctx, kubeconfig); err == nil {
				if owner, repo, err := gitops.ParseRepoURL(fluxRepo); err == nil {
					result.GitOpsEngine.Repository = fmt.Sprintf("%s/%s", owner, repo)
				}
				result.GitOpsEngine.Branch = fluxBranch
				result.GitOpsEngine.Path = fluxPath
			}
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// GetManagementStatus returns GitOps status for the management cluster.
func (h *GitOpsHandler) GetManagementStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	kubeconfig, err := h.k8sClient.GetManagementKubeconfig()
	if err != nil {
		h.logger.Error("Failed to get management kubeconfig", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get management cluster kubeconfig")
		return
	}

	addonDefList, err := h.k8sClient.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		addonDefList = &butlerv1alpha1.AddonDefinitionList{}
	}

	discoveryResult, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefList.Items)
	if err != nil {
		h.logger.Warn("Failed to discover releases", "error", err)
	}

	if discoveryResult == nil || discoveryResult.GitOpsEngine == nil || !discoveryResult.GitOpsEngine.Installed {
		writeJSON(w, http.StatusOK, gitops.GitOpsStatusResponse{
			Enabled: false,
		})
		return
	}

	var repository, branch, path string
	if fluxRepo, fluxBranch, fluxPath, err := gitops.GetFluxGitRepositoryConfig(ctx, kubeconfig); err == nil {
		if owner, repo, err := gitops.ParseRepoURL(fluxRepo); err == nil {
			repository = fmt.Sprintf("%s/%s", owner, repo)
		}
		branch = fluxBranch
		path = fluxPath
	}

	writeJSON(w, http.StatusOK, gitops.GitOpsStatusResponse{
		Enabled:     true,
		Provider:    discoveryResult.GitOpsEngine.Provider,
		FluxVersion: discoveryResult.GitOpsEngine.Version,
		Repository:  repository,
		Branch:      branch,
		Path:        path,
		Status:      "Healthy",
	})
}

// EnableManagementGitOps enables GitOps on the management cluster.
func (h *GitOpsHandler) EnableManagementGitOps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req gitops.EnableGitOpsRequest
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
	if req.Path == "" {
		req.Path = "clusters/management"
	}

	h.logger.Info("Enabling GitOps on management cluster",
		"repository", req.Repository,
		"branch", req.Branch,
		"path", req.Path,
	)

	kubeconfig, err := h.k8sClient.GetManagementKubeconfig()
	if err != nil {
		h.logger.Error("Failed to get management kubeconfig", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get management cluster kubeconfig")
		return
	}

	token, err := h.getGitToken(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	owner, repoName, err := gitops.ParseRepoFullName(req.Repository)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !gitops.IsFluxCLIAvailable() {
		h.logger.Error("Flux CLI not available")
		writeError(w, http.StatusInternalServerError, "Flux CLI not installed on server")
		return
	}

	bootstrapper := gitops.NewFluxBootstrapper(kubeconfig)
	result, err := bootstrapper.Bootstrap(ctx, gitops.BootstrapOptions{
		Provider:   "github",
		Owner:      owner,
		Repository: repoName,
		Branch:     req.Branch,
		Path:       req.Path,
		Token:      token,
		Private:    req.Private,
		Personal:   true,
		Cluster:    "management",
	})
	if err != nil {
		h.logger.Error("Flux bootstrap failed", "error", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Flux bootstrap failed: %v", err))
		return
	}

	h.logger.Info("GitOps enabled on management cluster",
		"repository", req.Repository,
		"fluxVersion", result.Version,
	)

	writeJSON(w, http.StatusOK, gitops.EnableGitOpsResponse{
		Success:       true,
		Message:       "GitOps enabled on management cluster",
		RepositoryURL: fmt.Sprintf("https://github.com/%s", req.Repository),
		Provider:      "fluxcd",
		Version:       result.Version,
		Path:          req.Path,
	})
}

// DisableManagementGitOps disables GitOps on the management cluster.
func (h *GitOpsHandler) DisableManagementGitOps(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Info("Disabling GitOps on management cluster")

	kubeconfig, err := h.k8sClient.GetManagementKubeconfig()
	if err != nil {
		h.logger.Error("Failed to get management kubeconfig", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get management cluster kubeconfig")
		return
	}

	if !gitops.IsFluxCLIAvailable() {
		h.logger.Error("Flux CLI not available")
		writeError(w, http.StatusInternalServerError, "Flux CLI not installed on server")
		return
	}

	bootstrapper := gitops.NewFluxBootstrapper(kubeconfig)
	if err := bootstrapper.Uninstall(ctx); err != nil {
		h.logger.Error("Flux uninstall failed on management cluster", "error", err)
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("Flux uninstall failed: %v", err))
		return
	}

	h.logger.Info("GitOps disabled successfully on management cluster")

	writeJSON(w, http.StatusOK, gitops.DisableGitOpsResponse{
		Success: true,
		Message: "GitOps disabled on management cluster",
	})
}

// DiscoverManagementReleases discovers Helm releases on management cluster.
func (h *GitOpsHandler) DiscoverManagementReleases(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	h.logger.Info("Discovering Helm releases on management cluster")

	kubeconfig, err := h.k8sClient.GetManagementKubeconfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get management cluster kubeconfig")
		return
	}

	addonDefList, err := h.k8sClient.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		h.logger.Warn("Failed to list AddonDefinitions, proceeding without matching", "error", err)
		addonDefList = &butlerv1alpha1.AddonDefinitionList{}
	}

	result, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefList.Items)
	if err != nil {
		h.logger.Error("Failed to discover releases", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to discover Helm releases")
		return
	}

	if result.GitOpsEngine != nil && result.GitOpsEngine.Installed {
		if fluxRepo, fluxBranch, fluxPath, err := gitops.GetFluxGitRepositoryConfig(ctx, kubeconfig); err == nil {
			if owner, repo, err := gitops.ParseRepoURL(fluxRepo); err == nil {
				result.GitOpsEngine.Repository = fmt.Sprintf("%s/%s", owner, repo)
			}
			result.GitOpsEngine.Branch = fluxBranch
			result.GitOpsEngine.Path = fluxPath
		}
	}

	writeJSON(w, http.StatusOK, result)
}

// ExportManagementAddon exports a management addon to GitOps.
func (h *GitOpsHandler) ExportManagementAddon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		ReleaseName      string `json:"releaseName"`
		ReleaseNamespace string `json:"releaseNamespace"`
		Repository       string `json:"repository"`
		Branch           string `json:"branch"`
		Path             string `json:"path"`
		CreatePR         bool   `json:"createPR"`
		PRTitle          string `json:"prTitle,omitempty"`
		HelmRepoURL      string `json:"helmRepoUrl,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.ReleaseName == "" {
		writeError(w, http.StatusBadRequest, "Release name is required")
		return
	}

	if req.Repository == "" {
		writeError(w, http.StatusBadRequest, "Repository is required")
		return
	}

	h.logger.Info("Exporting management addon to GitOps",
		"release", req.ReleaseName,
		"namespace", req.ReleaseNamespace,
		"repository", req.Repository,
	)

	kubeconfig, err := h.k8sClient.GetManagementKubeconfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get management cluster kubeconfig")
		return
	}

	addonDefList, err := h.k8sClient.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		h.logger.Warn("Failed to list AddonDefinitions", "error", err)
		addonDefList = &butlerv1alpha1.AddonDefinitionList{}
	}

	discoveryResult, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefList.Items)
	if err != nil {
		h.logger.Error("Failed to discover releases", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to discover releases")
		return
	}

	if discoveryResult.GitOpsEngine == nil || !discoveryResult.GitOpsEngine.Installed {
		writeError(w, http.StatusBadRequest, "No GitOps engine (Flux/ArgoCD) installed on this cluster")
		return
	}

	var release *gitops.DiscoveredRelease
	releaseKey := fmt.Sprintf("%s/%s", req.ReleaseNamespace, req.ReleaseName)

	for i := range discoveryResult.Matched {
		key := fmt.Sprintf("%s/%s", discoveryResult.Matched[i].Namespace, discoveryResult.Matched[i].Name)
		if key == releaseKey {
			release = discoveryResult.Matched[i]
			break
		}
	}
	if release == nil {
		for i := range discoveryResult.Unmatched {
			key := fmt.Sprintf("%s/%s", discoveryResult.Unmatched[i].Namespace, discoveryResult.Unmatched[i].Name)
			if key == releaseKey {
				release = discoveryResult.Unmatched[i]
				break
			}
		}
	}

	if release == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("Release %s not found", releaseKey))
		return
	}

	if release.RepoURL == "" && req.HelmRepoURL != "" {
		release.RepoURL = req.HelmRepoURL
	}

	if release.RepoURL == "" {
		writeError(w, http.StatusBadRequest, "Helm repository URL is required for this release")
		return
	}

	generator := gitops.NewManifestGenerator()
	manifests, err := generator.GenerateFromDiscoveredRelease(*release)
	if err != nil {
		h.logger.Error("Failed to generate manifests", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to generate manifests")
		return
	}

	client, err := h.getGitClient(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	owner, repo, err := gitops.ParseRepoFullName(req.Repository)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid repository format: %v", err))
		return
	}

	branch := req.Branch
	if branch == "" {
		branch = "main"
	}

	targetPath := req.Path
	if targetPath == "" {
		if release.Category == "infrastructure" {
			targetPath = fmt.Sprintf("clusters/management/infrastructure/%s", release.Name)
		} else {
			targetPath = fmt.Sprintf("clusters/management/apps/%s", release.Name)
		}
	} else {
		targetPath = fmt.Sprintf("%s/%s", targetPath, release.Name)
	}

	var files []gitops.FileCommit
	var fileNames []string
	for filename, content := range manifests {
		path := fmt.Sprintf("%s/%s", targetPath, filename)
		files = append(files, gitops.FileCommit{
			Path:    path,
			Content: content,
		})
		fileNames = append(fileNames, path)
	}

	commitMessage := fmt.Sprintf("Add %s to GitOps via Butler", release.Name)

	if req.CreatePR {
		prBranch := fmt.Sprintf("butler/add-%s-%s", release.Name, randomSuffix())

		baseSHA, err := client.GetBranchSHA(ctx, owner, repo, branch)
		if err != nil {
			h.logger.Error("Failed to get branch SHA", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to get branch")
			return
		}

		if err := client.CreateBranch(ctx, owner, repo, prBranch, baseSHA); err != nil {
			h.logger.Error("Failed to create branch", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to create branch")
			return
		}

		_, err = client.CreateOrUpdateFiles(ctx, owner, repo, prBranch, commitMessage, files)
		if err != nil {
			h.logger.Error("Failed to commit files", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		prTitle := req.PRTitle
		if prTitle == "" {
			prTitle = fmt.Sprintf("Add %s to GitOps", release.Name)
		}
		prBody := fmt.Sprintf("This PR adds %s to GitOps management.\n\nExported via Butler Console.", release.Name)

		pr, err := client.CreatePullRequest(ctx, owner, repo, prTitle, prBody, prBranch, branch)
		if err != nil {
			h.logger.Error("Failed to create PR", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to create pull request")
			return
		}

		h.logger.Info("Created PR for management addon export",
			"release", release.Name,
			"pr", pr.Number,
			"url", pr.HTMLURL,
		)

		writeJSON(w, http.StatusOK, gitops.ExportAddonResponse{
			Success:  true,
			Message:  "Pull request created successfully",
			Files:    fileNames,
			PRURL:    pr.HTMLURL,
			PRNumber: pr.Number,
		})
	} else {
		result, err := client.CreateOrUpdateFiles(ctx, owner, repo, branch, commitMessage, files)
		if err != nil {
			h.logger.Error("Failed to commit files", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		h.logger.Info("Committed management addon to GitOps",
			"release", release.Name,
			"sha", result.SHA,
		)

		writeJSON(w, http.StatusOK, gitops.ExportAddonResponse{
			Success:   true,
			Message:   "Committed successfully",
			Files:     fileNames,
			CommitSHA: result.SHA,
		})
	}
}

// ExportManagementCatalogAddon exports an addon from the catalog to GitOps for the management cluster.
func (h *GitOpsHandler) ExportManagementCatalogAddon(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		AddonName  string                 `json:"addonName"`
		Repository string                 `json:"repository"`
		Branch     string                 `json:"branch"`
		TargetPath string                 `json:"targetPath,omitempty"`
		CreatePR   bool                   `json:"createPR"`
		PRTitle    string                 `json:"prTitle,omitempty"`
		Values     map[string]interface{} `json:"values,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.AddonName == "" {
		writeError(w, http.StatusBadRequest, "Addon name is required")
		return
	}

	if req.Repository == "" {
		writeError(w, http.StatusBadRequest, "Repository is required")
		return
	}

	h.logger.Info("Exporting management catalog addon to GitOps",
		"addon", req.AddonName,
		"repository", req.Repository,
	)

	kubeconfig, err := h.k8sClient.GetManagementKubeconfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get management cluster kubeconfig")
		return
	}

	addonDefList, err := h.k8sClient.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		addonDefList = &butlerv1alpha1.AddonDefinitionList{}
	}

	discoveryResult, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefList.Items)
	if err != nil {
		h.logger.Error("Failed to check GitOps status", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to check GitOps status")
		return
	}

	if discoveryResult.GitOpsEngine == nil || !discoveryResult.GitOpsEngine.Installed {
		writeError(w, http.StatusBadRequest, "No GitOps engine (Flux/ArgoCD) installed on the management cluster")
		return
	}

	addonDef, err := h.k8sClient.GetAddonDefinitionTyped(ctx, req.AddonName)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("Addon definition not found: %s", req.AddonName))
		return
	}

	targetPath := req.TargetPath
	if targetPath == "" {
		if addonDef.Spec.Platform {
			targetPath = fmt.Sprintf("clusters/management/infrastructure/%s", req.AddonName)
		} else {
			targetPath = fmt.Sprintf("clusters/management/apps/%s", req.AddonName)
		}
	}

	chartName := addonDef.Spec.Chart.Name
	chartVersion := addonDef.Spec.Chart.DefaultVersion
	chartRepo := addonDef.Spec.Chart.Repository
	targetNamespace := addonDef.Spec.Defaults.Namespace
	createNamespace := addonDef.Spec.Defaults.CreateNamespace

	if targetNamespace == "" {
		targetNamespace = req.AddonName
	}

	generator := gitops.NewManifestGenerator()
	manifests, err := generator.GenerateAddonManifests(gitops.HelmReleaseConfig{
		Name:            req.AddonName,
		Namespace:       "flux-system",
		ChartName:       chartName,
		ChartVersion:    chartVersion,
		RepoURL:         chartRepo,
		RepoName:        strings.ToLower(strings.ReplaceAll(req.AddonName, "-", "")),
		Values:          req.Values,
		CreateNamespace: createNamespace,
		TargetNamespace: targetNamespace,
	})
	if err != nil {
		h.logger.Error("Failed to generate manifests", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to generate manifests")
		return
	}

	client, err := h.getGitClient(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	parts := strings.Split(req.Repository, "/")
	if len(parts) != 2 {
		writeError(w, http.StatusBadRequest, "Invalid repository format, expected owner/repo")
		return
	}
	owner, repo := parts[0], parts[1]

	branch := req.Branch
	if branch == "" {
		branch = "main"
	}

	var files []gitops.FileCommit
	var fileNames []string
	for filename, content := range manifests {
		path := fmt.Sprintf("%s/%s", targetPath, filename)
		files = append(files, gitops.FileCommit{
			Path:    path,
			Content: content,
		})
		fileNames = append(fileNames, path)
	}

	commitMessage := fmt.Sprintf("Add %s addon to management cluster via Butler GitOps export", req.AddonName)

	if req.CreatePR {
		prBranch := fmt.Sprintf("butler/add-%s-%s", req.AddonName, randomSuffix())

		baseSHA, err := client.GetBranchSHA(ctx, owner, repo, branch)
		if err != nil {
			h.logger.Error("Failed to get branch SHA", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to get branch")
			return
		}

		if err := client.CreateBranch(ctx, owner, repo, prBranch, baseSHA); err != nil {
			h.logger.Error("Failed to create branch", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to create branch")
			return
		}

		_, err = client.CreateOrUpdateFiles(ctx, owner, repo, prBranch, commitMessage, files)
		if err != nil {
			h.logger.Error("Failed to commit files", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		prTitle := req.PRTitle
		if prTitle == "" {
			prTitle = fmt.Sprintf("Add %s addon to management cluster", req.AddonName)
		}
		prBody := fmt.Sprintf("This PR adds the %s addon to the management cluster.\n\nExported via Butler Console.", req.AddonName)

		pr, err := client.CreatePullRequest(ctx, owner, repo, prTitle, prBody, prBranch, branch)
		if err != nil {
			h.logger.Error("Failed to create PR", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to create pull request")
			return
		}

		writeJSON(w, http.StatusOK, gitops.ExportAddonResponse{
			Success: true,
			Message: "Pull request created",
			PRURL:   pr.HTMLURL,
			Files:   fileNames,
		})
	} else {
		result, err := client.CreateOrUpdateFiles(ctx, owner, repo, branch, commitMessage, files)
		if err != nil {
			h.logger.Error("Failed to commit files", "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		writeJSON(w, http.StatusOK, gitops.ExportAddonResponse{
			Success:   true,
			Message:   "Committed successfully",
			Files:     fileNames,
			CommitSHA: result.SHA,
		})
	}
}

// ExportAllManagementAddons exports all management addons to GitOps.
func (h *GitOpsHandler) ExportAllManagementAddons(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req gitops.MigrateToGitOpsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	h.logger.Info("Migrating management cluster to GitOps",
		"releaseCount", len(req.Releases),
		"repository", req.Repository,
	)

	if req.Repository == "" {
		writeError(w, http.StatusBadRequest, "Repository is required")
		return
	}

	kubeconfig, err := h.k8sClient.GetManagementKubeconfig()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get management cluster kubeconfig")
		return
	}

	addonDefList, err := h.k8sClient.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		h.logger.Warn("Failed to list AddonDefinitions", "error", err)
		addonDefList = &butlerv1alpha1.AddonDefinitionList{}
	}

	discoveryResult, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefList.Items)
	if err != nil {
		h.logger.Error("Failed to discover releases", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to discover releases")
		return
	}

	if discoveryResult.GitOpsEngine == nil || !discoveryResult.GitOpsEngine.Installed {
		writeError(w, http.StatusBadRequest, "No GitOps engine (Flux/ArgoCD) installed on this cluster")
		return
	}

	releaseMap := make(map[string]*gitops.DiscoveredRelease)
	for i := range discoveryResult.Matched {
		key := fmt.Sprintf("%s/%s", discoveryResult.Matched[i].Namespace, discoveryResult.Matched[i].Name)
		releaseMap[key] = discoveryResult.Matched[i]
	}
	for i := range discoveryResult.Unmatched {
		key := fmt.Sprintf("%s/%s", discoveryResult.Unmatched[i].Namespace, discoveryResult.Unmatched[i].Name)
		releaseMap[key] = discoveryResult.Unmatched[i]
	}

	generator := gitops.NewManifestGenerator()
	var allFiles []gitops.FileCommit
	var fileNames []string
	migratedCount := 0

	basePath := req.BasePath
	if basePath == "" {
		basePath = "clusters/management"
	}

	for _, migration := range req.Releases {
		key := fmt.Sprintf("%s/%s", migration.Namespace, migration.Name)
		release, ok := releaseMap[key]
		if !ok {
			h.logger.Warn("Release not found", "release", key)
			continue
		}

		if migration.Category != "" {
			release.Category = migration.Category
		}

		if release.RepoURL == "" && migration.RepoURL != "" {
			release.RepoURL = migration.RepoURL
		}

		if release.RepoURL == "" {
			h.logger.Warn("Skipping release without repository URL", "release", release.Name)
			continue
		}

		manifests, err := generator.GenerateFromDiscoveredRelease(*release)
		if err != nil {
			h.logger.Warn("Failed to generate manifests for release", "release", release.Name, "error", err)
			continue
		}

		var categoryPath string
		if release.Category == "infrastructure" {
			categoryPath = fmt.Sprintf("%s/infrastructure", basePath)
		} else {
			categoryPath = fmt.Sprintf("%s/apps", basePath)
		}
		targetPath := fmt.Sprintf("%s/%s", categoryPath, release.Name)

		for filename, content := range manifests {
			path := fmt.Sprintf("%s/%s", targetPath, filename)
			allFiles = append(allFiles, gitops.FileCommit{
				Path:    path,
				Content: content,
			})
			fileNames = append(fileNames, path)
		}
		migratedCount++
	}

	if len(allFiles) == 0 {
		writeError(w, http.StatusBadRequest, "No releases selected for migration")
		return
	}

	client, err := h.getGitClient(ctx)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	owner, repo, err := gitops.ParseRepoFullName(req.Repository)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("Invalid repository format: %v", err))
		return
	}

	branch := req.Branch
	if branch == "" {
		branch = "main"
	}

	commitMessage := fmt.Sprintf("Migrate %d management releases to GitOps via Butler", migratedCount)

	if req.CreatePR {
		prBranch := fmt.Sprintf("butler/migrate-mgmt-to-gitops-%s", randomSuffix())

		baseSHA, err := client.GetBranchSHA(ctx, owner, repo, branch)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to get branch")
			return
		}

		if err := client.CreateBranch(ctx, owner, repo, prBranch, baseSHA); err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to create branch")
			return
		}

		_, err = client.CreateOrUpdateFiles(ctx, owner, repo, prBranch, commitMessage, allFiles)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		prTitle := req.PRTitle
		if prTitle == "" {
			prTitle = fmt.Sprintf("Migrate %d management releases to GitOps", migratedCount)
		}

		pr, err := client.CreatePullRequest(ctx, owner, repo,
			prTitle,
			fmt.Sprintf("This PR migrates %d management cluster Helm releases to GitOps management.\n\nMigrated via Butler Console.", migratedCount),
			prBranch, branch)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to create pull request")
			return
		}

		h.logger.Info("Created PR for management migration",
			"migratedCount", migratedCount,
			"pr", pr.Number,
		)

		writeJSON(w, http.StatusOK, gitops.MigrateToGitOpsResponse{
			Success:       true,
			Message:       "Pull request created for migration",
			MigratedCount: migratedCount,
			Files:         fileNames,
			PRURL:         pr.HTMLURL,
		})
	} else {
		result, err := client.CreateOrUpdateFiles(ctx, owner, repo, branch, commitMessage, allFiles)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "Failed to commit files")
			return
		}

		h.logger.Info("Committed management migration",
			"migratedCount", migratedCount,
			"sha", result.SHA,
		)

		writeJSON(w, http.StatusOK, gitops.MigrateToGitOpsResponse{
			Success:       true,
			Message:       "Migration committed successfully",
			MigratedCount: migratedCount,
			Files:         fileNames,
			CommitSHA:     result.SHA,
		})
	}
}

// PreviewManifest previews generated manifests without committing.
func (h *GitOpsHandler) PreviewManifest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req struct {
		AddonName string                 `json:"addonName"`
		Values    map[string]interface{} `json:"values,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.AddonName == "" {
		writeError(w, http.StatusBadRequest, "Addon name is required")
		return
	}

	addonDef, err := h.k8sClient.GetAddonDefinitionTyped(ctx, req.AddonName)
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("Addon definition not found: %s", req.AddonName))
		return
	}

	chartName := addonDef.Spec.Chart.Name
	chartVersion := addonDef.Spec.Chart.DefaultVersion
	chartRepo := addonDef.Spec.Chart.Repository
	targetNamespace := addonDef.Spec.Defaults.Namespace
	createNamespace := addonDef.Spec.Defaults.CreateNamespace

	if targetNamespace == "" {
		targetNamespace = req.AddonName
	}

	generator := gitops.NewManifestGenerator()
	manifests, err := generator.GenerateAddonManifests(gitops.HelmReleaseConfig{
		Name:            req.AddonName,
		Namespace:       "flux-system",
		ChartName:       chartName,
		ChartVersion:    chartVersion,
		RepoURL:         chartRepo,
		RepoName:        strings.ToLower(strings.ReplaceAll(req.AddonName, "-", "")),
		Values:          req.Values,
		CreateNamespace: createNamespace,
		TargetNamespace: targetNamespace,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate manifests")
		return
	}

	preview := make(map[string]string)
	for filename, content := range manifests {
		preview[filename] = string(content)
	}

	writeJSON(w, http.StatusOK, preview)
}

// Helper methods

type gitProviderConfigInternal struct {
	Type         string
	URL          string
	Organization string
	SecretName   string
}

func (h *GitOpsHandler) getGitProviderConfig(ctx context.Context) (*gitProviderConfigInternal, error) {
	configMap, err := h.k8sClient.GetConfigMap(ctx, h.config.SystemNamespace, "butler-gitops-config")
	if err != nil {
		return nil, fmt.Errorf("git provider not configured")
	}

	return &gitProviderConfigInternal{
		Type:         configMap["type"],
		URL:          configMap["url"],
		Organization: configMap["organization"],
		SecretName:   configMap["secretName"],
	}, nil
}

func (h *GitOpsHandler) createGitClient(ctx context.Context, cfg *gitProviderConfigInternal) (gitops.GitProvider, error) {
	token, err := h.k8sClient.GetSecretValue(ctx, h.config.SystemNamespace, cfg.SecretName, "token")
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	return gitops.NewProvider(gitops.ProviderConfig{
		Type:         gitops.ProviderType(cfg.Type),
		Token:        token,
		URL:          cfg.URL,
		Organization: cfg.Organization,
	})
}

func (h *GitOpsHandler) getGitClient(ctx context.Context) (gitops.GitProvider, error) {
	cfg, err := h.getGitProviderConfig(ctx)
	if err != nil {
		return nil, err
	}
	return h.createGitClient(ctx, cfg)
}

func (h *GitOpsHandler) getGitToken(ctx context.Context) (string, error) {
	cfg, err := h.getGitProviderConfig(ctx)
	if err != nil {
		return "", err
	}
	return h.k8sClient.GetSecretValue(ctx, h.config.SystemNamespace, cfg.SecretName, "token")
}

func parseGitHubURL(url string) (owner, repo string, err error) {
	url = strings.TrimSuffix(url, ".git")

	if strings.HasPrefix(url, "git@") {
		parts := strings.Split(url, ":")
		if len(parts) != 2 {
			return "", "", fmt.Errorf("invalid SSH URL format")
		}
		return gitops.ParseRepoFullName(parts[1])
	}

	parts := strings.Split(url, "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("invalid URL format")
	}

	repo = parts[len(parts)-1]
	owner = parts[len(parts)-2]
	return owner, repo, nil
}

func randomSuffix() string {
	n, err := rand.Int(rand.Reader, big.NewInt(9000))
	if err != nil {
		return "0000"
	}
	return fmt.Sprintf("%04d", n.Int64()+1000)
}
