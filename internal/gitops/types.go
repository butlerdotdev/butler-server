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

package gitops

import (
	"context"
	"fmt"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

// API Request/Response Types

// GitProviderConfigResponse is the response for GET /api/gitops/config.
type GitProviderConfigResponse struct {
	Configured   bool   `json:"configured"`
	Type         string `json:"type,omitempty"`
	URL          string `json:"url,omitempty"`
	Organization string `json:"organization,omitempty"`
	Username     string `json:"username,omitempty"`
}

// SaveGitProviderRequest is the request for POST /api/gitops/config.
type SaveGitProviderRequest struct {
	Type         string `json:"type"`
	Token        string `json:"token"`
	URL          string `json:"url,omitempty"`
	Organization string `json:"organization,omitempty"`
}

// EnableGitOpsRequest is the request for POST /api/clusters/{ns}/{name}/gitops/enable.
type EnableGitOpsRequest struct {
	Provider        string   `json:"provider,omitempty"`
	Repository      string   `json:"repository"`
	Branch          string   `json:"branch,omitempty"`
	Path            string   `json:"path,omitempty"`
	Private         bool     `json:"private,omitempty"`
	ComponentsExtra []string `json:"componentsExtra,omitempty"`
}

// DisableGitOpsResponse is the response for DELETE /api/clusters/{ns}/{name}/gitops.
type DisableGitOpsResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// EnableGitOpsResponse is the response for enabling GitOps.
type EnableGitOpsResponse struct {
	Success       bool   `json:"success"`
	Message       string `json:"message"`
	RepositoryURL string `json:"repositoryUrl"`
	Provider      string `json:"provider"`
	Version       string `json:"version,omitempty"`
	Path          string `json:"path"`
}

// GitOpsStatusResponse is the response for GET /api/clusters/{ns}/{name}/gitops/status.
type GitOpsStatusResponse struct {
	Enabled        bool            `json:"enabled"`
	Provider       string          `json:"provider,omitempty"`
	Repository     string          `json:"repository,omitempty"`
	Branch         string          `json:"branch,omitempty"`
	Path           string          `json:"path,omitempty"`
	Status         string          `json:"status,omitempty"`
	Version        string          `json:"version,omitempty"`
	FluxVersion    string          `json:"fluxVersion,omitempty"` // Deprecated: use Version
	ProviderStatus *ProviderStatus `json:"providerStatus,omitempty"`
}

// ExportAddonRequest is the request for POST /api/clusters/{ns}/{name}/gitops/export/addon.
type ExportAddonRequest struct {
	AddonName  string                 `json:"addonName"`
	TargetPath string                 `json:"targetPath"`
	Values     map[string]interface{} `json:"values,omitempty"`
	CreatePR   bool                   `json:"createPR,omitempty"`
	PRTitle    string                 `json:"prTitle,omitempty"`
	PRBody     string                 `json:"prBody,omitempty"`
	Repository string                 `json:"repository,omitempty"`
	Branch     string                 `json:"branch,omitempty"`
}

// ExportAddonResponse is the response for addon export.
type ExportAddonResponse struct {
	Success   bool     `json:"success"`
	Message   string   `json:"message"`
	Files     []string `json:"files"`
	CommitSHA string   `json:"commitSha,omitempty"`
	PRURL     string   `json:"prUrl,omitempty"`
	PRNumber  int      `json:"prNumber,omitempty"`
}

// PreviewManifestRequest is the request for POST /api/gitops/preview.
type PreviewManifestRequest struct {
	AddonName  string                 `json:"addonName"`
	Repository string                 `json:"repository"`
	Path       string                 `json:"path"`
	Format     string                 `json:"format,omitempty"`
	Values     map[string]interface{} `json:"values,omitempty"`
}

// PreviewManifestResponse is the response for manifest preview.
type PreviewManifestResponse map[string]string

// Git Provider Types

// FileCommit represents a file to be committed.
type FileCommit struct {
	Path    string
	Content []byte
	Mode    string
}

// CommitResult contains the result of a commit operation.
type CommitResult struct {
	SHA     string
	URL     string
	Message string
}

// PullRequestResult contains the result of creating a PR.
type PullRequestResult struct {
	Number  int
	URL     string
	HTMLURL string
	Title   string
}

// Repository Types

// Repository represents a Git repository.
type Repository struct {
	Name          string `json:"name"`
	FullName      string `json:"fullName"`
	Description   string `json:"description,omitempty"`
	DefaultBranch string `json:"defaultBranch"`
	Private       bool   `json:"private"`
	CloneURL      string `json:"cloneUrl"`
	SSHURL        string `json:"sshUrl"`
	HTMLURL       string `json:"htmlUrl"`
	UpdatedAt     string `json:"updatedAt,omitempty"`
}

// Branch represents a Git branch.
type Branch struct {
	Name      string `json:"name"`
	Protected bool   `json:"protected"`
	Default   bool   `json:"default"`
}

// Helper Functions

// ParseRepoFullName parses "owner/repo" format into owner and repo.
func ParseRepoFullName(fullName string) (owner, repo string, err error) {
	for i := 0; i < len(fullName); i++ {
		if fullName[i] == '/' {
			if i == 0 || i == len(fullName)-1 {
				return "", "", fmt.Errorf("invalid repository format: %q", fullName)
			}
			return fullName[:i], fullName[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("invalid repository format: %q (expected owner/repo)", fullName)
}

// ParseRepoURL parses a Git repository URL and returns the owner and repo name.
func ParseRepoURL(repoURL string) (owner, repo string, err error) {
	repoURL = strings.TrimSuffix(repoURL, ".git")

	if strings.Contains(repoURL, "github.com/") {
		parts := strings.Split(repoURL, "github.com/")
		if len(parts) == 2 {
			return ParseRepoFullName(parts[1])
		}
	}

	if strings.Contains(repoURL, "gitlab.com/") {
		parts := strings.Split(repoURL, "gitlab.com/")
		if len(parts) == 2 {
			return ParseRepoFullName(parts[1])
		}
	}

	return ParseRepoFullName(repoURL)
}

// GetFluxGitRepositoryConfig reads the GitRepository CR from Flux to get the configured repo.
func GetFluxGitRepositoryConfig(ctx context.Context, kubeconfig []byte) (repoURL, branch, path string, err error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create rest config: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create dynamic client: %w", err)
	}

	gitRepoGVR := schema.GroupVersionResource{
		Group:    "source.toolkit.fluxcd.io",
		Version:  "v1",
		Resource: "gitrepositories",
	}

	list, err := dynClient.Resource(gitRepoGVR).Namespace("flux-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to list GitRepositories: %w", err)
	}

	if len(list.Items) == 0 {
		return "", "", "", fmt.Errorf("no GitRepository found in flux-system")
	}

	gitRepo := list.Items[0]

	if spec, ok := gitRepo.Object["spec"].(map[string]interface{}); ok {
		if url, ok := spec["url"].(string); ok {
			repoURL = url
		}
		if ref, ok := spec["ref"].(map[string]interface{}); ok {
			if b, ok := ref["branch"].(string); ok {
				branch = b
			}
		}
	}

	kustomizationGVR := schema.GroupVersionResource{
		Group:    "kustomize.toolkit.fluxcd.io",
		Version:  "v1",
		Resource: "kustomizations",
	}

	ksList, err := dynClient.Resource(kustomizationGVR).Namespace("flux-system").List(ctx, metav1.ListOptions{})
	if err == nil && len(ksList.Items) > 0 {
		for _, ks := range ksList.Items {
			if ks.GetName() == "flux-system" {
				if spec, ok := ks.Object["spec"].(map[string]interface{}); ok {
					if p, ok := spec["path"].(string); ok {
						path = p
					}
				}
				break
			}
		}
	}

	if repoURL == "" {
		return "", "", "", fmt.Errorf("no URL found in GitRepository")
	}

	return repoURL, branch, path, nil
}
