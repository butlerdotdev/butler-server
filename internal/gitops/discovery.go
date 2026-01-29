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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	butlerv1alpha1 "github.com/butlerdotdev/butler-api/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Helm 3 stores releases as Secrets in the namespace where the release is
// installed. The secrets have label owner=helm and status=deployed.
// This approach is how production tools like Rancher, Lens, and Helm Dashboard
// discover releases without shelling out to the helm CLI.

// DiscoveryResult contains the results of Helm release discovery.
type DiscoveryResult struct {
	Matched      []*DiscoveredRelease `json:"matched"`
	Unmatched    []*DiscoveredRelease `json:"unmatched"`
	GitOpsEngine *GitOpsEngineStatus  `json:"gitopsEngine,omitempty"`
}

// GitOpsEngineStatus reports the status of GitOps tooling on a cluster.
type GitOpsEngineStatus struct {
	Provider   string   `json:"provider,omitempty"`
	Installed  bool     `json:"installed"`
	Ready      bool     `json:"ready"`
	Version    string   `json:"version,omitempty"`
	Components []string `json:"components,omitempty"`
	Repository string   `json:"repository,omitempty"`
	Branch     string   `json:"branch,omitempty"`
	Path       string   `json:"path,omitempty"`
}

// DiscoveredRelease represents a Helm release discovered on a cluster.
type DiscoveredRelease struct {
	Name            string                 `json:"name"`
	Namespace       string                 `json:"namespace"`
	Chart           string                 `json:"chart"`
	ChartVersion    string                 `json:"chartVersion"`
	AppVersion      string                 `json:"appVersion,omitempty"`
	Status          string                 `json:"status"`
	Revision        int                    `json:"revision"`
	Values          map[string]interface{} `json:"values,omitempty"`
	RepoURL         string                 `json:"repoUrl,omitempty"`
	Category        string                 `json:"category,omitempty"`
	AddonDefinition string                 `json:"addonDefinition,omitempty"`
	Platform        bool                   `json:"platform,omitempty"`
}

// DiscoverHelmReleases discovers all Helm releases on a cluster via the
// Kubernetes API and matches them against known AddonDefinitions.
func DiscoverHelmReleases(ctx context.Context, kubeconfig []byte, addonDefs []butlerv1alpha1.AddonDefinition) (*DiscoveryResult, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	addonLookup := buildAddonLookup(addonDefs)

	secrets, err := clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm,status=deployed",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list Helm secrets: %w", err)
	}

	latestReleases := make(map[string]*helmReleaseData)

	for _, secret := range secrets.Items {
		releaseData, err := decodeHelmRelease(secret.Data["release"])
		if err != nil {
			continue
		}

		key := fmt.Sprintf("%s/%s", releaseData.Namespace, releaseData.Name)
		if existing, ok := latestReleases[key]; ok {
			if releaseData.Version > existing.Version {
				latestReleases[key] = releaseData
			}
		} else {
			latestReleases[key] = releaseData
		}
	}

	result := &DiscoveryResult{
		Matched:   make([]*DiscoveredRelease, 0),
		Unmatched: make([]*DiscoveredRelease, 0),
	}

	for _, rd := range latestReleases {
		release := &DiscoveredRelease{
			Name:         rd.Name,
			Namespace:    rd.Namespace,
			Chart:        rd.Chart.Metadata.Name,
			ChartVersion: rd.Chart.Metadata.Version,
			AppVersion:   rd.Chart.Metadata.AppVersion,
			Status:       rd.Info.Status,
			Revision:     rd.Version,
			Values:       rd.Config,
		}

		if addonDef, found := matchAddonDefinition(release.Chart, addonLookup); found {
			release.AddonDefinition = addonDef.Name
			release.RepoURL = addonDef.Spec.Chart.Repository
			release.Platform = addonDef.Spec.Platform
			release.Category = categoryFromPlatform(addonDef.Spec.Platform)
			result.Matched = append(result.Matched, release)
		} else {
			release.Category = "apps"
			release.RepoURL = extractRepoURLFromChartMetadata(rd.Chart.Metadata)
			result.Unmatched = append(result.Unmatched, release)
		}
	}

	result.GitOpsEngine = detectGitOpsEngine(ctx, clientset)

	return result, nil
}

func detectGitOpsEngine(ctx context.Context, clientset *kubernetes.Clientset) *GitOpsEngineStatus {
	if fluxStatus := detectFlux(ctx, clientset); fluxStatus != nil {
		return fluxStatus
	}

	if argoStatus := detectArgoCD(ctx, clientset); argoStatus != nil {
		return argoStatus
	}

	return nil
}

func detectFlux(ctx context.Context, clientset *kubernetes.Clientset) *GitOpsEngineStatus {
	fluxComponents := []string{
		"source-controller",
		"kustomize-controller",
		"helm-controller",
		"notification-controller",
	}

	var readyComponents []string
	var version string

	for _, component := range fluxComponents {
		deployment, err := clientset.AppsV1().Deployments("flux-system").Get(ctx, component, metav1.GetOptions{})
		if err != nil {
			continue
		}

		if deployment.Status.ReadyReplicas > 0 {
			readyComponents = append(readyComponents, component)

			if version == "" && len(deployment.Spec.Template.Spec.Containers) > 0 {
				image := deployment.Spec.Template.Spec.Containers[0].Image
				if parts := strings.Split(image, ":"); len(parts) > 1 {
					version = parts[len(parts)-1]
				}
			}
		}
	}

	if len(readyComponents) >= 2 {
		return &GitOpsEngineStatus{
			Provider:   "flux",
			Installed:  true,
			Ready:      len(readyComponents) >= 3,
			Version:    version,
			Components: readyComponents,
		}
	}

	return nil
}

func detectArgoCD(ctx context.Context, clientset *kubernetes.Clientset) *GitOpsEngineStatus {
	argoComponents := []string{
		"argocd-server",
		"argocd-repo-server",
		"argocd-application-controller",
	}

	var readyComponents []string
	var version string

	for _, component := range argoComponents {
		deployment, err := clientset.AppsV1().Deployments("argocd").Get(ctx, component, metav1.GetOptions{})
		if err != nil {
			continue
		}

		if deployment.Status.ReadyReplicas > 0 {
			readyComponents = append(readyComponents, component)

			if version == "" && len(deployment.Spec.Template.Spec.Containers) > 0 {
				image := deployment.Spec.Template.Spec.Containers[0].Image
				if parts := strings.Split(image, ":"); len(parts) > 1 {
					version = parts[len(parts)-1]
				}
			}
		}
	}

	if len(readyComponents) >= 2 {
		return &GitOpsEngineStatus{
			Provider:   "argocd",
			Installed:  true,
			Ready:      len(readyComponents) >= 3,
			Version:    version,
			Components: readyComponents,
		}
	}

	return nil
}

func extractRepoURLFromChartMetadata(metadata helmChartMetadata) string {
	knownRepos := map[string]string{
		"butler-addons":     "oci://ghcr.io/butlerdotdev/charts",
		"butler-console":    "oci://ghcr.io/butlerdotdev/charts",
		"butler-controller": "oci://ghcr.io/butlerdotdev/charts",
		"butler-crds":       "oci://ghcr.io/butlerdotdev/charts",
		"steward":           "oci://ghcr.io/butlerdotdev/charts",
	}

	if url, ok := knownRepos[metadata.Name]; ok {
		return url
	}

	if metadata.Home != "" {
		if strings.Contains(metadata.Home, "charts") ||
			strings.HasPrefix(metadata.Home, "https://") && strings.Contains(metadata.Home, "helm") {
			return metadata.Home
		}
	}

	for _, source := range metadata.Sources {
		if strings.HasPrefix(source, "oci://") {
			return source
		}
		if strings.Contains(source, "charts") || strings.Contains(source, "helm") {
			return source
		}
	}

	if metadata.Home != "" && strings.HasPrefix(metadata.Home, "https://") {
		return metadata.Home
	}

	return ""
}

// Helm release decoding types

type helmReleaseData struct {
	Name      string                 `json:"name"`
	Namespace string                 `json:"namespace"`
	Version   int                    `json:"version"`
	Info      helmReleaseInfo        `json:"info"`
	Chart     helmChartData          `json:"chart"`
	Config    map[string]interface{} `json:"config"`
}

type helmReleaseInfo struct {
	Status        string `json:"status"`
	Description   string `json:"description"`
	FirstDeployed string `json:"first_deployed"`
	LastDeployed  string `json:"last_deployed"`
}

type helmChartData struct {
	Metadata helmChartMetadata `json:"metadata"`
}

type helmChartMetadata struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	AppVersion  string   `json:"appVersion"`
	Home        string   `json:"home"`
	Description string   `json:"description"`
	Sources     []string `json:"sources"`
}

// decodeHelmRelease decodes a Helm release from its stored format.
// Helm stores releases as: base64(gzip(base64(json)))
func decodeHelmRelease(data []byte) (*helmReleaseData, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty release data")
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		decoded = data
	}

	gzReader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	decompressed, err := io.ReadAll(gzReader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}

	jsonData, err := base64.StdEncoding.DecodeString(string(decompressed))
	if err != nil {
		jsonData = decompressed
	}

	var release helmReleaseData
	if err := json.Unmarshal(jsonData, &release); err != nil {
		return nil, fmt.Errorf("failed to unmarshal release: %w", err)
	}

	return &release, nil
}

// AddonDefinition matching

func buildAddonLookup(addonDefs []butlerv1alpha1.AddonDefinition) map[string]*butlerv1alpha1.AddonDefinition {
	lookup := make(map[string]*butlerv1alpha1.AddonDefinition)
	for i := range addonDefs {
		ad := &addonDefs[i]
		chartName := strings.ToLower(ad.Spec.Chart.Name)
		lookup[chartName] = ad

		addonName := strings.ToLower(ad.Name)
		if _, exists := lookup[addonName]; !exists {
			lookup[addonName] = ad
		}
	}
	return lookup
}

func matchAddonDefinition(chartName string, lookup map[string]*butlerv1alpha1.AddonDefinition) (*butlerv1alpha1.AddonDefinition, bool) {
	chartLower := strings.ToLower(chartName)

	if ad, found := lookup[chartLower]; found {
		return ad, true
	}

	variants := []string{
		strings.TrimSuffix(chartLower, "-operator"),
		strings.TrimSuffix(chartLower, "-controller"),
		strings.TrimSuffix(chartLower, "-helm"),
		strings.TrimPrefix(chartLower, "helm-"),
	}

	for _, variant := range variants {
		if variant != chartLower {
			if ad, found := lookup[variant]; found {
				return ad, true
			}
		}
	}

	return nil, false
}

func categoryFromPlatform(platform bool) string {
	if platform {
		return "infrastructure"
	}
	return "apps"
}

// Migration types

// MigrationRequest defines a request to migrate releases to GitOps.
type MigrationRequest struct {
	Releases   []MigrationRelease `json:"releases"`
	CreatePR   bool               `json:"createPR,omitempty"`
	Repository string             `json:"repository,omitempty"`
	Branch     string             `json:"branch,omitempty"`
	BasePath   string             `json:"basePath,omitempty"`
	PRTitle    string             `json:"prTitle,omitempty"`
}

// MigrationRelease defines a release to migrate.
type MigrationRelease struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Category  string `json:"category,omitempty"`
	RepoURL   string `json:"repoUrl,omitempty"`
}

// MigrationResult contains the results of a migration operation.
type MigrationResult struct {
	Success       bool     `json:"success"`
	Message       string   `json:"message"`
	MigratedCount int      `json:"migratedCount"`
	Files         []string `json:"files"`
	CommitSHA     string   `json:"commitSha,omitempty"`
	PRURL         string   `json:"prUrl,omitempty"`
}
