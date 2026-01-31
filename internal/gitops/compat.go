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
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"sigs.k8s.io/yaml"
)

// Compatibility Layer
//
// This file provides backward compatibility for handlers that use the old API.
// It bridges old function names to the new provider-based architecture.
//
// TODO: Gradually update handlers to use new API directly, then remove this file.

// ProviderType is the type of Git provider.
type ProviderType string

const (
	ProviderTypeGitHub ProviderType = "github"
	ProviderTypeGitLab ProviderType = "gitlab"
)

// ProviderConfig is configuration for creating a Git provider.
// This is the old API - use GitProviderConfig for new code.
type ProviderConfig struct {
	Type         ProviderType
	Token        string
	URL          string
	Organization string
}

// NewProvider creates a Git provider from config.
// This is the old API - use NewGitProvider for new code.
func NewProvider(cfg ProviderConfig) (GitProvider, error) {
	return NewGitProvider(GitProviderConfig{
		Type:         string(cfg.Type),
		Token:        cfg.Token,
		URL:          cfg.URL,
		Organization: cfg.Organization,
	})
}

// FluxBootstrapper wraps the new FluxProvider for CLI-based bootstrap.
// Note: This still uses CLI for bootstrap as Flux bootstrap requires it.
// The manifest generation uses the new typed approach.
type FluxBootstrapper struct {
	kubeconfig []byte
	provider   *FluxProvider
}

// NewFluxBootstrapper creates a new Flux bootstrapper.
func NewFluxBootstrapper(kubeconfig []byte) *FluxBootstrapper {
	return &FluxBootstrapper{
		kubeconfig: kubeconfig,
		provider:   &FluxProvider{},
	}
}

// BootstrapOptions contains options for Flux bootstrap.
type BootstrapOptions struct {
	Provider        string
	Owner           string
	Repository      string
	Branch          string
	Path            string
	Token           string
	Personal        bool
	Private         bool
	Cluster         string
	ComponentsExtra []string
}

// Bootstrap runs flux bootstrap github.
// CRITICAL: This writes the kubeconfig to a temp file and passes --kubeconfig
// to ensure flux targets the tenant cluster, not the management cluster.
func (f *FluxBootstrapper) Bootstrap(ctx context.Context, opts BootstrapOptions) (*BootstrapResult, error) {
	if !IsFluxCLIAvailable() {
		return nil, fmt.Errorf("flux CLI not available")
	}

	kubeconfigPath, cleanup, err := f.writeKubeconfig()
	if err != nil {
		return nil, fmt.Errorf("failed to write kubeconfig: %w", err)
	}
	defer cleanup()

	args := []string{
		"bootstrap", "github",
		"--kubeconfig", kubeconfigPath,
		"--owner", opts.Owner,
		"--repository", opts.Repository,
		"--branch", opts.Branch,
		"--path", opts.Path,
	}

	if opts.Personal {
		args = append(args, "--personal")
	}
	if opts.Private {
		args = append(args, "--private")
	}
	if len(opts.ComponentsExtra) > 0 {
		args = append(args, "--components-extra="+strings.Join(opts.ComponentsExtra, ","))
	}

	cmd := exec.CommandContext(ctx, "flux", args...)

	env := os.Environ()
	if opts.Token != "" {
		env = append(env, "GITHUB_TOKEN="+opts.Token)
	}
	cmd.Env = env

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("flux bootstrap failed: %w\noutput: %s", err, string(output))
	}

	version := f.getFluxVersion()

	return &BootstrapResult{
		Success: true,
		Message: "Flux bootstrap completed successfully",
		Version: version,
	}, nil
}

func (f *FluxBootstrapper) getFluxVersion() string {
	cmd := exec.Command("flux", "version", "--client")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(output)
}

func (f *FluxBootstrapper) writeKubeconfig() (string, func(), error) {
	tmpDir, err := os.MkdirTemp("", "butler-flux-*")
	if err != nil {
		return "", func() {}, fmt.Errorf("failed to create temp dir: %w", err)
	}

	kubeconfigPath := filepath.Join(tmpDir, "kubeconfig")
	if err := os.WriteFile(kubeconfigPath, f.kubeconfig, 0600); err != nil {
		os.RemoveAll(tmpDir)
		return "", func() {}, fmt.Errorf("failed to write kubeconfig: %w", err)
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}

	return kubeconfigPath, cleanup, nil
}

// GetStatus returns the status of Flux on the cluster.
func (f *FluxBootstrapper) GetStatus(ctx context.Context) (*ProviderStatus, error) {
	return f.provider.CheckInstalled(ctx, f.kubeconfig)
}

// Uninstall removes Flux from the cluster.
func (f *FluxBootstrapper) Uninstall(ctx context.Context) error {
	if !IsFluxCLIAvailable() {
		return fmt.Errorf("flux CLI not available")
	}

	kubeconfigPath, cleanup, err := f.writeKubeconfig()
	if err != nil {
		return fmt.Errorf("failed to write kubeconfig: %w", err)
	}
	defer cleanup()

	args := []string{
		"uninstall",
		"--kubeconfig", kubeconfigPath,
		"--silent",
	}

	cmd := exec.CommandContext(ctx, "flux", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("flux uninstall failed: %w\noutput: %s", err, string(output))
	}

	return nil
}

// BootstrapResult contains the result of a bootstrap operation.
type BootstrapResult struct {
	Success bool
	Message string
	Version string
}

// CheckFluxInstalled checks if Flux is installed on the cluster.
func (f *FluxBootstrapper) CheckFluxInstalled(ctx context.Context) (*ProviderStatus, error) {
	return f.provider.CheckInstalled(ctx, f.kubeconfig)
}

// IsFluxCLIAvailable checks if the flux CLI is available.
func IsFluxCLIAvailable() bool {
	_, err := exec.LookPath("flux")
	return err == nil
}

// ManifestGenerator wraps the new provider-based manifest generation.
type ManifestGenerator struct {
	fluxProvider   *FluxProvider
	argocdProvider *ArgoCDProvider
}

// NewManifestGenerator creates a new manifest generator.
func NewManifestGenerator() *ManifestGenerator {
	return &ManifestGenerator{
		fluxProvider:   &FluxProvider{},
		argocdProvider: &ArgoCDProvider{},
	}
}

// HelmReleaseConfig is configuration for generating Helm release manifests.
// This is the old API - use ReleaseConfig for new code.
type HelmReleaseConfig struct {
	Name            string
	Namespace       string
	TargetNamespace string
	ChartName       string
	ChartVersion    string
	RepoURL         string
	RepoName        string
	Values          map[string]interface{}
	CreateNamespace bool
	Interval        string
	DependsOn       []string
}

// GenerateAddonManifests generates Flux manifests for an addon.
func (g *ManifestGenerator) GenerateAddonManifests(cfg HelmReleaseConfig) (map[string][]byte, error) {
	return g.fluxProvider.GenerateReleaseManifests(ReleaseConfig{
		Name:            cfg.Name,
		Namespace:       cfg.Namespace,
		TargetNamespace: cfg.TargetNamespace,
		ChartName:       cfg.ChartName,
		ChartVersion:    cfg.ChartVersion,
		RepoURL:         cfg.RepoURL,
		RepoName:        cfg.RepoName,
		Values:          cfg.Values,
		CreateNamespace: cfg.CreateNamespace,
		Interval:        cfg.Interval,
		DependsOn:       cfg.DependsOn,
	})
}

// GenerateFromDiscoveredRelease generates manifests from a discovered release.
func (g *ManifestGenerator) GenerateFromDiscoveredRelease(release DiscoveredRelease) (map[string][]byte, error) {
	return g.fluxProvider.GenerateReleaseManifests(ReleaseConfig{
		Name:            release.Name,
		Namespace:       "flux-system",
		TargetNamespace: release.Namespace,
		ChartName:       release.Chart,
		ChartVersion:    release.ChartVersion,
		RepoURL:         release.RepoURL,
		Values:          release.Values,
		CreateNamespace: true,
		Category:        release.Category,
	})
}

// DirectoryStructure provides standard paths for GitOps repositories.
type DirectoryStructure struct {
	ClusterName string
	layout      DirectoryLayout
}

// NewDirectoryStructure creates a new DirectoryStructure.
func NewDirectoryStructure(clusterName string) *DirectoryStructure {
	return &DirectoryStructure{
		ClusterName: clusterName,
		layout:      DefaultDirectoryLayout(clusterName),
	}
}

// ClusterPath returns the base path for a cluster.
func (d *DirectoryStructure) ClusterPath() string {
	return d.layout.ClusterPath
}

// FluxSystemPath returns the path for flux-system components.
func (d *DirectoryStructure) FluxSystemPath() string {
	return d.layout.ClusterPath + "/flux-system"
}

// InfrastructurePath returns the path for infrastructure components.
func (d *DirectoryStructure) InfrastructurePath() string {
	return d.layout.InfrastructurePath
}

// AppsPath returns the path for application components.
func (d *DirectoryStructure) AppsPath() string {
	return d.layout.AppsPath
}

// GetCategoryPath returns the path for a given category.
func (d *DirectoryStructure) GetCategoryPath(category string) string {
	return d.layout.GetCategoryPath(category)
}

// AddonPath returns the full path for an addon.
func (d *DirectoryStructure) AddonPath(category, addonName string) string {
	return d.layout.GetReleasePath(category, addonName)
}

// MigrateToGitOpsRequest is the request for migration.
type MigrateToGitOpsRequest = MigrationRequest

// MigrateToGitOpsResponse is the response for migration.
type MigrateToGitOpsResponse struct {
	Success       bool     `json:"success"`
	Message       string   `json:"message"`
	MigratedCount int      `json:"migratedCount"`
	Files         []string `json:"files"`
	CommitSHA     string   `json:"commitSha,omitempty"`
	PRURL         string   `json:"prUrl,omitempty"`
}

// GeneratePreviewManifests generates manifests for preview without committing.
func GeneratePreviewManifests(providerType, addonName, repoURL, chartName, chartVersion string, values map[string]interface{}) (map[string]string, error) {
	var provider Provider
	var err error

	if providerType == "" || providerType == "flux" {
		provider = &FluxProvider{}
	} else if providerType == "argocd" {
		provider = &ArgoCDProvider{}
	} else {
		provider, err = GetProvider(providerType)
		if err != nil {
			return nil, err
		}
	}

	files, err := provider.GenerateReleaseManifests(ReleaseConfig{
		Name:            addonName,
		Namespace:       "flux-system",
		TargetNamespace: addonName,
		ChartName:       chartName,
		ChartVersion:    chartVersion,
		RepoURL:         repoURL,
		Values:          values,
		CreateNamespace: true,
	})
	if err != nil {
		return nil, err
	}

	result := make(map[string]string, len(files))
	for name, content := range files {
		result[name] = string(content)
	}

	return result, nil
}

// ValuesToYAML converts values map to YAML string.
func ValuesToYAML(values map[string]interface{}) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	data, err := yaml.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// NewNamespace creates a new Kubernetes Namespace resource.
func NewNamespace(name string) *K8sNamespace {
	return NewK8sNamespace(name)
}
