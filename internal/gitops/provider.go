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
)

// Provider defines the interface for GitOps providers (Flux, ArgoCD).
type Provider interface {
	Name() string
	DisplayName() string
	GenerateReleaseManifests(cfg ReleaseConfig) (map[string][]byte, error)
	GenerateBootstrapStructure(cfg BootstrapConfig) (map[string][]byte, error)
	CheckInstalled(ctx context.Context, kubeconfig []byte) (*ProviderStatus, error)
	GetSyncStatus(ctx context.Context, kubeconfig []byte, identifier string) (*SyncStatus, error)
}

// ReleaseConfig contains all configuration needed to generate GitOps manifests for a Helm release.
type ReleaseConfig struct {
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
	Category        string
	ClusterName     string
	ClusterServer   string
}

// BootstrapConfig contains configuration for generating the initial repo structure.
type BootstrapConfig struct {
	ClusterName   string
	ClusterServer string
	Layout        DirectoryLayout
	ToolConfig    GitOpsToolConfig
}

// DirectoryLayout defines the repository directory structure.
type DirectoryLayout struct {
	ClusterPath        string
	InfrastructurePath string
	AppsPath           string
}

// GitOpsToolConfig contains GitOps tool-specific settings.
type GitOpsToolConfig struct {
	Flux   *FluxProviderConfig
	ArgoCD *ArgoCDProviderConfig
}

// FluxProviderConfig contains Flux-specific settings.
type FluxProviderConfig struct {
	Namespace         string
	ReconcileInterval string
	SourceInterval    string
}

// ArgoCDProviderConfig contains ArgoCD-specific settings.
type ArgoCDProviderConfig struct {
	Namespace string
	Project   string
	AutoSync  bool
	Prune     bool
	SelfHeal  bool
}

// ProviderStatus contains information about a GitOps provider installation.
type ProviderStatus struct {
	Installed  bool
	Ready      bool
	Version    string
	Message    string
	Components []ComponentStatus
}

// ComponentStatus represents the status of a single provider component.
type ComponentStatus struct {
	Name    string
	Ready   bool
	Message string
}

// SyncStatus contains the sync status of a GitOps-managed resource.
type SyncStatus struct {
	Synced       bool
	Phase        string
	Message      string
	LastSyncTime string
	Revision     string
}

var providerRegistry = make(map[string]func() Provider)

// RegisterProvider registers a provider factory function.
func RegisterProvider(name string, factory func() Provider) {
	providerRegistry[name] = factory
}

// GetProvider returns a provider instance by name.
func GetProvider(name string) (Provider, error) {
	factory, ok := providerRegistry[name]
	if !ok {
		return nil, fmt.Errorf("unknown GitOps provider: %s (available: flux, argocd)", name)
	}
	return factory(), nil
}

// ListProviders returns all registered provider names.
func ListProviders() []string {
	names := make([]string, 0, len(providerRegistry))
	for name := range providerRegistry {
		names = append(names, name)
	}
	return names
}

// DefaultDirectoryLayout returns the default directory structure.
func DefaultDirectoryLayout(clusterName string) DirectoryLayout {
	return DirectoryLayout{
		ClusterPath:        fmt.Sprintf("clusters/%s", clusterName),
		InfrastructurePath: "infrastructure",
		AppsPath:           "apps",
	}
}

// DefaultFluxConfig returns default Flux settings.
func DefaultFluxConfig() *FluxProviderConfig {
	return &FluxProviderConfig{
		Namespace:         "flux-system",
		ReconcileInterval: "5m",
		SourceInterval:    "1h",
	}
}

// DefaultArgoCDConfig returns default ArgoCD settings.
func DefaultArgoCDConfig() *ArgoCDProviderConfig {
	return &ArgoCDProviderConfig{
		Namespace: "argocd",
		Project:   "default",
		AutoSync:  true,
		Prune:     true,
		SelfHeal:  true,
	}
}

// GetCategoryPath returns the path for a category within the layout.
func (l DirectoryLayout) GetCategoryPath(category string) string {
	switch category {
	case "infrastructure":
		return l.InfrastructurePath
	default:
		return l.AppsPath
	}
}

// GetReleasePath returns the full path for a release.
func (l DirectoryLayout) GetReleasePath(category, releaseName string) string {
	return fmt.Sprintf("%s/%s", l.GetCategoryPath(category), releaseName)
}
