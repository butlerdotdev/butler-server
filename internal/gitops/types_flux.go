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

// Flux resource types for YAML generation.
// Reference: https://fluxcd.io/flux/components/

// FluxHelmRepository represents a Flux HelmRepository resource.
type FluxHelmRepository struct {
	APIVersion string                 `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                 `json:"kind" yaml:"kind"`
	Metadata   FluxMetadata           `json:"metadata" yaml:"metadata"`
	Spec       FluxHelmRepositorySpec `json:"spec" yaml:"spec"`
}

// FluxHelmRepositorySpec is the spec for HelmRepository.
type FluxHelmRepositorySpec struct {
	URL       string               `json:"url" yaml:"url"`
	Interval  string               `json:"interval" yaml:"interval"`
	SecretRef *FluxSecretReference `json:"secretRef,omitempty" yaml:"secretRef,omitempty"`
	Type      string               `json:"type,omitempty" yaml:"type,omitempty"`
}

// FluxHelmRelease represents a Flux HelmRelease resource.
type FluxHelmRelease struct {
	APIVersion string              `json:"apiVersion" yaml:"apiVersion"`
	Kind       string              `json:"kind" yaml:"kind"`
	Metadata   FluxMetadata        `json:"metadata" yaml:"metadata"`
	Spec       FluxHelmReleaseSpec `json:"spec" yaml:"spec"`
}

// FluxHelmReleaseSpec is the spec for HelmRelease.
type FluxHelmReleaseSpec struct {
	Interval        string                    `json:"interval" yaml:"interval"`
	Chart           FluxHelmChartTemplate     `json:"chart" yaml:"chart"`
	TargetNamespace string                    `json:"targetNamespace,omitempty" yaml:"targetNamespace,omitempty"`
	ReleaseName     string                    `json:"releaseName,omitempty" yaml:"releaseName,omitempty"`
	Install         *FluxInstall              `json:"install,omitempty" yaml:"install,omitempty"`
	Upgrade         *FluxUpgrade              `json:"upgrade,omitempty" yaml:"upgrade,omitempty"`
	DependsOn       []FluxDependencyReference `json:"dependsOn,omitempty" yaml:"dependsOn,omitempty"`
	Values          map[string]interface{}    `json:"values,omitempty" yaml:"values,omitempty"`
	ValuesFrom      []FluxValuesReference     `json:"valuesFrom,omitempty" yaml:"valuesFrom,omitempty"`
}

// FluxHelmChartTemplate is the chart specification.
type FluxHelmChartTemplate struct {
	Spec FluxHelmChartTemplateSpec `json:"spec" yaml:"spec"`
}

// FluxHelmChartTemplateSpec is the chart template spec.
type FluxHelmChartTemplateSpec struct {
	Chart     string                `json:"chart" yaml:"chart"`
	Version   string                `json:"version,omitempty" yaml:"version,omitempty"`
	SourceRef FluxCrossNamespaceRef `json:"sourceRef" yaml:"sourceRef"`
	Interval  string                `json:"interval,omitempty" yaml:"interval,omitempty"`
}

// FluxInstall contains install configuration.
type FluxInstall struct {
	CreateNamespace bool             `json:"createNamespace,omitempty" yaml:"createNamespace,omitempty"`
	Remediation     *FluxRemediation `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

// FluxUpgrade contains upgrade configuration.
type FluxUpgrade struct {
	Remediation *FluxRemediation `json:"remediation,omitempty" yaml:"remediation,omitempty"`
}

// FluxRemediation contains remediation configuration.
type FluxRemediation struct {
	Retries int `json:"retries,omitempty" yaml:"retries,omitempty"`
}

// FluxKustomization represents a Flux Kustomization resource.
type FluxKustomization struct {
	APIVersion string                `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                `json:"kind" yaml:"kind"`
	Metadata   FluxMetadata          `json:"metadata" yaml:"metadata"`
	Spec       FluxKustomizationSpec `json:"spec" yaml:"spec"`
}

// FluxKustomizationSpec is the spec for Kustomization.
type FluxKustomizationSpec struct {
	Interval     string                    `json:"interval" yaml:"interval"`
	SourceRef    FluxCrossNamespaceRef     `json:"sourceRef" yaml:"sourceRef"`
	Path         string                    `json:"path" yaml:"path"`
	Prune        bool                      `json:"prune" yaml:"prune"`
	Wait         bool                      `json:"wait,omitempty" yaml:"wait,omitempty"`
	DependsOn    []FluxDependencyReference `json:"dependsOn,omitempty" yaml:"dependsOn,omitempty"`
	HealthChecks []FluxHealthCheck         `json:"healthChecks,omitempty" yaml:"healthChecks,omitempty"`
}

// FluxGitRepository represents a Flux GitRepository resource.
type FluxGitRepository struct {
	APIVersion string                `json:"apiVersion" yaml:"apiVersion"`
	Kind       string                `json:"kind" yaml:"kind"`
	Metadata   FluxMetadata          `json:"metadata" yaml:"metadata"`
	Spec       FluxGitRepositorySpec `json:"spec" yaml:"spec"`
}

// FluxGitRepositorySpec is the spec for GitRepository.
type FluxGitRepositorySpec struct {
	URL       string               `json:"url" yaml:"url"`
	Interval  string               `json:"interval" yaml:"interval"`
	Ref       *FluxGitRef          `json:"ref,omitempty" yaml:"ref,omitempty"`
	SecretRef *FluxSecretReference `json:"secretRef,omitempty" yaml:"secretRef,omitempty"`
}

// FluxGitRef specifies the Git reference.
type FluxGitRef struct {
	Branch string `json:"branch,omitempty" yaml:"branch,omitempty"`
	Tag    string `json:"tag,omitempty" yaml:"tag,omitempty"`
	Semver string `json:"semver,omitempty" yaml:"semver,omitempty"`
	Commit string `json:"commit,omitempty" yaml:"commit,omitempty"`
}

// FluxMetadata contains Kubernetes object metadata.
type FluxMetadata struct {
	Name        string            `json:"name" yaml:"name"`
	Namespace   string            `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// FluxCrossNamespaceRef is a reference to a resource, optionally in another namespace.
type FluxCrossNamespaceRef struct {
	Kind      string `json:"kind" yaml:"kind"`
	Name      string `json:"name" yaml:"name"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// FluxSecretReference is a reference to a Secret.
type FluxSecretReference struct {
	Name string `json:"name" yaml:"name"`
}

// FluxDependencyReference is a reference to another Flux resource.
type FluxDependencyReference struct {
	Name      string `json:"name" yaml:"name"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// FluxValuesReference is a reference to a values source.
type FluxValuesReference struct {
	Kind      string `json:"kind" yaml:"kind"`
	Name      string `json:"name" yaml:"name"`
	ValuesKey string `json:"valuesKey,omitempty" yaml:"valuesKey,omitempty"`
}

// FluxHealthCheck defines a health check for Kustomization.
type FluxHealthCheck struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind" yaml:"kind"`
	Name       string `json:"name" yaml:"name"`
	Namespace  string `json:"namespace" yaml:"namespace"`
}

// KustomizeFile represents a kustomization.yaml file.
type KustomizeFile struct {
	APIVersion string   `json:"apiVersion" yaml:"apiVersion"`
	Kind       string   `json:"kind" yaml:"kind"`
	Resources  []string `json:"resources,omitempty" yaml:"resources,omitempty"`
	Namespace  string   `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

// K8sNamespace represents a Kubernetes Namespace.
type K8sNamespace struct {
	APIVersion string               `json:"apiVersion" yaml:"apiVersion"`
	Kind       string               `json:"kind" yaml:"kind"`
	Metadata   K8sNamespaceMetadata `json:"metadata" yaml:"metadata"`
}

// K8sNamespaceMetadata is metadata for a Namespace.
type K8sNamespaceMetadata struct {
	Name        string            `json:"name" yaml:"name"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty" yaml:"annotations,omitempty"`
}

// NewFluxHelmRepository creates a new HelmRepository with defaults.
func NewFluxHelmRepository(name, namespace, url string) *FluxHelmRepository {
	return &FluxHelmRepository{
		APIVersion: "source.toolkit.fluxcd.io/v1",
		Kind:       "HelmRepository",
		Metadata: FluxMetadata{
			Name:      name,
			Namespace: namespace,
		},
		Spec: FluxHelmRepositorySpec{
			URL:      url,
			Interval: "1h",
		},
	}
}

// NewFluxHelmRelease creates a new HelmRelease with defaults.
func NewFluxHelmRelease(name, namespace string) *FluxHelmRelease {
	return &FluxHelmRelease{
		APIVersion: "helm.toolkit.fluxcd.io/v2",
		Kind:       "HelmRelease",
		Metadata: FluxMetadata{
			Name:      name,
			Namespace: namespace,
		},
		Spec: FluxHelmReleaseSpec{
			Interval: "5m",
		},
	}
}

// NewFluxKustomization creates a new Kustomization with defaults.
func NewFluxKustomization(name, namespace, path string) *FluxKustomization {
	return &FluxKustomization{
		APIVersion: "kustomize.toolkit.fluxcd.io/v1",
		Kind:       "Kustomization",
		Metadata: FluxMetadata{
			Name:      name,
			Namespace: namespace,
		},
		Spec: FluxKustomizationSpec{
			Interval: "10m",
			Path:     path,
			Prune:    true,
			SourceRef: FluxCrossNamespaceRef{
				Kind: "GitRepository",
				Name: "flux-system",
			},
		},
	}
}

// NewKustomizeFile creates a new kustomization.yaml.
func NewKustomizeFile() *KustomizeFile {
	return &KustomizeFile{
		APIVersion: "kustomize.config.k8s.io/v1beta1",
		Kind:       "Kustomization",
		Resources:  []string{},
	}
}

// NewK8sNamespace creates a new Namespace.
func NewK8sNamespace(name string) *K8sNamespace {
	return &K8sNamespace{
		APIVersion: "v1",
		Kind:       "Namespace",
		Metadata: K8sNamespaceMetadata{
			Name: name,
		},
	}
}
