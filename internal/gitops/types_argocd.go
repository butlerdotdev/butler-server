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

// ArgoCD resource types for YAML generation.
// Reference: https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/

// ArgoCDApplication represents an ArgoCD Application resource.
type ArgoCDApplication struct {
	APIVersion string                `yaml:"apiVersion"`
	Kind       string                `yaml:"kind"`
	Metadata   ArgoCDMetadata        `yaml:"metadata"`
	Spec       ArgoCDApplicationSpec `yaml:"spec"`
}

// ArgoCDApplicationSpec is the spec for Application.
type ArgoCDApplicationSpec struct {
	Project           string             `yaml:"project"`
	Source            *ArgoCDSource      `yaml:"source,omitempty"`
	Sources           []ArgoCDSource     `yaml:"sources,omitempty"`
	Destination       ArgoCDDestination  `yaml:"destination"`
	SyncPolicy        *ArgoCDSyncPolicy  `yaml:"syncPolicy,omitempty"`
	IgnoreDifferences []ArgoCDIgnoreDiff `yaml:"ignoreDifferences,omitempty"`
}

// ArgoCDSource defines the source of an application.
type ArgoCDSource struct {
	RepoURL        string               `yaml:"repoURL"`
	Path           string               `yaml:"path,omitempty"`
	TargetRevision string               `yaml:"targetRevision,omitempty"`
	Chart          string               `yaml:"chart,omitempty"`
	Helm           *ArgoCDHelmSpec      `yaml:"helm,omitempty"`
	Kustomize      *ArgoCDKustomizeSpec `yaml:"kustomize,omitempty"`
	Directory      *ArgoCDDirectorySpec `yaml:"directory,omitempty"`
}

// ArgoCDHelmSpec contains Helm-specific configuration.
type ArgoCDHelmSpec struct {
	ReleaseName     string                `yaml:"releaseName,omitempty"`
	ValueFiles      []string              `yaml:"valueFiles,omitempty"`
	Values          string                `yaml:"values,omitempty"`
	Parameters      []ArgoCDHelmParameter `yaml:"parameters,omitempty"`
	SkipCrds        bool                  `yaml:"skipCrds,omitempty"`
	PassCredentials bool                  `yaml:"passCredentials,omitempty"`
}

// ArgoCDHelmParameter is a Helm parameter override.
type ArgoCDHelmParameter struct {
	Name        string `yaml:"name"`
	Value       string `yaml:"value,omitempty"`
	ForceString bool   `yaml:"forceString,omitempty"`
}

// ArgoCDKustomizeSpec contains Kustomize-specific configuration.
type ArgoCDKustomizeSpec struct {
	NamePrefix   string            `yaml:"namePrefix,omitempty"`
	NameSuffix   string            `yaml:"nameSuffix,omitempty"`
	Images       []string          `yaml:"images,omitempty"`
	CommonLabels map[string]string `yaml:"commonLabels,omitempty"`
}

// ArgoCDDirectorySpec contains directory-specific configuration.
type ArgoCDDirectorySpec struct {
	Recurse bool               `yaml:"recurse,omitempty"`
	Jsonnet *ArgoCDJsonnetSpec `yaml:"jsonnet,omitempty"`
}

// ArgoCDJsonnetSpec contains Jsonnet-specific configuration.
type ArgoCDJsonnetSpec struct {
	ExtVars []ArgoCDJsonnetVar `yaml:"extVars,omitempty"`
	TLAs    []ArgoCDJsonnetVar `yaml:"tlas,omitempty"`
}

// ArgoCDJsonnetVar is a Jsonnet variable.
type ArgoCDJsonnetVar struct {
	Name  string `yaml:"name"`
	Value string `yaml:"value"`
	Code  bool   `yaml:"code,omitempty"`
}

// ArgoCDDestination defines where to deploy the application.
type ArgoCDDestination struct {
	Server    string `yaml:"server,omitempty"`
	Name      string `yaml:"name,omitempty"`
	Namespace string `yaml:"namespace,omitempty"`
}

// ArgoCDSyncPolicy defines the sync policy.
type ArgoCDSyncPolicy struct {
	Automated   *ArgoCDAutomatedSync `yaml:"automated,omitempty"`
	SyncOptions []string             `yaml:"syncOptions,omitempty"`
	Retry       *ArgoCDRetryPolicy   `yaml:"retry,omitempty"`
}

// ArgoCDAutomatedSync enables automatic syncing.
type ArgoCDAutomatedSync struct {
	Prune      bool `yaml:"prune,omitempty"`
	SelfHeal   bool `yaml:"selfHeal,omitempty"`
	AllowEmpty bool `yaml:"allowEmpty,omitempty"`
}

// ArgoCDRetryPolicy defines retry behavior.
type ArgoCDRetryPolicy struct {
	Limit   int                  `yaml:"limit,omitempty"`
	Backoff *ArgoCDBackoffPolicy `yaml:"backoff,omitempty"`
}

// ArgoCDBackoffPolicy defines backoff behavior.
type ArgoCDBackoffPolicy struct {
	Duration    string `yaml:"duration,omitempty"`
	Factor      int    `yaml:"factor,omitempty"`
	MaxDuration string `yaml:"maxDuration,omitempty"`
}

// ArgoCDIgnoreDiff defines fields to ignore during diff.
type ArgoCDIgnoreDiff struct {
	Group             string   `yaml:"group,omitempty"`
	Kind              string   `yaml:"kind,omitempty"`
	Name              string   `yaml:"name,omitempty"`
	Namespace         string   `yaml:"namespace,omitempty"`
	JSONPointers      []string `yaml:"jsonPointers,omitempty"`
	JQPathExpressions []string `yaml:"jqPathExpressions,omitempty"`
}

// ArgoCDAppProject represents an ArgoCD AppProject resource.
type ArgoCDAppProject struct {
	APIVersion string               `yaml:"apiVersion"`
	Kind       string               `yaml:"kind"`
	Metadata   ArgoCDMetadata       `yaml:"metadata"`
	Spec       ArgoCDAppProjectSpec `yaml:"spec"`
}

// ArgoCDAppProjectSpec is the spec for AppProject.
type ArgoCDAppProjectSpec struct {
	Description                string              `yaml:"description,omitempty"`
	SourceRepos                []string            `yaml:"sourceRepos"`
	SourceNamespaces           []string            `yaml:"sourceNamespaces,omitempty"`
	Destinations               []ArgoCDProjectDest `yaml:"destinations"`
	ClusterResourceWhitelist   []ArgoCDGroupKind   `yaml:"clusterResourceWhitelist,omitempty"`
	NamespaceResourceWhitelist []ArgoCDGroupKind   `yaml:"namespaceResourceWhitelist,omitempty"`
}

// ArgoCDProjectDest defines a destination for a project.
type ArgoCDProjectDest struct {
	Server    string `yaml:"server,omitempty"`
	Name      string `yaml:"name,omitempty"`
	Namespace string `yaml:"namespace"`
}

// ArgoCDGroupKind is a Kubernetes API group/kind.
type ArgoCDGroupKind struct {
	Group string `yaml:"group"`
	Kind  string `yaml:"kind"`
}

// ArgoCDMetadata contains Kubernetes object metadata.
type ArgoCDMetadata struct {
	Name        string            `yaml:"name"`
	Namespace   string            `yaml:"namespace,omitempty"`
	Labels      map[string]string `yaml:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty"`
	Finalizers  []string          `yaml:"finalizers,omitempty"`
}

// NewArgoCDApplication creates a new Application with defaults.
func NewArgoCDApplication(name, namespace, project string) *ArgoCDApplication {
	return &ArgoCDApplication{
		APIVersion: "argoproj.io/v1alpha1",
		Kind:       "Application",
		Metadata: ArgoCDMetadata{
			Name:      name,
			Namespace: namespace,
		},
		Spec: ArgoCDApplicationSpec{
			Project: project,
		},
	}
}

// NewArgoCDHelmApplication creates a new Application for a Helm chart.
func NewArgoCDHelmApplication(name, namespace, project, repoURL, chart, version, destServer, destNamespace string) *ArgoCDApplication {
	app := NewArgoCDApplication(name, namespace, project)
	app.Spec.Source = &ArgoCDSource{
		RepoURL:        repoURL,
		Chart:          chart,
		TargetRevision: version,
		Helm:           &ArgoCDHelmSpec{},
	}
	app.Spec.Destination = ArgoCDDestination{
		Server:    destServer,
		Namespace: destNamespace,
	}
	return app
}

// NewArgoCDAppProject creates a new AppProject with defaults.
func NewArgoCDAppProject(name, namespace string) *ArgoCDAppProject {
	return &ArgoCDAppProject{
		APIVersion: "argoproj.io/v1alpha1",
		Kind:       "AppProject",
		Metadata: ArgoCDMetadata{
			Name:      name,
			Namespace: namespace,
		},
		Spec: ArgoCDAppProjectSpec{
			SourceRepos:              []string{"*"},
			Destinations:             []ArgoCDProjectDest{{Server: "*", Namespace: "*"}},
			ClusterResourceWhitelist: []ArgoCDGroupKind{{Group: "*", Kind: "*"}},
		},
	}
}

// SetAutomatedSync enables automated sync with common options.
func (a *ArgoCDApplication) SetAutomatedSync(prune, selfHeal bool) {
	a.Spec.SyncPolicy = &ArgoCDSyncPolicy{
		Automated: &ArgoCDAutomatedSync{
			Prune:    prune,
			SelfHeal: selfHeal,
		},
		SyncOptions: []string{
			"CreateNamespace=true",
		},
	}
}
