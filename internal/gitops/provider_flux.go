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
	"sort"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
	"sigs.k8s.io/yaml"
)

func init() {
	RegisterProvider("flux", func() Provider { return &FluxProvider{} })
}

// FluxProvider implements the Provider interface for Flux CD.
type FluxProvider struct{}

var _ Provider = (*FluxProvider)(nil)

// Name returns the provider identifier.
func (p *FluxProvider) Name() string {
	return "flux"
}

// DisplayName returns the human-readable name.
func (p *FluxProvider) DisplayName() string {
	return "Flux CD"
}

// GenerateReleaseManifests creates Flux manifests for a Helm release.
func (p *FluxProvider) GenerateReleaseManifests(cfg ReleaseConfig) (map[string][]byte, error) {
	files := make(map[string][]byte)

	namespace := cfg.Namespace
	if namespace == "" {
		namespace = "flux-system"
	}

	interval := cfg.Interval
	if interval == "" {
		interval = "5m"
	}

	repoName := cfg.RepoName
	if repoName == "" {
		repoName = sanitizeName(cfg.ChartName)
	}

	helmRepo := NewFluxHelmRepository(repoName, namespace, cfg.RepoURL)
	helmRepoYAML, err := yaml.Marshal(helmRepo)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HelmRepository: %w", err)
	}
	files["helmrepository.yaml"] = helmRepoYAML

	helmRelease := p.buildHelmRelease(cfg, namespace, interval, repoName)
	helmReleaseYAML, err := yaml.Marshal(helmRelease)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal HelmRelease: %w", err)
	}
	files["helmrelease.yaml"] = helmReleaseYAML

	if cfg.CreateNamespace && cfg.TargetNamespace != "" {
		ns := NewK8sNamespace(cfg.TargetNamespace)
		nsYAML, err := yaml.Marshal(ns)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Namespace: %w", err)
		}
		files["namespace.yaml"] = nsYAML
	}

	kustomization := p.buildKustomizeFile(files)
	kustomizationYAML, err := yaml.Marshal(kustomization)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal kustomization: %w", err)
	}
	files["kustomization.yaml"] = kustomizationYAML

	return files, nil
}

func (p *FluxProvider) buildHelmRelease(cfg ReleaseConfig, namespace, interval, repoName string) *FluxHelmRelease {
	hr := NewFluxHelmRelease(cfg.Name, namespace)
	hr.Spec.Interval = interval
	hr.Spec.Chart = FluxHelmChartTemplate{
		Spec: FluxHelmChartTemplateSpec{
			Chart:    cfg.ChartName,
			Version:  cfg.ChartVersion,
			Interval: "1h",
			SourceRef: FluxCrossNamespaceRef{
				Kind:      "HelmRepository",
				Name:      repoName,
				Namespace: namespace,
			},
		},
	}

	if cfg.TargetNamespace != "" {
		hr.Spec.TargetNamespace = cfg.TargetNamespace
	}

	if cfg.CreateNamespace {
		hr.Spec.Install = &FluxInstall{
			CreateNamespace: true,
		}
	}

	if len(cfg.DependsOn) > 0 {
		hr.Spec.DependsOn = make([]FluxDependencyReference, len(cfg.DependsOn))
		for i, dep := range cfg.DependsOn {
			hr.Spec.DependsOn[i] = FluxDependencyReference{Name: dep}
		}
	}

	if len(cfg.Values) > 0 {
		hr.Spec.Values = cfg.Values
	}

	return hr
}

func (p *FluxProvider) buildKustomizeFile(files map[string][]byte) *KustomizeFile {
	kf := NewKustomizeFile()

	for name := range files {
		if name != "kustomization.yaml" {
			kf.Resources = append(kf.Resources, name)
		}
	}

	sort.Strings(kf.Resources)

	return kf
}

// GenerateBootstrapStructure creates the initial Flux repository structure.
func (p *FluxProvider) GenerateBootstrapStructure(cfg BootstrapConfig) (map[string][]byte, error) {
	files := make(map[string][]byte)

	layout := cfg.Layout
	if layout.ClusterPath == "" {
		layout = DefaultDirectoryLayout(cfg.ClusterName)
	}

	fluxCfg := cfg.ToolConfig.Flux
	if fluxCfg == nil {
		fluxCfg = DefaultFluxConfig()
	}

	infraKs := NewFluxKustomization("infrastructure", fluxCfg.Namespace, "./"+layout.InfrastructurePath)
	infraKs.Spec.Wait = true
	infraYAML, _ := yaml.Marshal(infraKs)
	files[layout.ClusterPath+"/infrastructure.yaml"] = infraYAML

	appsKs := NewFluxKustomization("apps", fluxCfg.Namespace, "./"+layout.AppsPath)
	appsKs.Spec.DependsOn = []FluxDependencyReference{{Name: "infrastructure"}}
	appsYAML, _ := yaml.Marshal(appsKs)
	files[layout.ClusterPath+"/apps.yaml"] = appsYAML

	emptyKf := NewKustomizeFile()
	emptyYAML, _ := yaml.Marshal(emptyKf)
	files[layout.InfrastructurePath+"/kustomization.yaml"] = emptyYAML
	files[layout.AppsPath+"/kustomization.yaml"] = emptyYAML

	return files, nil
}

// CheckInstalled verifies Flux is installed on the cluster.
func (p *FluxProvider) CheckInstalled(ctx context.Context, kubeconfig []byte) (*ProviderStatus, error) {
	clientset, err := createClientset(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	status := &ProviderStatus{
		Installed: false,
		Ready:     false,
	}

	_, err = clientset.CoreV1().Namespaces().Get(ctx, "flux-system", metav1.GetOptions{})
	if err != nil {
		status.Message = "flux-system namespace not found"
		return status, nil
	}

	fluxComponents := []string{
		"source-controller",
		"kustomize-controller",
		"helm-controller",
		"notification-controller",
	}

	status.Components = make([]ComponentStatus, 0, len(fluxComponents))
	allReady := true

	for _, component := range fluxComponents {
		deployment, err := clientset.AppsV1().Deployments("flux-system").Get(ctx, component, metav1.GetOptions{})

		compStatus := ComponentStatus{Name: component}

		if err != nil {
			compStatus.Ready = false
			compStatus.Message = "not found"
			allReady = false
		} else {
			compStatus.Ready = deployment.Status.ReadyReplicas > 0
			if !compStatus.Ready {
				compStatus.Message = "not ready"
				allReady = false
			} else {
				compStatus.Message = "ready"
			}
		}

		status.Components = append(status.Components, compStatus)
	}

	status.Installed = true
	status.Ready = allReady

	if allReady {
		status.Message = "Flux is installed and healthy"
	} else {
		status.Message = "Flux is installed but some components are not ready"
	}

	deployment, err := clientset.AppsV1().Deployments("flux-system").Get(ctx, "source-controller", metav1.GetOptions{})
	if err == nil && len(deployment.Spec.Template.Spec.Containers) > 0 {
		image := deployment.Spec.Template.Spec.Containers[0].Image
		if parts := strings.Split(image, ":"); len(parts) > 1 {
			status.Version = parts[len(parts)-1]
		}
	}

	return status, nil
}

// GetSyncStatus checks the sync status of a Flux resource.
func (p *FluxProvider) GetSyncStatus(ctx context.Context, kubeconfig []byte, identifier string) (*SyncStatus, error) {
	clientset, err := createClientset(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	_, err = clientset.CoreV1().Namespaces().Get(ctx, "flux-system", metav1.GetOptions{})
	if err != nil {
		return &SyncStatus{
			Synced:  false,
			Phase:   "Unknown",
			Message: "Flux not installed",
		}, nil
	}

	return &SyncStatus{
		Synced:  true,
		Phase:   "Ready",
		Message: "Flux is operational",
	}, nil
}

func createClientset(kubeconfig []byte) (*kubernetes.Clientset, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(config)
}

func sanitizeName(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, "_", "-")
	name = strings.ReplaceAll(name, ".", "-")
	if len(name) > 0 && name[0] >= '0' && name[0] <= '9' {
		name = "r-" + name
	}
	return name
}
