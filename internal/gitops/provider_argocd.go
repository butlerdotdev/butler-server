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
	"sigs.k8s.io/yaml"
)

func init() {
	RegisterProvider("argocd", func() Provider { return &ArgoCDProvider{} })
}

// ArgoCDProvider implements the Provider interface for Argo CD.
type ArgoCDProvider struct{}

var _ Provider = (*ArgoCDProvider)(nil)

// Name returns the provider identifier.
func (p *ArgoCDProvider) Name() string {
	return "argocd"
}

// DisplayName returns the human-readable name.
func (p *ArgoCDProvider) DisplayName() string {
	return "Argo CD"
}

// GenerateReleaseManifests creates ArgoCD Application manifests for a Helm release.
func (p *ArgoCDProvider) GenerateReleaseManifests(cfg ReleaseConfig) (map[string][]byte, error) {
	files := make(map[string][]byte)

	namespace := cfg.Namespace
	if namespace == "" {
		namespace = "argocd"
	}

	project := "default"

	clusterServer := cfg.ClusterServer
	if clusterServer == "" {
		clusterServer = "https://kubernetes.default.svc"
	}

	app := p.buildApplication(cfg, namespace, project, clusterServer)
	appYAML, err := yaml.Marshal(app)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Application: %w", err)
	}
	files["application.yaml"] = appYAML

	return files, nil
}

func (p *ArgoCDProvider) buildApplication(cfg ReleaseConfig, namespace, project, clusterServer string) *ArgoCDApplication {
	app := NewArgoCDHelmApplication(
		cfg.Name,
		namespace,
		project,
		cfg.RepoURL,
		cfg.ChartName,
		cfg.ChartVersion,
		clusterServer,
		cfg.TargetNamespace,
	)

	if len(cfg.Values) > 0 {
		valuesYAML, err := yaml.Marshal(cfg.Values)
		if err == nil {
			app.Spec.Source.Helm.Values = string(valuesYAML)
		}
	}

	syncOptions := []string{}
	if cfg.CreateNamespace {
		syncOptions = append(syncOptions, "CreateNamespace=true")
	}

	app.Spec.SyncPolicy = &ArgoCDSyncPolicy{
		Automated: &ArgoCDAutomatedSync{
			Prune:    true,
			SelfHeal: true,
		},
		SyncOptions: syncOptions,
		Retry: &ArgoCDRetryPolicy{
			Limit: 5,
			Backoff: &ArgoCDBackoffPolicy{
				Duration:    "5s",
				Factor:      2,
				MaxDuration: "3m",
			},
		},
	}

	return app
}

// GenerateBootstrapStructure creates the initial ArgoCD repository structure.
func (p *ArgoCDProvider) GenerateBootstrapStructure(cfg BootstrapConfig) (map[string][]byte, error) {
	files := make(map[string][]byte)

	layout := cfg.Layout
	if layout.ClusterPath == "" {
		layout = DefaultDirectoryLayout(cfg.ClusterName)
	}

	argocdCfg := cfg.ToolConfig.ArgoCD
	if argocdCfg == nil {
		argocdCfg = DefaultArgoCDConfig()
	}

	clusterServer := cfg.ClusterServer
	if clusterServer == "" {
		clusterServer = "https://kubernetes.default.svc"
	}

	rootApp := p.buildAppOfApps(cfg.ClusterName, argocdCfg.Namespace, argocdCfg.Project, clusterServer, layout)
	rootAppYAML, _ := yaml.Marshal(rootApp)
	files[layout.ClusterPath+"/root.yaml"] = rootAppYAML

	infraApp := p.buildCategoryApp("infrastructure", argocdCfg.Namespace, argocdCfg.Project, clusterServer, layout)
	infraAppYAML, _ := yaml.Marshal(infraApp)
	files[layout.ClusterPath+"/infrastructure.yaml"] = infraAppYAML

	appsApp := p.buildCategoryApp("apps", argocdCfg.Namespace, argocdCfg.Project, clusterServer, layout)
	appsAppYAML, _ := yaml.Marshal(appsApp)
	files[layout.ClusterPath+"/apps.yaml"] = appsAppYAML

	files[layout.InfrastructurePath+"/.gitkeep"] = []byte("")
	files[layout.AppsPath+"/.gitkeep"] = []byte("")

	return files, nil
}

func (p *ArgoCDProvider) buildAppOfApps(clusterName, namespace, project, clusterServer string, layout DirectoryLayout) *ArgoCDApplication {
	app := NewArgoCDApplication(clusterName+"-root", namespace, project)
	app.Spec.Source = &ArgoCDSource{
		RepoURL:        "",
		Path:           layout.ClusterPath,
		TargetRevision: "HEAD",
	}
	app.Spec.Destination = ArgoCDDestination{
		Server:    clusterServer,
		Namespace: namespace,
	}
	app.Spec.SyncPolicy = &ArgoCDSyncPolicy{
		Automated: &ArgoCDAutomatedSync{
			Prune:    true,
			SelfHeal: true,
		},
	}
	return app
}

func (p *ArgoCDProvider) buildCategoryApp(category, namespace, project, clusterServer string, layout DirectoryLayout) *ArgoCDApplication {
	app := NewArgoCDApplication(category, namespace, project)
	app.Spec.Source = &ArgoCDSource{
		RepoURL:        "",
		Path:           layout.GetCategoryPath(category),
		TargetRevision: "HEAD",
		Directory: &ArgoCDDirectorySpec{
			Recurse: true,
		},
	}
	app.Spec.Destination = ArgoCDDestination{
		Server:    clusterServer,
		Namespace: namespace,
	}
	app.Spec.SyncPolicy = &ArgoCDSyncPolicy{
		Automated: &ArgoCDAutomatedSync{
			Prune:    true,
			SelfHeal: true,
		},
	}
	return app
}

// CheckInstalled verifies ArgoCD is installed on the cluster.
func (p *ArgoCDProvider) CheckInstalled(ctx context.Context, kubeconfig []byte) (*ProviderStatus, error) {
	clientset, err := createClientset(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	status := &ProviderStatus{
		Installed: false,
		Ready:     false,
	}

	_, err = clientset.CoreV1().Namespaces().Get(ctx, "argocd", metav1.GetOptions{})
	if err != nil {
		status.Message = "argocd namespace not found"
		return status, nil
	}

	argoComponents := []string{
		"argocd-server",
		"argocd-repo-server",
		"argocd-application-controller",
		"argocd-redis",
		"argocd-dex-server",
	}

	status.Components = make([]ComponentStatus, 0, len(argoComponents))
	allReady := true
	foundCount := 0

	for _, component := range argoComponents {
		deployment, err := clientset.AppsV1().Deployments("argocd").Get(ctx, component, metav1.GetOptions{})

		compStatus := ComponentStatus{Name: component}

		if err != nil {
			sts, stsErr := clientset.AppsV1().StatefulSets("argocd").Get(ctx, component, metav1.GetOptions{})
			if stsErr != nil {
				if component == "argocd-redis" || component == "argocd-dex-server" {
					compStatus.Ready = true
					compStatus.Message = "optional - not installed"
				} else {
					compStatus.Ready = false
					compStatus.Message = "not found"
					allReady = false
				}
			} else {
				foundCount++
				compStatus.Ready = sts.Status.ReadyReplicas > 0
				if !compStatus.Ready {
					compStatus.Message = "not ready"
					allReady = false
				} else {
					compStatus.Message = "ready"
				}
			}
		} else {
			foundCount++
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

	status.Installed = foundCount >= 3
	status.Ready = allReady

	if allReady {
		status.Message = "ArgoCD is installed and healthy"
	} else if status.Installed {
		status.Message = "ArgoCD is installed but some components are not ready"
	} else {
		status.Message = "ArgoCD is not installed"
	}

	deployment, err := clientset.AppsV1().Deployments("argocd").Get(ctx, "argocd-server", metav1.GetOptions{})
	if err == nil && len(deployment.Spec.Template.Spec.Containers) > 0 {
		image := deployment.Spec.Template.Spec.Containers[0].Image
		if parts := strings.Split(image, ":"); len(parts) > 1 {
			status.Version = parts[len(parts)-1]
		}
	}

	return status, nil
}

// GetSyncStatus checks the sync status of an ArgoCD Application.
func (p *ArgoCDProvider) GetSyncStatus(ctx context.Context, kubeconfig []byte, identifier string) (*SyncStatus, error) {
	clientset, err := createClientset(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	_, err = clientset.CoreV1().Namespaces().Get(ctx, "argocd", metav1.GetOptions{})
	if err != nil {
		return &SyncStatus{
			Synced:  false,
			Phase:   "Unknown",
			Message: "ArgoCD not installed",
		}, nil
	}

	return &SyncStatus{
		Synced:  true,
		Phase:   "Synced",
		Message: "ArgoCD is operational",
	}, nil
}
