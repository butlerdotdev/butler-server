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
	"errors"
	"testing"

	butlerv1alpha1 "github.com/butlerdotdev/butler-api/api/v1alpha1"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"
	clienttesting "k8s.io/client-go/testing"
)

// detectFlux must populate Repository/Branch/Path from the Flux-created
// GitRepository and Kustomization CRs so the Management GitOps export
// modal pre-fills correctly. Before v0.7.2 those fields were stitched
// in by the handler after calling GetFluxGitRepositoryConfig separately;
// the unified path lets the UI rely on a single source.

func fluxDeployments() []runtime.Object {
	mk := func(name string) *appsv1.Deployment {
		d := &appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "flux-system"},
			Spec: appsv1.DeploymentSpec{
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						Containers: []corev1.Container{{Name: name, Image: "ghcr.io/fluxcd/" + name + ":v2.3.0"}},
					},
				},
			},
			Status: appsv1.DeploymentStatus{ReadyReplicas: 1},
		}
		return d
	}
	return []runtime.Object{
		mk("source-controller"),
		mk("kustomize-controller"),
		mk("helm-controller"),
	}
}

func gitRepositoryUnstructured(name, url, branch, tag, commit string) *unstructured.Unstructured {
	spec := map[string]interface{}{
		"url":      url,
		"interval": "1m",
	}
	ref := map[string]interface{}{}
	if branch != "" {
		ref["branch"] = branch
	}
	if tag != "" {
		ref["tag"] = tag
	}
	if commit != "" {
		ref["commit"] = commit
	}
	if len(ref) > 0 {
		spec["ref"] = ref
	}
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "source.toolkit.fluxcd.io/v1",
			"kind":       "GitRepository",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": "flux-system",
			},
			"spec": spec,
		},
	}
}

func kustomizationUnstructured(name, path string) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "kustomize.toolkit.fluxcd.io/v1",
			"kind":       "Kustomization",
			"metadata": map[string]interface{}{
				"name":      name,
				"namespace": "flux-system",
			},
			"spec": map[string]interface{}{
				"path": path,
			},
		},
	}
}

func newFakeDynamicClient(objs ...runtime.Object) dynamic.Interface {
	scheme := runtime.NewScheme()
	gvrMap := map[schema.GroupVersionResource]string{
		{Group: "source.toolkit.fluxcd.io", Version: "v1", Resource: "gitrepositories"}: "GitRepositoryList",
		{Group: "kustomize.toolkit.fluxcd.io", Version: "v1", Resource: "kustomizations"}: "KustomizationList",
	}
	return dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, gvrMap, objs...)
}

func TestDetectFlux_PopulatesRepositoryBranchPath(t *testing.T) {
	clientset := fake.NewSimpleClientset(fluxDeployments()...)
	dynClient := newFakeDynamicClient(
		gitRepositoryUnstructured("flux-system", "https://github.com/butlerdotdev/butler-mgmt-live.git", "main", "", ""),
		kustomizationUnstructured("flux-system", "clusters/management"),
	)

	status := detectFlux(context.Background(), clientset, dynClient)
	if status == nil {
		t.Fatal("expected non-nil GitOpsEngineStatus")
	}
	if status.Provider != "flux" || !status.Installed {
		t.Errorf("provider=%q installed=%v; want flux/true", status.Provider, status.Installed)
	}
	if status.Repository != "butlerdotdev/butler-mgmt-live" {
		t.Errorf("Repository = %q, want %q", status.Repository, "butlerdotdev/butler-mgmt-live")
	}
	if status.Branch != "main" {
		t.Errorf("Branch = %q, want %q", status.Branch, "main")
	}
	if status.Path != "clusters/management" {
		t.Errorf("Path = %q, want %q", status.Path, "clusters/management")
	}
}

func TestDetectFlux_RefFallbackToTag(t *testing.T) {
	clientset := fake.NewSimpleClientset(fluxDeployments()...)
	dynClient := newFakeDynamicClient(
		gitRepositoryUnstructured("flux-system", "https://github.com/butlerdotdev/butler-mgmt-live", "", "v1.2.3", ""),
		kustomizationUnstructured("flux-system", "clusters/management"),
	)

	status := detectFlux(context.Background(), clientset, dynClient)
	if status == nil {
		t.Fatal("expected non-nil GitOpsEngineStatus")
	}
	if status.Branch != "v1.2.3" {
		t.Errorf("Branch = %q, want tag %q (branch-missing-fallback)", status.Branch, "v1.2.3")
	}
}

func TestDetectFlux_RefFallbackToCommit(t *testing.T) {
	clientset := fake.NewSimpleClientset(fluxDeployments()...)
	dynClient := newFakeDynamicClient(
		gitRepositoryUnstructured("flux-system", "https://github.com/butlerdotdev/butler-mgmt-live", "", "", "abc1234def"),
		kustomizationUnstructured("flux-system", "clusters/management"),
	)

	status := detectFlux(context.Background(), clientset, dynClient)
	if status == nil {
		t.Fatal("expected non-nil GitOpsEngineStatus")
	}
	if status.Branch != "abc1234def" {
		t.Errorf("Branch = %q, want commit %q (tag-missing-fallback)", status.Branch, "abc1234def")
	}
}

func TestDetectFlux_EnabledEvenWithoutGitRepository(t *testing.T) {
	// Regression guard: GitRepository read failing or returning nothing
	// must not regress Flux detection itself. Installed=true should still
	// flow through so the UI shows GitOps enabled and the operator can
	// investigate why the bootstrap CRs are missing.
	clientset := fake.NewSimpleClientset(fluxDeployments()...)
	dynClient := newFakeDynamicClient()

	status := detectFlux(context.Background(), clientset, dynClient)
	if status == nil {
		t.Fatal("expected non-nil GitOpsEngineStatus even without bootstrap CRs")
	}
	if !status.Installed {
		t.Error("Installed = false; want true (detection must survive CR read miss)")
	}
	if status.Repository != "" {
		t.Errorf("Repository = %q, want empty when GitRepository missing", status.Repository)
	}
	if status.Branch != "" {
		t.Errorf("Branch = %q, want empty", status.Branch)
	}
	if status.Path != "" {
		t.Errorf("Path = %q, want empty", status.Path)
	}
}

func TestDetectFlux_EnabledWhenGitRepositoryReadErrors(t *testing.T) {
	// RBAC denial on gitrepositories must not regress Flux detection.
	// Simulated via a reactor returning Forbidden on list.
	clientset := fake.NewSimpleClientset(fluxDeployments()...)
	dynClient := newFakeDynamicClient()
	fakeDyn := dynClient.(*dynamicfake.FakeDynamicClient)
	fakeDyn.PrependReactor("list", "gitrepositories", func(action clienttesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("forbidden")
	})

	status := detectFlux(context.Background(), clientset, dynClient)
	if status == nil {
		t.Fatal("expected non-nil GitOpsEngineStatus even when list errors")
	}
	if !status.Installed {
		t.Error("Installed = false; want true despite list error")
	}
	if status.Repository != "" {
		t.Errorf("Repository = %q, want empty on list error", status.Repository)
	}
}

func TestDetectFlux_ReturnsNilWhenFluxAbsent(t *testing.T) {
	clientset := fake.NewSimpleClientset() // no flux deployments
	dynClient := newFakeDynamicClient()

	status := detectFlux(context.Background(), clientset, dynClient)
	if status != nil {
		t.Errorf("status = %+v, want nil when Flux is not installed", status)
	}
}

func TestDetectFlux_FallsBackToFirstGitRepositoryWhenNoneNamedFluxSystem(t *testing.T) {
	// Out-of-band installs may use a non-default GitRepository name.
	// The enrichment should still read the first available entry.
	clientset := fake.NewSimpleClientset(fluxDeployments()...)
	dynClient := newFakeDynamicClient(
		gitRepositoryUnstructured("custom-name", "https://github.com/example/repo", "develop", "", ""),
	)

	status := detectFlux(context.Background(), clientset, dynClient)
	if status == nil {
		t.Fatal("expected non-nil GitOpsEngineStatus")
	}
	if status.Repository != "example/repo" {
		t.Errorf("Repository = %q, want %q", status.Repository, "example/repo")
	}
	if status.Branch != "develop" {
		t.Errorf("Branch = %q, want develop", status.Branch)
	}
}

var _ kubernetes.Interface = (*fake.Clientset)(nil) // compile-time assertion

func TestAddonTierToReleasePath(t *testing.T) {
	layout := DefaultDirectoryLayout("test-cluster")

	tests := []struct {
		name     string
		addon    butlerv1alpha1.AddonDefinition
		wantTier string
		wantPath string
	}{
		{
			name: "explicit infrastructure tier",
			addon: butlerv1alpha1.AddonDefinition{
				Spec: butlerv1alpha1.AddonDefinitionSpec{
					Tier: butlerv1alpha1.AddonTierInfrastructure,
				},
			},
			wantTier: "infrastructure",
			wantPath: "infrastructure/sealed-secrets",
		},
		{
			name: "explicit apps tier",
			addon: butlerv1alpha1.AddonDefinition{
				Spec: butlerv1alpha1.AddonDefinitionSpec{
					Tier: butlerv1alpha1.AddonTierApps,
				},
			},
			wantTier: "apps",
			wantPath: "apps/sealed-secrets",
		},
		{
			name: "explicit tier overrides platform",
			addon: butlerv1alpha1.AddonDefinition{
				Spec: butlerv1alpha1.AddonDefinitionSpec{
					Tier:     butlerv1alpha1.AddonTierApps,
					Platform: true,
				},
			},
			wantTier: "apps",
			wantPath: "apps/sealed-secrets",
		},
		{
			name: "platform true infers infrastructure",
			addon: butlerv1alpha1.AddonDefinition{
				Spec: butlerv1alpha1.AddonDefinitionSpec{
					Platform: true,
				},
			},
			wantTier: "infrastructure",
			wantPath: "infrastructure/sealed-secrets",
		},
		{
			name: "non-platform defaults to apps",
			addon: butlerv1alpha1.AddonDefinition{
				Spec: butlerv1alpha1.AddonDefinitionSpec{},
			},
			wantTier: "apps",
			wantPath: "apps/sealed-secrets",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tier := tt.addon.GetEffectiveTier()
			if tier != tt.wantTier {
				t.Errorf("GetEffectiveTier() = %q, want %q", tier, tt.wantTier)
			}

			path := layout.GetReleasePath(tier, "sealed-secrets")
			if path != tt.wantPath {
				t.Errorf("GetReleasePath() = %q, want %q", path, tt.wantPath)
			}
		})
	}
}
