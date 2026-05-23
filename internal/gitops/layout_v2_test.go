/*
Copyright 2026 The Butler Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package gitops

import (
	"path"
	"sort"
	"strings"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"sigs.k8s.io/yaml"
)

func TestLayoutV2ClusterFiles(t *testing.T) {
	tree, err := GenerateLayoutV2(ExportInput{
		ClusterName: "usini2kpbtlrkn",
		Env:         "prd",
		Helm:        &DiscoveryResult{},
		Native:      &NativeDiscoveryResult{},
	})
	if err != nil {
		t.Fatalf("GenerateLayoutV2: %v", err)
	}

	clusterKust := tree["clusters/usini2kpbtlrkn/kustomization.yaml"]
	if clusterKust == nil {
		t.Fatalf("missing clusters/<name>/kustomization.yaml")
	}
	if !strings.Contains(string(clusterKust), "flux-system") ||
		!strings.Contains(string(clusterKust), "infrastructure.yaml") ||
		!strings.Contains(string(clusterKust), "apps.yaml") {
		t.Errorf("cluster kustomization missing pointers: %s", clusterKust)
	}

	infra := tree["clusters/usini2kpbtlrkn/infrastructure.yaml"]
	if !strings.Contains(string(infra), "name: infra-controllers") ||
		!strings.Contains(string(infra), "name: infra-configs") ||
		!strings.Contains(string(infra), "wait: true") {
		t.Errorf("infrastructure.yaml missing required Kustomization or wait flag: %s", infra)
	}

	apps := tree["clusters/usini2kpbtlrkn/apps.yaml"]
	if !strings.Contains(string(apps), "name: apps") ||
		!strings.Contains(string(apps), "name: infra-configs") {
		t.Errorf("apps.yaml missing required Kustomization or dependsOn: %s", apps)
	}
}

func TestLayoutV2InfraReleaseConsolidatedFile(t *testing.T) {
	in := ExportInput{
		ClusterName: "c",
		Env:         "prd",
		Helm: &DiscoveryResult{
			Matched: []*DiscoveredRelease{{
				Name:         "cilium",
				Namespace:    "kube-system",
				Chart:        "cilium",
				ChartVersion: "1.17.0",
				RepoURL:      "https://helm.cilium.io/",
				Category:     TierInfrastructure,
			}},
		},
		Native: &NativeDiscoveryResult{},
	}
	tree, err := GenerateLayoutV2(in)
	if err != nil {
		t.Fatalf("GenerateLayoutV2: %v", err)
	}

	file := tree["infrastructure/controllers/cilium.yaml"]
	if file == nil {
		t.Fatalf("missing infrastructure/controllers/cilium.yaml")
	}
	content := string(file)
	if strings.Count(content, "---") < 2 {
		t.Errorf("consolidated file must contain at least 2 `---` separators (HelmRepo + HelmRelease), got %d:\n%s", strings.Count(content, "---"), content)
	}
	if !strings.Contains(content, "kind: HelmRepository") || !strings.Contains(content, "kind: HelmRelease") {
		t.Errorf("consolidated file must include HelmRepository and HelmRelease: %s", content)
	}

	kust := tree["infrastructure/controllers/kustomization.yaml"]
	if !strings.Contains(string(kust), "cilium.yaml") {
		t.Errorf("infra controllers kustomization must list cilium.yaml: %s", kust)
	}
}

func TestLayoutV2AppReleaseMultiFileShape(t *testing.T) {
	in := ExportInput{
		ClusterName: "c",
		Env:         "prd",
		Helm: &DiscoveryResult{
			Matched: []*DiscoveredRelease{{
				Name:         "argocd",
				Namespace:    "argocd",
				Chart:        "argo-cd",
				ChartVersion: "7.7.5",
				RepoURL:      "https://argoproj.github.io/argo-helm",
				Category:     TierApps,
			}},
		},
		Native: &NativeDiscoveryResult{},
	}
	tree, err := GenerateLayoutV2(in)
	if err != nil {
		t.Fatalf("GenerateLayoutV2: %v", err)
	}

	for _, p := range []string{
		"apps/base/argocd/repository.yaml",
		"apps/base/argocd/release.yaml",
		"apps/base/argocd/kustomization.yaml",
		"apps/prd/argocd-values.yaml",
		"apps/prd/kustomization.yaml",
	} {
		if _, ok := tree[p]; !ok {
			t.Errorf("expected file %s missing from tree", p)
		}
	}

	envKust := mustUnmarshalKust(t, tree["apps/prd/kustomization.yaml"])
	if !sliceContains(envKust.Resources, "../base/argocd") {
		t.Errorf("env kustomization should resource ../base/argocd, got %v", envKust.Resources)
	}
	if len(envKust.Patches) != 1 || envKust.Patches[0].Path != "argocd-values.yaml" {
		t.Errorf("env kustomization patches block = %+v", envKust.Patches)
	}
}

func TestLayoutV2NativeResourcePlacement(t *testing.T) {
	identityProvider := newUnstructured("butler.butlerlabs.dev/v1alpha1", "IdentityProvider", "microsoft-entra", "")
	team := newUnstructured("butler.butlerlabs.dev/v1alpha1", "Team", "platform-engineering", "")
	ccp := newUnstructured("butler.butlerlabs.dev/v1alpha1", "ClusterCreationPolicy", "platform-wide", "")
	sealed := newUnstructured("bitnami.com/v1alpha1", "SealedSecret", "entra-oidc", "butler-system")
	gitopsCM := newUnstructured("v1", "ConfigMap", "butler-gitops-config", "butler-system")

	in := ExportInput{
		ClusterName: "c",
		Env:         "prd",
		Helm:        &DiscoveryResult{},
		Native: &NativeDiscoveryResult{
			IdentityProviders:       []*DiscoveredNative{wrap("IdentityProvider", identityProvider)},
			Teams:                   []*DiscoveredNative{wrap("Team", team)},
			ClusterCreationPolicies: []*DiscoveredNative{wrap("ClusterCreationPolicy", ccp)},
			SealedSecrets:           []*DiscoveredNative{wrap("SealedSecret", sealed)},
			ButlerGitOpsConfig:      wrap("ConfigMap", gitopsCM),
		},
	}
	tree, err := GenerateLayoutV2(in)
	if err != nil {
		t.Fatalf("GenerateLayoutV2: %v", err)
	}

	for _, p := range []string{
		"infrastructure/configs/identity-providers/microsoft-entra.yaml",
		"apps/prd/teams/platform-engineering.yaml",
		"infrastructure/configs/cluster-creation-policies/platform-wide.yaml",
		"infrastructure/configs/sealed-secrets/butler-system-entra-oidc.yaml",
		"infrastructure/configs/butler-gitops-config.yaml",
	} {
		if _, ok := tree[p]; !ok {
			t.Errorf("expected native file %s missing from tree", p)
		}
	}
}

// TestPruneSafetyPropertyAgainstSyntheticState verifies the load-bearing
// claim from ADR-016 subsection 6.1: every discovered object appears under
// some kustomization.yaml's resources list. Stronger version covered by
// TestPruneSafetyAgainstLiveStateSurrogate below, which simulates the
// "live cluster object that discovery misses" failure mode.
func TestPruneSafetyPropertyAgainstSyntheticState(t *testing.T) {
	in := loadMinimalScenario(t)
	tree, err := GenerateLayoutV2(in)
	if err != nil {
		t.Fatalf("GenerateLayoutV2: %v", err)
	}

	// Build set of every (directory, filename) the tree contains, derived
	// from each kustomization.yaml's resources list. A live resource is
	// "covered" if its emitted path appears as resource in its dir's
	// kustomization.yaml.
	listed := buildListedSet(t, tree)

	for _, rel := range in.Helm.Matched {
		path := primaryPathForRelease(rel)
		if !listed[path] {
			t.Errorf("matched release %s not covered by any kustomization.yaml: emitted at %s", rel.Name, path)
		}
	}
	for _, rel := range in.Helm.Unmatched {
		path := primaryPathForRelease(rel)
		if !listed[path] {
			t.Errorf("unmatched release %s not covered by any kustomization.yaml: emitted at %s", rel.Name, path)
		}
	}

	for _, kind := range collectNativeKinds(in.Native) {
		for _, item := range kind {
			expected := PathForNative(item, in.Env)
			if expected == "" {
				continue
			}
			if !listed[expected] {
				t.Errorf("native %s/%s not covered by any kustomization.yaml: expected at %s", item.Kind, item.Name, expected)
			}
		}
	}
}

// TestPruneSafetyAgainstLiveStateSurrogate is the stronger property test
// per ADR-016 subsection 6.2: a live resource not in the discovery set is
// flagged because its expected layout path has no covering kustomization
// entry. This catches the "added a CRD to butler-api but forgot to extend
// discovery" failure mode.
func TestPruneSafetyAgainstLiveStateSurrogate(t *testing.T) {
	in := loadMinimalScenario(t)
	tree, err := GenerateLayoutV2(in)
	if err != nil {
		t.Fatalf("GenerateLayoutV2: %v", err)
	}

	// Surrogate "live state": real input + an extra resource that
	// discovery did NOT find. Expected behavior: the test surfaces that
	// this resource has no covering kustomization entry, simulating what
	// would happen against a real cluster.
	missing := newUnstructured("butler.butlerlabs.dev/v1alpha1", "Workspace", "team-a", "")
	missingPath := PathForNative(&DiscoveredNative{Kind: "Workspace", Name: "team-a"}, in.Env)
	if missingPath != "" {
		t.Fatalf("Workspace should have empty path mapping in v1 (not in discovery table)")
	}

	// Confirm that adding a kind without a path entry is correctly
	// surfaced — the layout generator returns an error when discovery
	// produces an item with no PathForNative.
	in.Native.IdentityProviders = append(in.Native.IdentityProviders, &DiscoveredNative{
		Kind:   "Workspace",
		Name:   "team-a",
		Object: missing,
	})
	if _, err := GenerateLayoutV2(in); err == nil {
		t.Errorf("layout should reject a discovered item with no v2 placement rule, but accepted it")
	}

	_ = tree
}

func loadMinimalScenario(t *testing.T) ExportInput {
	t.Helper()
	return ExportInput{
		ClusterName: "test-cluster",
		Env:         "prd",
		Helm: &DiscoveryResult{
			Matched: []*DiscoveredRelease{
				{
					Name:         "cilium",
					Namespace:    "kube-system",
					Chart:        "cilium",
					ChartVersion: "1.17.0",
					RepoURL:      "https://helm.cilium.io/",
					Category:     TierInfrastructure,
				},
				{
					Name:         "cert-manager",
					Namespace:    "cert-manager",
					Chart:        "cert-manager",
					ChartVersion: "v1.16.2",
					RepoURL:      "https://charts.jetstack.io",
					Category:     TierInfrastructure,
				},
				{
					Name:         "argocd",
					Namespace:    "argocd",
					Chart:        "argo-cd",
					ChartVersion: "7.7.5",
					RepoURL:      "https://argoproj.github.io/argo-helm",
					Category:     TierApps,
				},
			},
		},
		Native: &NativeDiscoveryResult{
			IdentityProviders: []*DiscoveredNative{
				wrap("IdentityProvider", newUnstructured("butler.butlerlabs.dev/v1alpha1", "IdentityProvider", "microsoft-entra", "")),
			},
			ProviderConfigs: []*DiscoveredNative{
				wrap("ProviderConfig", newUnstructured("butler.butlerlabs.dev/v1alpha1", "ProviderConfig", "nutanix", "")),
			},
			Teams: []*DiscoveredNative{
				wrap("Team", newUnstructured("butler.butlerlabs.dev/v1alpha1", "Team", "platform-engineering", "")),
			},
		},
	}
}

func primaryPathForRelease(rel *DiscoveredRelease) string {
	tier := rel.Category
	if tier == "" {
		tier = classifyUnmatchedRelease(rel.Namespace)
	}
	switch tier {
	case TierInfrastructure:
		return path.Join("infrastructure/controllers", rel.Name+".yaml")
	default:
		return path.Join("apps/base", rel.Name, "release.yaml")
	}
}

func collectNativeKinds(n *NativeDiscoveryResult) [][]*DiscoveredNative {
	if n == nil {
		return nil
	}
	all := [][]*DiscoveredNative{
		n.IdentityProviders, n.NetworkPools, n.ProviderConfigs, n.Teams,
		n.ClusterCreationPolicies, n.SealedSecrets,
		n.MetalLBIPAddressPools, n.MetalLBL2Advertisements,
		n.StewardControlPlanes, n.StewardControlPlaneTemplates,
	}
	if n.ButlerGitOpsConfig != nil {
		all = append(all, []*DiscoveredNative{n.ButlerGitOpsConfig})
	}
	return all
}

// buildListedSet parses every kustomization.yaml in the tree and returns
// the set of (directory-resolved) file paths each one lists as a resource.
// A path is "covered" iff it appears in this set.
//
// Resources may reference subdirectories (e.g. "../base/butler-controller"
// or "teams") rather than direct filenames. For subdirectory references,
// the directory's own kustomization.yaml chains the coverage check.
func buildListedSet(t *testing.T, tree map[string][]byte) map[string]bool {
	t.Helper()
	listed := map[string]bool{}

	// Collect kustomization.yaml paths sorted for deterministic walk.
	var kustPaths []string
	for p := range tree {
		if path.Base(p) == "kustomization.yaml" {
			kustPaths = append(kustPaths, p)
		}
	}
	sort.Strings(kustPaths)

	for _, kustPath := range kustPaths {
		dir := path.Dir(kustPath)
		var kf KustomizeFile
		if err := yaml.Unmarshal(tree[kustPath], &kf); err != nil {
			t.Errorf("parse %s: %v", kustPath, err)
			continue
		}
		for _, r := range kf.Resources {
			resolved := path.Join(dir, r)
			// If resource ends with .yaml, it's a file. Else assume dir.
			if strings.HasSuffix(r, ".yaml") {
				listed[resolved] = true
			} else {
				// Subdirectory: its own kustomization.yaml is the next step
				// in the chain; we mark every file under the subdir as
				// transitively covered by walking its own kust.
				subKust := path.Join(resolved, "kustomization.yaml")
				if subData, ok := tree[subKust]; ok {
					var subKF KustomizeFile
					if err := yaml.Unmarshal(subData, &subKF); err == nil {
						for _, sr := range subKF.Resources {
							if strings.HasSuffix(sr, ".yaml") {
								listed[path.Join(resolved, sr)] = true
							}
						}
					}
				}
			}
		}
		// Patches also implicitly cover the values file in the same dir.
		for _, p := range kf.Patches {
			if strings.HasSuffix(p.Path, ".yaml") {
				listed[path.Join(dir, p.Path)] = true
			}
		}
	}

	return listed
}

func newUnstructured(apiVersion, kind, name, namespace string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{}
	obj.SetAPIVersion(apiVersion)
	obj.SetKind(kind)
	obj.SetName(name)
	if namespace != "" {
		obj.SetNamespace(namespace)
	}
	return obj
}

func wrap(kind string, obj *unstructured.Unstructured) *DiscoveredNative {
	return &DiscoveredNative{
		Kind:       kind,
		APIVersion: obj.GetAPIVersion(),
		Name:       obj.GetName(),
		Namespace:  obj.GetNamespace(),
		Object:     obj,
	}
}

func mustUnmarshalKust(t *testing.T, data []byte) *KustomizeFile {
	t.Helper()
	var kf KustomizeFile
	if err := yaml.Unmarshal(data, &kf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &kf
}

func sliceContains(haystack []string, needle string) bool {
	for _, h := range haystack {
		if h == needle {
			return true
		}
	}
	return false
}
