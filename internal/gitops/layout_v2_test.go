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

// TestLayoutV2ClusterFiles_EmptyConfigs verifies the conditional
// infra-configs emission per ADR-017 revision 3: when the tree has no
// content under infrastructure/configs/, the export emits ONLY
// infra-controllers (no infra-configs Flux Kustomization), and
// apps.yaml depends on infra-controllers directly. Matches
// butler-observability-pipeline-reference's actual pattern — that
// reference repo has empty infrastructure/configs/ and emits this
// shape.
func TestLayoutV2ClusterFiles_EmptyConfigs(t *testing.T) {
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
	if !strings.Contains(string(infra), "name: infra-controllers") {
		t.Errorf("infrastructure.yaml missing infra-controllers Kustomization: %s", infra)
	}
	if !strings.Contains(string(infra), "wait: true") {
		t.Errorf("infrastructure.yaml missing wait: true on infra-controllers: %s", infra)
	}
	if strings.Contains(string(infra), "name: infra-configs") {
		t.Errorf("infrastructure.yaml should NOT emit infra-configs when configs/ is empty (conditional emission): %s", infra)
	}

	apps := tree["clusters/usini2kpbtlrkn/apps.yaml"]
	if !strings.Contains(string(apps), "name: apps") {
		t.Errorf("apps.yaml missing apps Kustomization: %s", apps)
	}
	if !strings.Contains(string(apps), "name: infra-controllers") {
		t.Errorf("apps.yaml must dependsOn: infra-controllers when infra-configs absent: %s", apps)
	}
	if strings.Contains(string(apps), "name: infra-configs") {
		t.Errorf("apps.yaml should NOT dependsOn: infra-configs when configs/ is empty: %s", apps)
	}
}

// TestLayoutV2ClusterFiles_WithConfigs verifies the conditional emission
// fires the OTHER way: when content lands in infrastructure/configs/
// (here via a SealedSecret), both infra-controllers AND infra-configs
// are emitted, and apps.yaml depends on infra-configs.
func TestLayoutV2ClusterFiles_WithConfigs(t *testing.T) {
	in := ExportInput{
		ClusterName: "usini2kpbtlrkn",
		Env:         "prd",
		Helm:        &DiscoveryResult{},
		Native: &NativeDiscoveryResult{
			SealedSecrets: []*DiscoveredNative{
				wrap("SealedSecret", newUnstructured("bitnami.com/v1alpha1", "SealedSecret", "entra-oidc", "butler-system")),
			},
		},
	}
	tree, err := GenerateLayoutV2(in)
	if err != nil {
		t.Fatalf("GenerateLayoutV2: %v", err)
	}

	infra := tree["clusters/usini2kpbtlrkn/infrastructure.yaml"]
	if !strings.Contains(string(infra), "name: infra-controllers") {
		t.Errorf("infrastructure.yaml missing infra-controllers Kustomization: %s", infra)
	}
	if !strings.Contains(string(infra), "name: infra-configs") {
		t.Errorf("infrastructure.yaml must emit infra-configs when configs/ has content: %s", infra)
	}
	if !strings.Contains(string(infra), "wait: true") {
		t.Errorf("infrastructure.yaml missing wait: true: %s", infra)
	}

	apps := tree["clusters/usini2kpbtlrkn/apps.yaml"]
	if !strings.Contains(string(apps), "name: infra-configs") {
		t.Errorf("apps.yaml must dependsOn: infra-configs when infra-configs is emitted: %s", apps)
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

// TestPruneSafetyAgainstLiveStateSurrogate verifies the prune-safety
// behavior under the ratified ADR-017 D4 design: a discovered resource
// with no specific PathForNative entry MUST route through the
// scope-tiered default placement (PathForNativeWithDefault) rather than
// either silently dropping (would prune) OR loudly failing the export
// (would block legitimate operator work). The coverage report (D5)
// separately surfaces unknown-kind placements so the operator sees them.
//
// This test was originally written to assert the OLD "fail loudly"
// behavior. ADR-017 D4 ratified the differentiated default placement
// as the replacement design — unknown kinds get a default bucket, not
// an error, AND the coverage report makes the placement visible. The
// coverage-report visibility is asserted separately in coverage_test.go.
func TestPruneSafetyAgainstLiveStateSurrogate(t *testing.T) {
	in := loadMinimalScenario(t)

	// Surrogate "live state": real input + an extra resource of a kind
	// not in PathForNative's explicit table (Workspace).
	workspace := newUnstructured("butler.butlerlabs.dev/v1alpha1", "Workspace", "team-a", "")

	// PathForNative explicit-table lookup returns empty — Workspace is
	// not in the v1 table. That's the entry condition for the default
	// placement.
	if got := PathForNative(&DiscoveredNative{Kind: "Workspace", Name: "team-a"}, in.Env); got != "" {
		t.Fatalf("Workspace should have empty PathForNative mapping (not in explicit table), got %q", got)
	}

	// PathForNativeWithDefault routes it via the scope-tiered default.
	// Workspace is a butler.butlerlabs.dev/v1alpha1 CRD instance,
	// namespaced (the surrogate has no namespace set, so it falls to the
	// user-workload bucket per D4's rule).
	defaultPath := PathForNativeWithDefault(
		&DiscoveredNative{Kind: "Workspace", Name: "team-a", APIVersion: "butler.butlerlabs.dev/v1alpha1"},
		in.Env,
	)
	if defaultPath == "" {
		t.Fatalf("PathForNativeWithDefault should never return empty for default placement")
	}
	wantPrefix := "apps/prd/workloads/butler-butlerlabs-dev/Workspace/"
	if !strings.HasPrefix(defaultPath, wantPrefix) {
		t.Errorf("Workspace should route to user-workload default bucket; got %q, want prefix %q", defaultPath, wantPrefix)
	}

	// Add it to the layout input and confirm GenerateLayoutV2 accepts
	// it (no longer errors on unknown kinds — placement is via default
	// bucket; coverage report surfaces the placement).
	in.Native.IdentityProviders = append(in.Native.IdentityProviders, &DiscoveredNative{
		Kind:       "Workspace",
		Name:       "team-a",
		APIVersion: "butler.butlerlabs.dev/v1alpha1",
		Object:     workspace,
	})
	tree, err := GenerateLayoutV2(in)
	if err != nil {
		t.Fatalf("GenerateLayoutV2 should not reject unknown kinds under ADR-017 D4 default placement: %v", err)
	}
	if _, ok := tree[defaultPath]; !ok {
		t.Errorf("Workspace should be emitted at default path %q, but tree does not contain it", defaultPath)
	}
}

// TestCapiStewardScopeTieredPlacement is the load-bearing test for the
// scope-tiered default placement (ADR-017 D4 revision 2): capi-steward's
// hand-rolled raw-YAML resources (CRDs + ClusterRoles + Deployment) MUST
// land in infrastructure/configs/ (cluster-scoped infra path), NOT in
// apps/<env>/workloads/ (the wrong-placement bug an earlier single-bucket
// default would have shipped).
func TestCapiStewardScopeTieredPlacement(t *testing.T) {
	env := "prd"
	cases := []struct {
		name      string
		apiVer    string
		kind      string
		objName   string
		objNS     string
		wantPath  string
	}{
		{
			name: "CRD: stewardcontrolplanes",
			apiVer:   "apiextensions.k8s.io/v1",
			kind:     "CustomResourceDefinition",
			objName:  "stewardcontrolplanes.controlplane.cluster.x-k8s.io",
			wantPath: "infrastructure/configs/apiextensions-k8s-io/CustomResourceDefinition/stewardcontrolplanes.controlplane.cluster.x-k8s.io.yaml",
		},
		{
			name: "CRD: stewardcontrolplanetemplates",
			apiVer:   "apiextensions.k8s.io/v1",
			kind:     "CustomResourceDefinition",
			objName:  "stewardcontrolplanetemplates.controlplane.cluster.x-k8s.io",
			wantPath: "infrastructure/configs/apiextensions-k8s-io/CustomResourceDefinition/stewardcontrolplanetemplates.controlplane.cluster.x-k8s.io.yaml",
		},
		{
			name: "ClusterRole: capi-steward-manager-role (cluster-scoped infra)",
			apiVer:   "rbac.authorization.k8s.io/v1",
			kind:     "ClusterRole",
			objName:  "capi-steward-manager-role",
			wantPath: "infrastructure/configs/rbac-authorization-k8s-io/ClusterRole/capi-steward-manager-role.yaml",
		},
		{
			name: "ClusterRoleBinding: capi-steward-manager-rolebinding",
			apiVer:   "rbac.authorization.k8s.io/v1",
			kind:     "ClusterRoleBinding",
			objName:  "capi-steward-manager-rolebinding",
			wantPath: "infrastructure/configs/rbac-authorization-k8s-io/ClusterRoleBinding/capi-steward-manager-rolebinding.yaml",
		},
		{
			name: "Deployment in steward-system (namespaced infra in known infra ns)",
			apiVer:   "apps/v1",
			kind:     "Deployment",
			objName:  "capi-steward-controller-manager",
			objNS:    "steward-system",
			wantPath: "infrastructure/configs/apps/Deployment/steward-system-capi-steward-controller-manager.yaml",
		},
		{
			name: "ServiceAccount in steward-system",
			apiVer:   "v1",
			kind:     "ServiceAccount",
			objName:  "capi-steward-controller-manager",
			objNS:    "steward-system",
			wantPath: "infrastructure/configs/core/ServiceAccount/steward-system-capi-steward-controller-manager.yaml",
		},
		{
			name: "Role in steward-system",
			apiVer:   "rbac.authorization.k8s.io/v1",
			kind:     "Role",
			objName:  "capi-steward-leader-election-role",
			objNS:    "steward-system",
			wantPath: "infrastructure/configs/rbac-authorization-k8s-io/Role/steward-system-capi-steward-leader-election-role.yaml",
		},
		// Negative control: a user workload-shaped object in a user
		// namespace correctly lands in apps/<env>/workloads/, NOT in
		// infrastructure/configs/.
		{
			name: "User CRD instance in user namespace (negative control)",
			apiVer:   "example.com/v1",
			kind:     "MyWorkload",
			objName:  "my-app",
			objNS:    "team-payments",
			wantPath: "apps/prd/workloads/example-com/MyWorkload/team-payments-my-app.yaml",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := &DiscoveredNative{
				APIVersion: c.apiVer,
				Kind:       c.kind,
				Name:       c.objName,
				Namespace:  c.objNS,
			}
			got := PathForNativeWithDefault(n, env)
			if got != c.wantPath {
				t.Errorf("PathForNativeWithDefault(%s/%s) = %q, want %q",
					c.kind, c.objName, got, c.wantPath)
			}
		})
	}
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
		tier = classifyUnmatchedRelease(rel)
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
