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
	"fmt"
	"sort"

	"sigs.k8s.io/yaml"
)

// LayoutV2 generates the canonical Flux tree described in ADR-016 from a
// discovered cluster state. Every emitted file flows through a
// DirectoryAccumulator so each directory ends up with a kustomization.yaml
// listing every resource in it — the in-tree half of the prune-safety
// guarantee (ADR-016 subsection 6.1).

// ExportInput is the discovered cluster state passed to LayoutV2.
type ExportInput struct {
	ClusterName string
	Env         string // apps overlay name (e.g. "prd")
	Helm        *DiscoveryResult
	Native      *NativeDiscoveryResult
}

// GenerateLayoutV2 returns the full set of files (path -> bytes) representing
// the v2 export tree.
func GenerateLayoutV2(in ExportInput) (map[string][]byte, error) {
	if in.ClusterName == "" {
		return nil, fmt.Errorf("layout v2: ClusterName required")
	}
	if in.Env == "" {
		return nil, fmt.Errorf("layout v2: Env required")
	}

	acc := NewDirectoryAccumulator()

	if in.Helm != nil {
		if err := emitHelmReleases(acc, in.Helm, in.Env); err != nil {
			return nil, err
		}
	}

	if in.Native != nil {
		if err := emitNativeResources(acc, in.Native, in.Env); err != nil {
			return nil, err
		}
	}

	emitClusterFiles(acc, in.ClusterName, in.Env)

	// Manual kustomization.yaml for apps/<env>/ — it must list each
	// ../base/<name> referenced app, the teams subdirectory if present,
	// and a patches block for every <name>-values.yaml emitted. The
	// DirectoryAccumulator's default resources-list synthesis doesn't know
	// about cross-directory references or patches.
	overrides := map[string]func(*KustomizeFile){
		fmt.Sprintf("apps/%s", in.Env): buildEnvKustomizationOverride(in.Helm, in.Native, in.Env, acc),
	}

	return acc.FinalizeWithKustomizations(overrides)
}

func emitHelmReleases(acc *DirectoryAccumulator, hr *DiscoveryResult, env string) error {
	all := append([]*DiscoveredRelease{}, hr.Matched...)
	all = append(all, hr.Unmatched...)

	for _, rel := range all {
		tier := releaseTier(rel)
		switch tier {
		case TierInfrastructure:
			if err := emitInfrastructureRelease(acc, rel); err != nil {
				return fmt.Errorf("infra release %s: %w", rel.Name, err)
			}
		case TierApps:
			if err := emitAppRelease(acc, rel, env); err != nil {
				return fmt.Errorf("app release %s: %w", rel.Name, err)
			}
		default:
			return fmt.Errorf("release %s: unknown tier %q", rel.Name, tier)
		}
	}
	return nil
}

// releaseTier returns the layout tier for a discovered Helm release.
// Matched releases use the Category populated from AddonDefinition.Tier
// (ADR-015). Unmatched releases fall to the namespace heuristic.
func releaseTier(rel *DiscoveredRelease) string {
	if rel.Category != "" {
		switch rel.Category {
		case TierInfrastructure:
			return TierInfrastructure
		case TierApps:
			return TierApps
		}
	}
	target := rel.Namespace
	if rel.Category == "" {
		// Discovery sets Category from tier for matched releases; for
		// unmatched it is unset before this point. Use targetNamespace
		// which discovery stores as Namespace (the release's installed
		// namespace).
	}
	return classifyUnmatchedRelease(target)
}

// emitInfrastructureRelease writes infrastructure/controllers/<name>.yaml
// as a single consolidated file: optional Namespace, HelmRepository, and
// HelmRelease joined by `---`. Matches butler-crop-live-infra's
// infrastructure/controllers/ shape.
func emitInfrastructureRelease(acc *DirectoryAccumulator, rel *DiscoveredRelease) error {
	docs := [][]byte{}

	if rel.Namespace != "" && rel.Namespace != "flux-system" {
		ns := NewK8sNamespace(rel.Namespace)
		nsYAML, err := yaml.Marshal(ns)
		if err != nil {
			return fmt.Errorf("marshal namespace: %w", err)
		}
		docs = append(docs, nsYAML)
	}

	repoName := sanitizeName(rel.Chart)
	if rel.Name != "" {
		repoName = sanitizeName(rel.Name)
	}
	helmRepo := NewFluxHelmRepository(repoName, "flux-system", rel.RepoURL)
	repoYAML, err := yaml.Marshal(helmRepo)
	if err != nil {
		return fmt.Errorf("marshal helmrepository: %w", err)
	}
	docs = append(docs, repoYAML)

	helmRelease := buildHelmReleaseFromDiscovered(rel, repoName)
	relYAML, err := yaml.Marshal(helmRelease)
	if err != nil {
		return fmt.Errorf("marshal helmrelease: %w", err)
	}
	docs = append(docs, relYAML)

	content := joinYAMLDocs(docs)
	acc.Add(fmt.Sprintf("infrastructure/controllers/%s.yaml", rel.Name), content)
	return nil
}

// emitAppRelease writes apps/base/<name>/{repository,release,kustomization
// optional namespace}.yaml plus an empty apps/<env>/<name>-values.yaml
// stub for env-specific overrides. The base directory's kustomization.yaml
// is synthesized by the accumulator; the env <name>-values.yaml is a
// HelmRelease strategic-merge patch (empty in v1 per Decision B —
// single-cluster export, multi-cluster splitter deferred).
func emitAppRelease(acc *DirectoryAccumulator, rel *DiscoveredRelease, env string) error {
	baseDir := fmt.Sprintf("apps/base/%s", rel.Name)

	repoName := sanitizeName(rel.Chart)
	if rel.Name != "" {
		repoName = sanitizeName(rel.Name)
	}
	helmRepo := NewFluxHelmRepository(repoName, "flux-system", rel.RepoURL)
	repoYAML, err := yaml.Marshal(helmRepo)
	if err != nil {
		return fmt.Errorf("marshal helmrepository: %w", err)
	}
	acc.Add(fmt.Sprintf("%s/repository.yaml", baseDir), repoYAML)

	helmRelease := buildHelmReleaseFromDiscovered(rel, repoName)
	relYAML, err := yaml.Marshal(helmRelease)
	if err != nil {
		return fmt.Errorf("marshal helmrelease: %w", err)
	}
	acc.Add(fmt.Sprintf("%s/release.yaml", baseDir), relYAML)

	// Empty env-values stub. Keeps the v2 path shape forward-compatible
	// with multi-cluster splitting (Decision B).
	envValues := buildEnvValuesPatch(rel.Name)
	envValuesYAML, err := yaml.Marshal(envValues)
	if err != nil {
		return fmt.Errorf("marshal env values: %w", err)
	}
	acc.Add(fmt.Sprintf("apps/%s/%s-values.yaml", env, rel.Name), envValuesYAML)

	return nil
}

// buildEnvValuesPatch returns the empty HelmRelease patch used as the
// v1 env-overlay stub. Strategic-merge by name, no values overrides.
func buildEnvValuesPatch(releaseName string) *FluxHelmRelease {
	return &FluxHelmRelease{
		APIVersion: "helm.toolkit.fluxcd.io/v2",
		Kind:       "HelmRelease",
		Metadata: FluxMetadata{
			Name: releaseName,
		},
		Spec: FluxHelmReleaseSpec{
			Values: map[string]interface{}{},
		},
	}
}

func buildHelmReleaseFromDiscovered(rel *DiscoveredRelease, repoName string) *FluxHelmRelease {
	hr := NewFluxHelmRelease(rel.Name, "flux-system")
	hr.Spec.ReleaseName = rel.Name
	hr.Spec.Chart = FluxHelmChartTemplate{
		Spec: FluxHelmChartTemplateSpec{
			Chart:    rel.Chart,
			Version:  rel.ChartVersion,
			Interval: "1h",
			SourceRef: FluxCrossNamespaceRef{
				Kind:      "HelmRepository",
				Name:      repoName,
				Namespace: "flux-system",
			},
		},
	}
	if rel.Namespace != "" {
		hr.Spec.TargetNamespace = rel.Namespace
		hr.Spec.Install = &FluxInstall{CreateNamespace: true}
	}
	if len(rel.Values) > 0 {
		hr.Spec.Values = rel.Values
	}
	return hr
}

func emitNativeResources(acc *DirectoryAccumulator, n *NativeDiscoveryResult, env string) error {
	all := []*DiscoveredNative{}
	all = append(all, n.IdentityProviders...)
	all = append(all, n.NetworkPools...)
	all = append(all, n.ProviderConfigs...)
	all = append(all, n.Teams...)
	all = append(all, n.ClusterCreationPolicies...)
	all = append(all, n.SealedSecrets...)
	all = append(all, n.MetalLBIPAddressPools...)
	all = append(all, n.MetalLBL2Advertisements...)
	all = append(all, n.StewardControlPlanes...)
	all = append(all, n.StewardControlPlaneTemplates...)
	if n.ButlerGitOpsConfig != nil {
		all = append(all, n.ButlerGitOpsConfig)
	}

	for _, item := range all {
		path := PathForNative(item, env)
		if path == "" {
			// Kind has no v2 placement rule. Per ADR-016 subsection 6.2,
			// silently dropping would weaken prune safety. Return an error
			// so the export fails loudly and the operator/discovery
			// adds an entry.
			return fmt.Errorf("native resource %s/%s/%s has no v2 placement rule",
				item.APIVersion, item.Kind, item.Name)
		}
		content, err := yaml.Marshal(item.Object.Object)
		if err != nil {
			return fmt.Errorf("marshal %s/%s: %w", item.Kind, item.Name, err)
		}
		acc.Add(path, content)
	}

	return nil
}

// emitClusterFiles emits clusters/<cluster>/{infrastructure,apps,kustomization}.yaml
// per ADR-016 subsection 2. The dependsOn chain is:
//   infra-controllers (wait: true) ← infra-configs ← apps
//
// Flux waits for controllers to become healthy before reconciling configs,
// and configs before apps. This ensures CRDs registered by controllers exist
// before native resources reference them.
func emitClusterFiles(acc *DirectoryAccumulator, clusterName, env string) {
	clusterDir := fmt.Sprintf("clusters/%s", clusterName)

	infraControllers := NewFluxKustomization("infra-controllers", "flux-system", "./infrastructure/controllers")
	infraControllers.Spec.Wait = true

	infraConfigs := NewFluxKustomization("infra-configs", "flux-system", "./infrastructure/configs")
	infraConfigs.Spec.DependsOn = []FluxDependencyReference{{Name: "infra-controllers"}}

	infraControllersYAML, _ := yaml.Marshal(infraControllers)
	infraConfigsYAML, _ := yaml.Marshal(infraConfigs)
	infraFile := joinYAMLDocs([][]byte{infraControllersYAML, infraConfigsYAML})
	acc.Add(fmt.Sprintf("%s/infrastructure.yaml", clusterDir), infraFile)

	appsKs := NewFluxKustomization("apps", "flux-system", fmt.Sprintf("./apps/%s", env))
	appsKs.Spec.DependsOn = []FluxDependencyReference{{Name: "infra-configs"}}
	appsYAML, _ := yaml.Marshal(appsKs)
	acc.Add(fmt.Sprintf("%s/apps.yaml", clusterDir), appsYAML)

	// clusters/<cluster>/kustomization.yaml lists the two pointer files plus
	// the bootstrap flux-system directory. flux-system is owned by `flux
	// bootstrap` and not regenerated by export, but the kustomization.yaml
	// entry pins it as a resource so Kustomize includes it in the build.
	clusterKust := NewKustomizeFile()
	clusterKust.Resources = []string{"flux-system", "infrastructure.yaml", "apps.yaml"}
	clusterKustYAML, _ := yaml.Marshal(clusterKust)
	acc.Add(fmt.Sprintf("%s/kustomization.yaml", clusterDir), clusterKustYAML)
}

// buildEnvKustomizationOverride synthesizes apps/<env>/kustomization.yaml.
// Resources point at ../base/<name> for each app release plus the teams
// directory if any teams were emitted. A `patches` block lists each
// <name>-values.yaml as a strategic-merge patch targeting its HelmRelease.
func buildEnvKustomizationOverride(hr *DiscoveryResult, n *NativeDiscoveryResult, env string, acc *DirectoryAccumulator) func(*KustomizeFile) {
	type envPatch struct {
		path   string
		target KustomizePatchTarget
	}

	var appReleases []string
	if hr != nil {
		for _, rel := range append(hr.Matched, hr.Unmatched...) {
			if releaseTier(rel) == TierApps {
				appReleases = append(appReleases, rel.Name)
			}
		}
	}
	sort.Strings(appReleases)

	hasTeams := n != nil && len(n.Teams) > 0
	if hasTeams {
		acc.EnsureDirectory(fmt.Sprintf("apps/%s/teams", env))
	}

	return func(kf *KustomizeFile) {
		var resources []string
		for _, name := range appReleases {
			resources = append(resources, fmt.Sprintf("../base/%s", name))
		}
		if hasTeams {
			resources = append(resources, "teams")
		}
		kf.Resources = resources

		var patches []envPatch
		for _, name := range appReleases {
			patches = append(patches, envPatch{
				path: fmt.Sprintf("%s-values.yaml", name),
				target: KustomizePatchTarget{
					Kind: "HelmRelease",
					Name: name,
				},
			})
		}
		// KustomizeFile.Resources is the canonical field; the patches block
		// is not in the existing KustomizeFile type. We extend by marshaling
		// a richer struct via override-only path below: callers that need
		// patches set them via the extended KustomizeFile.Patches slice,
		// which we add to the type in the same change.
		kf.Patches = make([]KustomizePatch, 0, len(patches))
		for _, p := range patches {
			kf.Patches = append(kf.Patches, KustomizePatch{
				Path:   p.path,
				Target: p.target,
			})
		}
	}
}

// joinYAMLDocs concatenates marshaled YAML documents with a `---` separator
// and a leading `---` so the output is a valid multi-document YAML stream
// readable by kubectl and kustomize.
func joinYAMLDocs(docs [][]byte) []byte {
	var buf bytes.Buffer
	for _, d := range docs {
		buf.WriteString("---\n")
		trimmed := bytes.TrimRight(d, "\n")
		buf.Write(trimmed)
		buf.WriteString("\n")
	}
	return buf.Bytes()
}
