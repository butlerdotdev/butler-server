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
	"strings"

	"sigs.k8s.io/yaml"
)

// LayoutV2 generates the canonical Flux tree described in ADR-016 from a
// discovered cluster state. Every emitted file flows through a
// DirectoryAccumulator so each directory ends up with a kustomization.yaml
// listing every resource in it — the in-tree half of the prune-safety
// guarantee (ADR-016 subsection 6.1).

// ExportInput is the discovered cluster state passed to LayoutV2.
//
// NamespaceMeta carries labels/annotations from live Namespace objects
// for the namespaces the export references — required to preserve
// metadata like pod-security labels and network-policy targeting that
// would otherwise be lost in the synthesized bare Namespace emit. When
// nil or empty, the layout falls back to bare Namespaces for backward
// compatibility (mgmt clusters typically don't carry custom namespace
// metadata, tenant clusters do).
type ExportInput struct {
	ClusterName   string
	Env           string // apps overlay name (e.g. "prd")
	Helm          *DiscoveryResult
	Native        *NativeDiscoveryResult
	NamespaceMeta NamespaceMetadataMap
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
		if err := emitHelmReleases(acc, in.Helm, in.Env, in.NamespaceMeta); err != nil {
			return nil, err
		}
	}

	if in.Native != nil {
		if err := emitNativeResources(acc, in.Native, in.Helm, in.Env); err != nil {
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
		fmt.Sprintf("apps/%s", in.Env): buildEnvKustomizationOverride(in.Helm, in.Env, acc),
	}

	return acc.FinalizeWithKustomizations(overrides)
}

func emitHelmReleases(acc *DirectoryAccumulator, hr *DiscoveryResult, env string, nsMeta NamespaceMetadataMap) error {
	all := append([]*DiscoveredRelease{}, hr.Matched...)
	all = append(all, hr.Unmatched...)

	for _, rel := range all {
		tier := releaseTier(rel)
		switch tier {
		case TierInfrastructure:
			meta := nsMeta[rel.Namespace]
			if err := emitInfrastructureRelease(acc, rel, meta); err != nil {
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
// Matched releases (rel.AddonDefinition != "") use the Category that
// discovery populated from AddonDefinition.Tier (ADR-015). Unmatched
// releases fall to the namespace heuristic from ADR-016 subsection 3.2 —
// the discovery layer pre-fills Category="apps" for the unmatched bucket
// (discovery.go:147), which would short-circuit the classifier here, so
// we explicitly switch on the AddonDefinition presence instead of Category.
func releaseTier(rel *DiscoveredRelease) string {
	if rel.AddonDefinition != "" {
		switch rel.Category {
		case TierInfrastructure:
			return TierInfrastructure
		case TierApps:
			return TierApps
		}
	}
	return classifyUnmatchedRelease(rel)
}

// emitInfrastructureRelease writes infrastructure/controllers/<name>.yaml
// as a single consolidated file: optional Namespace, HelmRepository, and
// HelmRelease joined by `---`. Matches butler-crop-live-infra's
// infrastructure/controllers/ shape.
//
// The file basename and the emitted HR/HelmRepository CR names come from
// the Flux HelmRelease CR's metadata.name when discovery populated it
// (HelmReleaseCRName). When unset (no Flux HR CR matched the Helm release
// — uncommon, e.g. a Helm release applied without a Flux HR), fall back
// to the Helm release name. See discovery.enrichWithHelmReleaseCRs.
func emitInfrastructureRelease(acc *DirectoryAccumulator, rel *DiscoveredRelease, nsMeta *NamespaceMetadata) error {
	docs := [][]byte{}

	hrName := exportedHRName(rel)
	hrNamespace := exportedHRNamespace(rel)
	repoName := exportedHelmRepoName(rel)
	repoNamespace := exportedHelmRepoNamespace(rel)

	if rel.Namespace != "" && rel.Namespace != "flux-system" {
		ns := namespaceFromDiscovery(rel.Namespace, nsMeta)
		nsYAML, err := yaml.Marshal(ns)
		if err != nil {
			return fmt.Errorf("marshal namespace: %w", err)
		}
		docs = append(docs, nsYAML)
	}

	helmRepo := NewFluxHelmRepository(repoName, repoNamespace, rel.RepoURL)
	repoYAML, err := yaml.Marshal(helmRepo)
	if err != nil {
		return fmt.Errorf("marshal helmrepository: %w", err)
	}
	docs = append(docs, repoYAML)

	helmRelease := buildInfraHelmRelease(rel, hrName, hrNamespace, repoName, repoNamespace)
	relYAML, err := yaml.Marshal(helmRelease)
	if err != nil {
		return fmt.Errorf("marshal helmrelease: %w", err)
	}
	docs = append(docs, relYAML)

	content := joinYAMLDocs(docs)
	acc.Add(fmt.Sprintf("infrastructure/controllers/%s.yaml", hrName), content)
	return nil
}

// buildInfraHelmRelease emits the consolidated infra-tier HR with
// values inlined. The apps-tier split (scaffolding base + env overlay)
// does not yet apply at infra tier: the live convention puts infra
// env-overrides as inline patches on per-operator cluster pointer
// files (clusters/<cluster>/<operator>.yaml's spec.patches block on
// the Flux Kustomization), and the export does not yet emit that
// per-operator pointer structure. Until that restructure lands, infra
// HRs carry their values inline so no live state is lost. The
// coverage report's kustomizationObservations surface already notes
// any live inline patches not preserved by the v1 export.
func buildInfraHelmRelease(rel *DiscoveredRelease, hrName, hrNamespace, repoName, repoNamespace string) *FluxHelmRelease {
	hr := NewFluxHelmRelease(hrName, hrNamespace)
	hr.Spec.ReleaseName = rel.Name
	hr.Spec.Chart = FluxHelmChartTemplate{
		Spec: FluxHelmChartTemplateSpec{
			Chart:    rel.Chart,
			Version:  rel.ChartVersion,
			Interval: "1h",
			SourceRef: FluxCrossNamespaceRef{
				Kind:      "HelmRepository",
				Name:      repoName,
				Namespace: repoNamespace,
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

// exportedHRName returns the HelmRelease CR metadata.name the export
// should emit for this release. HR-CR-name from discovery wins (preserves
// existing tree identity); fallback to the Helm release name.
func exportedHRName(rel *DiscoveredRelease) string {
	if rel.HelmReleaseCRName != "" {
		return rel.HelmReleaseCRName
	}
	return rel.Name
}

// exportedHRNamespace returns the HelmRelease CR metadata.namespace the
// export should emit. HR-CR-namespace from discovery wins. Falls back to
// flux-system to match the existing default for fresh exports.
func exportedHRNamespace(rel *DiscoveredRelease) string {
	if rel.HelmReleaseCRNamespace != "" {
		return rel.HelmReleaseCRNamespace
	}
	return "flux-system"
}

// exportedHelmRepoName returns the HelmRepository CR metadata.name the
// export should emit. Sourced from the HR's spec.chart.sourceRef.name on
// the cluster (enrichWithHelmReleaseCRs); fallback to a sanitized HR
// CR name only when discovery did not find a corresponding HR CR. Required
// for charts whose publisher-named HelmRepository diverges from the
// release name — tenant clusters expose this routinely.
func exportedHelmRepoName(rel *DiscoveredRelease) string {
	if rel.HelmRepositoryCRName != "" {
		return rel.HelmRepositoryCRName
	}
	return sanitizeName(exportedHRName(rel))
}

// exportedHelmRepoNamespace returns the HelmRepository CR
// metadata.namespace. HelmRepository CR namespace from discovery wins;
// fallback to the HR's namespace which matches Flux's default sourceRef
// resolution.
func exportedHelmRepoNamespace(rel *DiscoveredRelease) string {
	if rel.HelmRepositoryCRNamespace != "" {
		return rel.HelmRepositoryCRNamespace
	}
	return exportedHRNamespace(rel)
}

// emitAppRelease writes apps/base/<name>/{repository,release,kustomization
// optional namespace}.yaml plus an empty apps/<env>/<name>-values.yaml
// stub for env-specific overrides. The base directory's kustomization.yaml
// is synthesized by the accumulator; the env <name>-values.yaml is a
// HelmRelease strategic-merge patch (empty in v1 per Decision B —
// single-cluster export, multi-cluster splitter deferred).
//
// Directory names, file basenames, and HR/HelmRepository CR names use the
// HR CR name from discovery (when populated). See emitInfrastructureRelease
// for the rationale.
func emitAppRelease(acc *DirectoryAccumulator, rel *DiscoveredRelease, env string) error {
	hrName := exportedHRName(rel)
	hrNamespace := exportedHRNamespace(rel)
	repoName := exportedHelmRepoName(rel)
	repoNamespace := exportedHelmRepoNamespace(rel)
	baseDir := fmt.Sprintf("apps/base/%s", hrName)

	helmRepo := NewFluxHelmRepository(repoName, repoNamespace, rel.RepoURL)
	repoYAML, err := yaml.Marshal(helmRepo)
	if err != nil {
		return fmt.Errorf("marshal helmrepository: %w", err)
	}
	acc.Add(fmt.Sprintf("%s/repository.yaml", baseDir), repoYAML)

	// Base release.yaml: HR SCAFFOLDING only. Chart name + sourceRef +
	// releaseName + interval + install policy. Version floats ("*");
	// no spec.values. Matches the canonical convention observed in
	// butler-observability-pipeline-reference and Flux's
	// fluxcd/flux2-kustomize-helm-example. Per-env values + actual
	// version pin live in apps/<env>/<release>-values.yaml below.
	baseHR := buildBaseHelmRelease(rel, hrName, hrNamespace, repoName, repoNamespace)
	relYAML, err := yaml.Marshal(baseHR)
	if err != nil {
		return fmt.Errorf("marshal helmrelease: %w", err)
	}
	acc.Add(fmt.Sprintf("%s/release.yaml", baseDir), relYAML)

	// Env overlay: strategic-merge patch. metadata.name only (kustomize
	// matches on name; no namespace needed in the patch). spec.chart.
	// spec.version is the discovered live version (env pins what's
	// actually running); spec.values is the full live values block.
	// Adding a second cluster's overlay later is just another
	// apps/<other-env>/<release>-values.yaml; base never changes. This
	// retires the multi-cluster values splitter ADR-016 Decision B
	// deferred: the layout itself is the splitter.
	envOverlay := buildEnvValuesOverlay(rel, hrName)
	envValuesYAML, err := yaml.Marshal(envOverlay)
	if err != nil {
		return fmt.Errorf("marshal env values: %w", err)
	}
	acc.Add(fmt.Sprintf("apps/%s/%s-values.yaml", env, hrName), envValuesYAML)

	return nil
}

// buildBaseHelmRelease emits the apps/base/<release>/release.yaml
// scaffolding: HR identity + chart-spec template + sourceRef +
// interval + install policy. Version field is "*" (floating); the
// env overlay pins the actual version this env runs. spec.values is
// deliberately absent so base stays stable across env-overlay churn.
func buildBaseHelmRelease(rel *DiscoveredRelease, hrName, hrNamespace, repoName, repoNamespace string) *FluxHelmRelease {
	hr := NewFluxHelmRelease(hrName, hrNamespace)
	hr.Spec.ReleaseName = rel.Name
	hr.Spec.Chart = FluxHelmChartTemplate{
		Spec: FluxHelmChartTemplateSpec{
			Chart:    rel.Chart,
			Version:  "*",
			Interval: "1h",
			SourceRef: FluxCrossNamespaceRef{
				Kind:      "HelmRepository",
				Name:      repoName,
				Namespace: repoNamespace,
			},
		},
	}
	if rel.Namespace != "" {
		hr.Spec.TargetNamespace = rel.Namespace
		hr.Spec.Install = &FluxInstall{CreateNamespace: true}
	}
	return hr
}

// buildEnvValuesOverlay emits the apps/<env>/<release>-values.yaml
// strategic-merge patch as a map. Strategic-merge patches must contain
// ONLY the fields being patched (unset fields would serialize as
// empty values from the FluxHelmRelease struct, which kustomize
// ignores at build time but reads as noise in the rendered file).
// The map contains: apiVersion, kind, metadata.name, spec.chart.spec.
// version (pinned live version), spec.values (live values block).
// Fields are derived from the discovered release.
func buildEnvValuesOverlay(rel *DiscoveredRelease, releaseName string) map[string]interface{} {
	overlay := map[string]interface{}{
		"apiVersion": "helm.toolkit.fluxcd.io/v2",
		"kind":       "HelmRelease",
		"metadata": map[string]interface{}{
			"name": releaseName,
		},
	}
	spec := map[string]interface{}{}
	if rel.ChartVersion != "" {
		spec["chart"] = map[string]interface{}{
			"spec": map[string]interface{}{
				"version": rel.ChartVersion,
			},
		}
	}
	if len(rel.Values) > 0 {
		spec["values"] = rel.Values
	}
	if len(spec) > 0 {
		overlay["spec"] = spec
	}
	return overlay
}

func emitNativeResources(acc *DirectoryAccumulator, n *NativeDiscoveryResult, hr *DiscoveryResult, env string) error {
	if n == nil {
		return nil
	}
	analysis := AnalyzeNativePathCollisions(n.Items, buildHelmPathOwnedSet(hr), env)
	// Emit only the items that won their path. Items that lost a
	// collision are recorded in analysis.Collisions and will surface
	// in coverage.yaml's pathCollisions list. Keeping the same single
	// "first writer wins" rule across emit and coverage prevents a
	// tree-vs-report disagreement.
	for path, item := range analysis.Owners {
		content, err := yaml.Marshal(item.Object.Object)
		if err != nil {
			return fmt.Errorf("marshal %s/%s: %w", item.Kind, item.Name, err)
		}
		acc.Add(path, content)
	}
	return nil
}

// NativePathCollisionAnalysis is the result of resolving native items
// against their target paths. Owners maps each emitted path to the
// item that won that path; Collisions maps each contested path to the
// PathCollisionCoverage record naming every conflicting identity.
//
// This is the single source of truth for path-collision detection.
// Both the layout emit path and the coverage report consume the same
// analysis so they cannot disagree on which items got written or which
// paths had a conflict. Replacing the previous duplicate detection in
// emitNativeResources and BuildCoverage closes the "drift between two
// implementations of the same rule" class of bug.
type NativePathCollisionAnalysis struct {
	Owners     map[string]*DiscoveredNative
	Collisions map[string]*PathCollisionCoverage
}

// AnalyzeNativePathCollisions walks items in slice order, skips any
// already owned by the Helm path, resolves each remaining item to its
// emit path, and records first-writer-wins ownership and any
// collisions. Items with identical (apiVersion, kind, namespace, name)
// landing on the same path are NOT a collision — they're the same
// logical object appearing in the input list twice (defensive).
func AnalyzeNativePathCollisions(items []*DiscoveredNative, helmOwned map[string]bool, env string) NativePathCollisionAnalysis {
	owners := map[string]*DiscoveredNative{}
	collisions := map[string]*PathCollisionCoverage{}
	for _, item := range items {
		if helmOwned[helmOwnedKey(item.Kind, item.Namespace, item.Name)] {
			continue
		}
		path := PathForNative(item, env)
		prior, claimed := owners[path]
		if !claimed {
			owners[path] = item
			continue
		}
		if sameNativeIdentity(prior, item) {
			// Same logical object listed twice; not a collision.
			continue
		}
		coll, exists := collisions[path]
		if !exists {
			coll = &PathCollisionCoverage{
				Path:      path,
				Conflicts: []CoverageItem{coverageItemFromNative(prior)},
			}
			collisions[path] = coll
		}
		coll.Conflicts = append(coll.Conflicts, coverageItemFromNative(item))
	}
	return NativePathCollisionAnalysis{Owners: owners, Collisions: collisions}
}

// sameNativeIdentity returns true if two DiscoveredNative pointers
// refer to the same logical object. The single identity helper used
// by both the layout collision analysis and coverage's de-duplication
// — replaces the previous duplicate sameIdentity helper in coverage.go.
func sameNativeIdentity(a, b *DiscoveredNative) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.APIVersion == b.APIVersion && a.Kind == b.Kind &&
		a.Namespace == b.Namespace && a.Name == b.Name
}

// coverageItemFromNative builds a CoverageItem from a DiscoveredNative
// for inclusion in path-collision records. Path and SourceKustomization
// fields are filled by the coverage builder when it needs them; the
// collision record only needs identity.
func coverageItemFromNative(n *DiscoveredNative) CoverageItem {
	return CoverageItem{
		APIVersion: n.APIVersion,
		Kind:       n.Kind,
		Namespace:  n.Namespace,
		Name:       n.Name,
	}
}

// buildHelmPathOwnedSet returns the set of object identities the Helm
// path will write to the tree, expressed as (apiVersion, kind,
// namespace, name) tuples. Used to deduplicate against the inventory
// walk: any item the walk discovers that matches an identity in this
// set is skipped from the native-emit path because the Helm path owns
// the canonical placement (infrastructure/controllers/<name>.yaml or
// apps/base/<name>/release.yaml).
//
// The identities are derived by CALLING THE SAME CONSTRUCTORS the Helm
// path uses to emit (NewFluxHelmRepository, NewFluxHelmRelease) and
// reading APIVersion+Kind+Metadata off the returned objects. No kind
// strings appear in this filter — if the Helm path's constructors ever
// change the APIVersion they stamp (e.g., v2 → v2beta3), this dedupe
// tracks the change automatically because it reads the same source of
// truth. The filter is tier-based ("the Helm path emits this") rather
// than name-based ("this kind happens to be called HelmRelease").
func buildHelmPathOwnedSet(hr *DiscoveryResult) map[string]bool {
	out := map[string]bool{}
	if hr == nil {
		return out
	}
	for _, rel := range append(hr.Matched, hr.Unmatched...) {
		repo := NewFluxHelmRepository(
			exportedHelmRepoName(rel),
			exportedHelmRepoNamespace(rel),
			rel.RepoURL,
		)
		release := NewFluxHelmRelease(
			exportedHRName(rel),
			exportedHRNamespace(rel),
		)
		out[helmOwnedKey(repo.Kind, repo.Metadata.Namespace, repo.Metadata.Name)] = true
		out[helmOwnedKey(release.Kind, release.Metadata.Namespace, release.Metadata.Name)] = true
	}
	return out
}

// helmOwnedKey identifies a Helm-path-owned object by (kind, namespace,
// name). APIVersion is deliberately not in the key: kind+namespace+name
// uniquely identifies an object on a cluster, and including the version
// would couple the dedupe to the constructor's hardcoded apiVersion
// (helm.toolkit.fluxcd.io/v2, source.toolkit.fluxcd.io/v1). A cluster
// serving a different version of the same kind would silently bypass
// the dedupe and produce a duplicate emission. Keying on kind alone
// keeps the dedupe correct across any served version.
func helmOwnedKey(kind, namespace, name string) string {
	return kind + "|" + namespace + "|" + name
}

// emitClusterFiles emits clusters/<cluster>/{infrastructure,apps,kustomization}.yaml
// per ADR-016 subsection 2 + ADR-017 D4 (refined by post-cross-check
// observation against butler-observability-pipeline-reference).
//
// The dependsOn chain is:
//   infra-controllers (wait: true) ← infra-configs (if present) ← apps
//
// Flux waits for controllers to become healthy before reconciling configs,
// and configs before apps. This ensures CRDs registered by controllers
// exist before native resources reference them.
//
// infra-configs is emitted CONDITIONALLY: only when infrastructure/configs/
// has content. Matches butler-observability-pipeline-reference's
// convention — that repo has no infrastructure/configs content (only
// README.md) and consequently emits only infra-controllers + apps,
// with apps depending directly on infra-controllers. The export
// produces a byte-equivalent shape for clusters whose configs/ ends
// up empty (e.g. tenants with no IdentityProvider/NetworkPool/
// ClusterIssuer/etc.).
//
// hasInfraConfigs is computed from the accumulator: any directory under
// infrastructure/configs/ that the accumulator has emitted means configs
// content exists.
func emitClusterFiles(acc *DirectoryAccumulator, clusterName, env string) {
	clusterDir := fmt.Sprintf("clusters/%s", clusterName)

	hasInfraConfigs := accumulatorHasInfraConfigs(acc)

	infraControllers := NewFluxKustomization("infra-controllers", "flux-system", "./infrastructure/controllers")
	infraControllers.Spec.Wait = true

	var infraDocs [][]byte
	infraControllersYAML, _ := yaml.Marshal(infraControllers)
	infraDocs = append(infraDocs, infraControllersYAML)

	appsDependsOn := "infra-controllers"
	if hasInfraConfigs {
		infraConfigs := NewFluxKustomization("infra-configs", "flux-system", "./infrastructure/configs")
		infraConfigs.Spec.DependsOn = []FluxDependencyReference{{Name: "infra-controllers"}}
		infraConfigsYAML, _ := yaml.Marshal(infraConfigs)
		infraDocs = append(infraDocs, infraConfigsYAML)
		appsDependsOn = "infra-configs"
	}

	infraFile := joinYAMLDocs(infraDocs)
	acc.Add(fmt.Sprintf("%s/infrastructure.yaml", clusterDir), infraFile)

	appsKs := NewFluxKustomization("apps", "flux-system", fmt.Sprintf("./apps/%s", env))
	appsKs.Spec.DependsOn = []FluxDependencyReference{{Name: appsDependsOn}}
	appsYAML, _ := yaml.Marshal(appsKs)
	acc.Add(fmt.Sprintf("%s/apps.yaml", clusterDir), appsYAML)

	// clusters/<cluster>/kustomization.yaml lists the pointer files plus
	// the bootstrap flux-system directory. flux-system is owned by `flux
	// bootstrap` and not regenerated by export, but the kustomization.yaml
	// entry pins it as a resource so Kustomize includes it in the build.
	clusterKust := NewKustomizeFile()
	clusterKust.Resources = []string{"flux-system", "infrastructure.yaml", "apps.yaml"}
	clusterKustYAML, _ := yaml.Marshal(clusterKust)
	acc.Add(fmt.Sprintf("%s/kustomization.yaml", clusterDir), clusterKustYAML)
}

// accumulatorHasInfraConfigs returns true when the export has emitted
// any file under infrastructure/configs/. Used by emitClusterFiles to
// decide whether to emit the infra-configs Flux Kustomization.
func accumulatorHasInfraConfigs(acc *DirectoryAccumulator) bool {
	for _, dir := range acc.Directories() {
		if dir == "infrastructure/configs" {
			return true
		}
		if strings.HasPrefix(dir, "infrastructure/configs/") {
			return true
		}
	}
	return false
}

// buildEnvKustomizationOverride augments the auto-synthesized
// apps/<env>/kustomization.yaml with:
//
//   - ../base/<name> entries for each apps-tier Helm release (the
//     accumulator can't infer those — they live OUTSIDE apps/<env>/
//     at apps/base/<name>/, so subdir-walking doesn't pick them up).
//
//   - A patches block listing each <release>-values.yaml as a
//     strategic-merge patch targeting its HelmRelease. The values
//     files are emitted as flat files in apps/<env>/; the accumulator
//     auto-adds them to Resources, but they need to be REMOVED from
//     Resources and MOVED to Patches because Kustomize will error if
//     the same file appears in both.
//
// Subdirectories (workloads/, etc.) and standalone flat files
// (<name>-namespace.yaml, etc.) are added to Resources by the
// accumulator's auto-synthesis; this override just augments.
func buildEnvKustomizationOverride(hr *DiscoveryResult, env string, acc *DirectoryAccumulator) func(*KustomizeFile) {
	var appReleases []string
	if hr != nil {
		for _, rel := range append(hr.Matched, hr.Unmatched...) {
			if releaseTier(rel) == TierApps {
				appReleases = append(appReleases, exportedHRName(rel))
			}
		}
	}
	sort.Strings(appReleases)

	// apps/<env>/ must always have a kustomization.yaml because
	// clusters/<cluster>/apps.yaml's Flux Kustomization points at this
	// directory. EnsureDirectory makes the accumulator track it even
	// when no files exist there yet.
	acc.EnsureDirectory(fmt.Sprintf("apps/%s", env))

	valuesBasenames := make(map[string]bool, len(appReleases))
	for _, name := range appReleases {
		valuesBasenames[fmt.Sprintf("%s-values.yaml", name)] = true
	}

	return func(kf *KustomizeFile) {
		// Strip <release>-values.yaml entries from Resources (the
		// accumulator added them as direct files); they belong to
		// Patches instead. Allocate a fresh slice rather than reusing
		// kf.Resources's backing array — the aliased-slice trick
		// (kf.Resources[:0]) works here because kf is local, but the
		// explicit allocation reads identically and doesn't lay a
		// trap for the next reader.
		filtered := make([]string, 0, len(kf.Resources)+len(appReleases))
		for _, r := range kf.Resources {
			if valuesBasenames[r] {
				continue
			}
			filtered = append(filtered, r)
		}
		// Append ../base/<name> for each apps-tier release.
		for _, name := range appReleases {
			filtered = append(filtered, fmt.Sprintf("../base/%s", name))
		}
		kf.Resources = filtered

		kf.Patches = make([]KustomizePatch, 0, len(appReleases))
		for _, name := range appReleases {
			kf.Patches = append(kf.Patches, KustomizePatch{
				Path: fmt.Sprintf("%s-values.yaml", name),
				Target: KustomizePatchTarget{
					Kind: "HelmRelease",
					Name: name,
				},
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
