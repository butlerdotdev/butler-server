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
	"sort"
)

// CRITICAL: do NOT add Source classification to gitops.CoverageItem in
// coverage.go. Doing so changes coverage.yaml's serialized shape and
// breaks the engine's golden fixtures. Classification lives here, at
// the API boundary, and wraps CoverageItem without modifying it.

// CapturedItem is a CoverageItem plus a Source classifier — the API-
// layer enrichment the preview-cluster response carries.
type CapturedItem struct {
	APIVersion          string `json:"apiVersion"`
	Kind                string `json:"kind"`
	Namespace           string `json:"namespace,omitempty"`
	Name                string `json:"name"`
	Path                string `json:"path,omitempty"`
	SourceKustomization string `json:"sourceKustomization,omitempty"`

	Source ItemSource `json:"source"`

	// AddonDefinition is populated only when Source == ItemSourceHelmAddon.
	AddonDefinition string `json:"addonDefinition,omitempty"`
}

// ItemSource is the classification of how an item was discovered.
type ItemSource string

const (
	// ItemSourceHelmAddon: Helm release matched a Butler AddonDefinition.
	ItemSourceHelmAddon ItemSource = "helm-addon"

	// ItemSourceHelmUnmatched: Helm release with no AddonDefinition match.
	ItemSourceHelmUnmatched ItemSource = "helm-unmatched"

	// ItemSourceNativeInventory: an item the Flux inventory walk fetched.
	// HelmRelease/HelmRepository are excluded (Helm path owns them).
	ItemSourceNativeInventory ItemSource = "native-inventory"
)

// PreviewClusterResponse is the HTTP response shape for preview-cluster.
type PreviewClusterResponse struct {
	// ClusterName is the directory emitted under clusters/. Resolved
	// from override > Flux root path > caller fallback. Surfaced so
	// the UI can show what was used.
	ClusterName string                    `json:"clusterName"`
	Files       map[string]string         `json:"files"`
	Coverage    PreviewClusterCoverage    `json:"coverage"`
	Summary     PreviewClusterSummary     `json:"summary"`
}

// PreviewClusterCoverage carries the coverage report at the API layer
// with the captured list enriched to CapturedItem.
type PreviewClusterCoverage struct {
	Captured                  []CapturedItem            `json:"captured"`
	FluxSelfManagement        []CapturedItem            `json:"fluxSelfManagement"`
	KustomizationObservations []KustomizationCoverage   `json:"kustomizationObservations"`
	DiscoveryFailures         []DiscoveryFailureCoverage `json:"discoveryFailures,omitempty"`
	PathCollisions            []PathCollisionCoverage    `json:"pathCollisions,omitempty"`
}

// PreviewClusterSummary is the at-a-glance counts for the modal.
type PreviewClusterSummary struct {
	FileCount         int                       `json:"fileCount"`
	CapturedByKind    map[string]int            `json:"capturedByKind"`
	CapturedBySource  PreviewClusterSourceCounts `json:"capturedBySource"`
	Collisions        int                       `json:"collisions"`
	Failures          int                       `json:"failures"`
}

type PreviewClusterSourceCounts struct {
	HelmAddon       int `json:"helmAddon"`
	HelmUnmatched   int `json:"helmUnmatched"`
	NativeInventory int `json:"nativeInventory"`
}

// BuildClusterPreview composes the preview response. Classification:
//   - helm-addon: HelmRelease/HelmRepository with non-empty AddonDefinition.
//   - helm-unmatched: HelmRelease/HelmRepository, empty AddonDefinition.
//   - native-inventory: everything else captured.
//
// The helm-vs-native identity match uses helmOwnedKey + the exportedH*
// helpers so it tracks what the layout emit produces.
func BuildClusterPreview(
	files map[string]string,
	coverage *CoverageReport,
	helm *DiscoveryResult,
) *PreviewClusterResponse {
	resp := &PreviewClusterResponse{
		Files: files,
		Coverage: PreviewClusterCoverage{
			KustomizationObservations: coverage.KustomizationObservations,
			DiscoveryFailures:         coverage.DiscoveryFailures,
			PathCollisions:            coverage.PathCollisions,
		},
	}

	// Build the addon-match index from discovered Helm releases.
	// Key: (kind|namespace|name) using the same exportedH* helpers
	// the layout uses, so the index matches what the Helm path will
	// emit as canonical HRs/HRepositories.
	addonByID := map[string]string{} // identity -> AddonDefinition name
	helmIdentities := map[string]bool{}
	if helm != nil {
		for _, rel := range append(helm.Matched, helm.Unmatched...) {
			hrID := helmOwnedKey("HelmRelease", exportedHRNamespace(rel), exportedHRName(rel))
			repoID := helmOwnedKey("HelmRepository", exportedHelmRepoNamespace(rel), exportedHelmRepoName(rel))
			helmIdentities[hrID] = true
			helmIdentities[repoID] = true
			if rel.AddonDefinition != "" {
				addonByID[hrID] = rel.AddonDefinition
				addonByID[repoID] = rel.AddonDefinition
			}
		}
	}

	classify := func(item CoverageItem) (ItemSource, string) {
		id := helmOwnedKey(item.Kind, item.Namespace, item.Name)
		if helmIdentities[id] {
			if addon := addonByID[id]; addon != "" {
				return ItemSourceHelmAddon, addon
			}
			return ItemSourceHelmUnmatched, ""
		}
		return ItemSourceNativeInventory, ""
	}

	resp.Coverage.Captured = make([]CapturedItem, 0, len(coverage.Captured))
	for _, c := range coverage.Captured {
		src, addon := classify(c)
		resp.Coverage.Captured = append(resp.Coverage.Captured, CapturedItem{
			APIVersion:          c.APIVersion,
			Kind:                c.Kind,
			Namespace:           c.Namespace,
			Name:                c.Name,
			Path:                c.Path,
			SourceKustomization: c.SourceKustomization,
			Source:              src,
			AddonDefinition:     addon,
		})
	}
	resp.Coverage.FluxSelfManagement = make([]CapturedItem, 0, len(coverage.FluxSelfManagement))
	for _, c := range coverage.FluxSelfManagement {
		resp.Coverage.FluxSelfManagement = append(resp.Coverage.FluxSelfManagement, CapturedItem{
			APIVersion:          c.APIVersion,
			Kind:                c.Kind,
			Namespace:           c.Namespace,
			Name:                c.Name,
			Path:                c.Path,
			SourceKustomization: c.SourceKustomization,
			Source:              ItemSourceNativeInventory,
		})
	}

	resp.Summary = buildPreviewSummary(resp)
	return resp
}

func buildPreviewSummary(resp *PreviewClusterResponse) PreviewClusterSummary {
	sum := PreviewClusterSummary{
		FileCount:      len(resp.Files),
		CapturedByKind: map[string]int{},
		Collisions:     len(resp.Coverage.PathCollisions),
		Failures:       len(resp.Coverage.DiscoveryFailures),
	}
	for _, c := range resp.Coverage.Captured {
		sum.CapturedByKind[c.Kind]++
		switch c.Source {
		case ItemSourceHelmAddon:
			sum.CapturedBySource.HelmAddon++
		case ItemSourceHelmUnmatched:
			sum.CapturedBySource.HelmUnmatched++
		case ItemSourceNativeInventory:
			sum.CapturedBySource.NativeInventory++
		}
	}
	return sum
}

// FilterCapturedBySelection returns the subset of items whose
// (kind, namespace, name) identity is in selection. Empty selection
// returns items unchanged.
func FilterCapturedBySelection(items []CapturedItem, selection []CapturedItemIdentity) []CapturedItem {
	if len(selection) == 0 {
		return items
	}
	included := make(map[string]bool, len(selection))
	for _, s := range selection {
		included[s.identityKey()] = true
	}
	out := make([]CapturedItem, 0, len(items))
	for _, item := range items {
		key := identityKey(item.Kind, item.Namespace, item.Name)
		if included[key] {
			out = append(out, item)
		}
	}
	return out
}

// CapturedItemIdentity is the (kind, namespace, name) tuple
// export-cluster accepts as a selection element.
type CapturedItemIdentity struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

func (i CapturedItemIdentity) identityKey() string {
	return identityKey(i.Kind, i.Namespace, i.Name)
}

func identityKey(kind, namespace, name string) string {
	return kind + "|" + namespace + "|" + name
}

// FilterHelmDiscoveryBySelection returns a filtered DiscoveryResult
// keeping only releases whose emitted HR identity is in selection.
// The companion HelmRepository rides along on the same DiscoveredRelease
// record. Empty selection returns the input unchanged.
func FilterHelmDiscoveryBySelection(hr *DiscoveryResult, selection []CapturedItemIdentity) *DiscoveryResult {
	if hr == nil || len(selection) == 0 {
		return hr
	}
	included := make(map[string]bool, len(selection))
	for _, s := range selection {
		included[s.identityKey()] = true
	}
	filter := func(rels []*DiscoveredRelease) []*DiscoveredRelease {
		out := make([]*DiscoveredRelease, 0, len(rels))
		for _, rel := range rels {
			key := identityKey("HelmRelease", exportedHRNamespace(rel), exportedHRName(rel))
			if included[key] {
				out = append(out, rel)
			}
		}
		return out
	}
	return &DiscoveryResult{
		Matched:      filter(hr.Matched),
		Unmatched:    filter(hr.Unmatched),
		GitOpsEngine: hr.GitOpsEngine,
	}
}

// FilterNativeBySelection returns a filtered NativeDiscoveryResult
// keeping only items whose identity is in selection. InventoryWalk
// metadata is preserved so the per-Kustomization observations and
// discoveryFailures surfaces aren't dropped by the filter.
func FilterNativeBySelection(nat *NativeDiscoveryResult, selection []CapturedItemIdentity) *NativeDiscoveryResult {
	if nat == nil || len(selection) == 0 {
		return nat
	}
	included := make(map[string]bool, len(selection))
	for _, s := range selection {
		included[s.identityKey()] = true
	}
	out := make([]*DiscoveredNative, 0, len(nat.Items))
	for _, item := range nat.Items {
		key := identityKey(item.Kind, item.Namespace, item.Name)
		if included[key] {
			out = append(out, item)
		}
	}
	return &NativeDiscoveryResult{
		Items:         out,
		InventoryWalk: nat.InventoryWalk,
	}
}

// SortCapturedItems sorts in (kind, namespace, name) order so the
// JSON response is deterministic.
func SortCapturedItems(items []CapturedItem) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		return a.Name < b.Name
	})
}
