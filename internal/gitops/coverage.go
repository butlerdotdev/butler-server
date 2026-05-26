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
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/yaml"
)

// coverage.go synthesizes coverage.yaml — the export tree's metadata
// companion that surfaces what the export captured, what it deliberately
// filtered (Flux self-management), and what fell through to default
// placement so the operator can see it.
//
// ADR-017 D5 + revision 3: the coverage report MUST surface inline
// patches observed on Flux Kustomization spec.patches fields. Those
// patches are NOT separate inventory items — they live in the
// Kustomization CR's spec, not in .status.inventory.entries — so the
// inventory-walk discovery alone would miss them. Without surfacing
// them, the per-env controller value overrides convention (the
// kube-prometheus-stack replicas/retention/storage pattern from
// butler-observability-pipeline-reference) would silently flatten
// into base values on every export. The coverage report makes the
// limitation operator-visible.

// CoverageReport is the in-memory shape of coverage.yaml. Tests assert
// against this structure; production marshals it to YAML via
// MarshalCoverage.
type CoverageReport struct {
	// ClusterName + Env identify the export this report describes.
	ClusterName string `json:"clusterName" yaml:"clusterName"`
	Env         string `json:"env" yaml:"env"`

	// Captured: every (kind, namespace, name) the export emitted to the
	// tree, with its path. Sorted lexically for stable diffs.
	Captured []CoverageItem `json:"captured" yaml:"captured"`

	// FluxSelfManagement: inventory items the discovery walk identified
	// as Flux operational and deliberately excluded from the export
	// tree. Recorded for transparency — these items remain managed by
	// `flux bootstrap`, not by the exported repo.
	FluxSelfManagement []CoverageItem `json:"fluxSelfManagement" yaml:"fluxSelfManagement"`

	// KustomizationObservations: per-Kustomization snapshot of the
	// inventory-read moment. Captures Ready condition,
	// lastAppliedRevision, and inline patches observed on
	// spec.patches. The inline-patches list is the env-overrides
	// visibility surface required by ADR-017 revision 3: each entry
	// here is a per-env controller value override that v1 export does
	// not preserve as a separate overlay. Operators see them
	// explicitly rather than having them silently flattened into
	// base values.
	KustomizationObservations []KustomizationCoverage `json:"kustomizationObservations" yaml:"kustomizationObservations"`

	// DiscoveryFailures: inventory entries the walk discovered in some
	// Flux Kustomization's inventory but couldn't fetch via the dynamic
	// client (RESTMapper miss, RBAC denial, stale inventory entry,
	// etc.). Surfaced here so the loud-on-silent-drop guarantee is
	// visible in coverage.yaml — without this, the class of bug where
	// an inventory entry references a CRD version the cluster no longer
	// serves would silently drop user state and pass the prune-safety
	// property test because the missing item never reached the layout
	// layer.
	DiscoveryFailures []DiscoveryFailureCoverage `json:"discoveryFailures,omitempty" yaml:"discoveryFailures,omitempty"`

	// PathCollisions: defense-in-depth backstop. Two distinct
	// emitted objects that resolve to the same tree path are recorded
	// here with both identities. The placement rule (group-short +
	// kind-lower + optional-namespace + name) makes collisions
	// structurally near-impossible, but near-impossible isn't
	// impossible: any unanticipated collision (path-shape change, new
	// kind with surprising naming, operator quirks) surfaces here
	// instead of silently overwriting one object with another. Same
	// loud-on-unknown pattern as DiscoveryFailures. Empty = every
	// emitted path unique (the good zero).
	PathCollisions []PathCollisionCoverage `json:"pathCollisions,omitempty" yaml:"pathCollisions,omitempty"`
}

// CoverageItem is one resource entry in the coverage report.
type CoverageItem struct {
	APIVersion string `json:"apiVersion" yaml:"apiVersion"`
	Kind       string `json:"kind" yaml:"kind"`
	Namespace  string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Name       string `json:"name" yaml:"name"`
	Path       string `json:"path,omitempty" yaml:"path,omitempty"`
	// SourceKustomization identifies which Flux Kustomization's
	// inventory this item came from. Helps the operator trace the
	// item back to its source-of-truth on the cluster.
	SourceKustomization string `json:"sourceKustomization,omitempty" yaml:"sourceKustomization,omitempty"`
}

// KustomizationCoverage records what the discovery walk observed about
// one Flux Kustomization CR. The InlinePatches field is the load-bearing
// surface for the env-overrides visibility requirement.
type KustomizationCoverage struct {
	Name                string                `json:"name" yaml:"name"`
	Namespace           string                `json:"namespace" yaml:"namespace"`
	Ready               bool                  `json:"ready" yaml:"ready"`
	LastAppliedRevision string                `json:"lastAppliedRevision,omitempty" yaml:"lastAppliedRevision,omitempty"`
	InventoryItemCount  int                   `json:"inventoryItemCount" yaml:"inventoryItemCount"`
	Skipped             bool                  `json:"skipped,omitempty" yaml:"skipped,omitempty"`
	SkipReason          string                `json:"skipReason,omitempty" yaml:"skipReason,omitempty"`
	// InlinePatches: patches on the Kustomization's spec.patches that
	// the export does NOT preserve as separate overlays (per-env
	// controller value overrides per ADR-017 Negative consequences).
	// Surfaced here for operator visibility — without this, the
	// limitation would be silent.
	InlinePatches []InlinePatchCoverage `json:"inlinePatches,omitempty" yaml:"inlinePatches,omitempty"`
}

// PathCollisionCoverage records two or more distinct emitted objects
// resolving to the same tree path. Surfaced when the placement rule
// produces a collision so the operator sees both identities rather
// than the export silently last-write-wins overwriting.
type PathCollisionCoverage struct {
	Path      string         `json:"path" yaml:"path"`
	Conflicts []CoverageItem `json:"conflicts" yaml:"conflicts"`
}

// DiscoveryFailureCoverage is one entry in the discoveryFailures surface
// — an inventory entry the walk found but couldn't fetch. The Hint field
// is a short triage classification (RESTMapper miss, RBAC denial, stale
// inventory, etc.) so the operator has a starting point without reading
// the raw error. Kind/group are reported verbatim from the inventory ID
// so the operator can correlate against the source Kustomization on the
// cluster.
type DiscoveryFailureCoverage struct {
	InventoryID         string `json:"inventoryID" yaml:"inventoryID"`
	Group               string `json:"group,omitempty" yaml:"group,omitempty"`
	Kind                string `json:"kind" yaml:"kind"`
	Namespace           string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	Name                string `json:"name" yaml:"name"`
	SourceKustomization string `json:"sourceKustomization,omitempty" yaml:"sourceKustomization,omitempty"`
	Error               string `json:"error" yaml:"error"`
	Hint                string `json:"hint,omitempty" yaml:"hint,omitempty"`
}

// InlinePatchCoverage is one entry in the inline-patches surface — one
// inline patch observed on a Kustomization, with the target it patches
// and a size proxy. The patch body is not stored to keep the coverage
// report compact; PatchSize gives the operator a sense of how much
// override content is being dropped from base.
type InlinePatchCoverage struct {
	TargetKind      string `json:"targetKind" yaml:"targetKind"`
	TargetName      string `json:"targetName" yaml:"targetName"`
	TargetNamespace string `json:"targetNamespace,omitempty" yaml:"targetNamespace,omitempty"`
	TargetGroup     string `json:"targetGroup,omitempty" yaml:"targetGroup,omitempty"`
	PatchSize       int    `json:"patchSize" yaml:"patchSize"`
	// Note explains the visibility-not-preservation behavior so the
	// operator reading coverage.yaml understands why this entry exists.
	Note string `json:"note" yaml:"note"`
}

// CoverageInput is the data needed to synthesize the coverage report.
// All fields are populated by GenerateLayoutV2's caller after running
// discovery + inventory walk + layout emission.
type CoverageInput struct {
	ClusterName        string
	Env                string
	EmittedFiles       map[string][]byte                 // every file path the export wrote
	Helm               *DiscoveryResult                  // Helm releases discovered
	Inventory          *InventoryWalkResult              // inventory walk result with per-Kustomization observations
	NativeResults      []*DiscoveredNative                // native items emitted (used to identify default-bucket placements)
	NamespaceMeta      NamespaceMetadataMap              // for path resolution when needed
	SourceKustomizations map[string]string               // map of (group/kind/namespace/name) -> source Kustomization name, optional
}

// BuildCoverage synthesizes the coverage report from the export's
// discovery + emission state. The returned report can be marshaled to
// coverage.yaml via MarshalCoverage.
func BuildCoverage(in CoverageInput) *CoverageReport {
	report := &CoverageReport{
		ClusterName: in.ClusterName,
		Env:         in.Env,
	}

	// Captured + PathCollisions: derived from the single
	// AnalyzeNativePathCollisions pass that the layout emit ALSO
	// consumes. Same analysis, two consumers: emit writes the owners
	// to disk, coverage reports them. Items that lost a collision are
	// in analysis.Collisions and do NOT appear under Captured (only
	// what's actually on disk is captured). Closes the previous
	// drift class where emit's pathOwners and coverage's pathOwners
	// were separate implementations of the same rule.
	analysis := AnalyzeNativePathCollisions(in.NativeResults, buildHelmPathOwnedSet(in.Helm), in.Env)
	for path, item := range analysis.Owners {
		src := ""
		if in.SourceKustomizations != nil {
			key := fmt.Sprintf("%s/%s/%s/%s", apiGroup(item.APIVersion), item.Kind, item.Namespace, item.Name)
			src = in.SourceKustomizations[key]
		}
		report.Captured = append(report.Captured, CoverageItem{
			APIVersion:          item.APIVersion,
			Kind:                item.Kind,
			Namespace:           item.Namespace,
			Name:                item.Name,
			Path:                path,
			SourceKustomization: src,
		})
	}
	for _, c := range analysis.Collisions {
		report.PathCollisions = append(report.PathCollisions, *c)
	}
	if in.Helm != nil {
		for _, rel := range append(in.Helm.Matched, in.Helm.Unmatched...) {
			tier := releaseTier(rel)
			hrName := exportedHRName(rel)
			var path string
			if tier == TierInfrastructure {
				path = fmt.Sprintf("infrastructure/controllers/%s.yaml", hrName)
			} else {
				path = fmt.Sprintf("apps/base/%s/release.yaml", hrName)
			}
			report.Captured = append(report.Captured, CoverageItem{
				APIVersion: "helm.toolkit.fluxcd.io/v2",
				Kind:       "HelmRelease",
				Namespace:  exportedHRNamespace(rel),
				Name:       hrName,
				Path:       path,
			})
		}
	}

	// FluxSelfManagement: derived by re-walking the inventory and
	// keeping only items that isFluxOperational identifies. Surfaces
	// what the export deliberately did NOT emit.
	if in.Inventory != nil {
		for _, ks := range in.Inventory.Kustomizations {
			obs := KustomizationCoverage{
				Name:                ks.Name,
				Namespace:           ks.Namespace,
				Ready:               ks.Ready,
				LastAppliedRevision: ks.LastAppliedRevision,
				InventoryItemCount:  ks.InventoryItemCount,
				Skipped:             ks.Skipped,
				SkipReason:          ks.SkipReason,
			}
			for _, p := range ks.SpecPatches {
				obs.InlinePatches = append(obs.InlinePatches, InlinePatchCoverage{
					TargetKind:      p.TargetKind,
					TargetName:      p.TargetName,
					TargetNamespace: p.TargetNamespace,
					TargetGroup:     p.TargetGroup,
					PatchSize:       p.PatchSize,
					Note:            "env-override present on the live Kustomization, not captured in the base export (ADR-017 Negative consequences). Operator re-adds per-env controller patches post-export.",
				})
			}
			report.KustomizationObservations = append(report.KustomizationObservations, obs)
		}
		for _, f := range in.Inventory.FetchFailures {
			report.DiscoveryFailures = append(report.DiscoveryFailures, DiscoveryFailureCoverage{
				InventoryID:         f.InventoryID,
				Group:               f.Group,
				Kind:                f.Kind,
				Namespace:           f.Namespace,
				Name:                f.Name,
				SourceKustomization: f.SourceKustomization,
				Error:               f.Error,
				Hint:                f.Hint,
			})
		}
	}

	// Stable ordering for diffs.
	sortCoverageItems(report.Captured)
	sortCoverageItems(report.FluxSelfManagement)
	sort.SliceStable(report.KustomizationObservations, func(i, j int) bool {
		return report.KustomizationObservations[i].Name < report.KustomizationObservations[j].Name
	})
	sort.SliceStable(report.DiscoveryFailures, func(i, j int) bool {
		return report.DiscoveryFailures[i].InventoryID < report.DiscoveryFailures[j].InventoryID
	})
	sort.SliceStable(report.PathCollisions, func(i, j int) bool {
		return report.PathCollisions[i].Path < report.PathCollisions[j].Path
	})

	return report
}

func sortCoverageItems(items []CoverageItem) {
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

// MarshalCoverage serializes the coverage report to YAML for emission
// at the export tree root as coverage.yaml. The tree itself is clean
// Flux YAML; coverage.yaml is metadata-about-the-export, NOT part of
// the Kustomize build (Kustomization.yaml files don't reference it).
func MarshalCoverage(report *CoverageReport) ([]byte, error) {
	var buf strings.Builder
	buf.WriteString("# coverage.yaml — generated by butler-server gitops export.\n")
	buf.WriteString("# Surfaces what the export captured, what it filtered as Flux\n")
	buf.WriteString("# operational, and what fell through to default placement.\n")
	buf.WriteString("# inlinePatches under kustomizationObservations records per-env\n")
	buf.WriteString("# controller value overrides the v1 export does not preserve as\n")
	buf.WriteString("# separate overlays (ADR-017 Negative consequences).\n")
	buf.WriteString("# discoveryFailures records inventory entries the walk found but\n")
	buf.WriteString("# could not fetch — surfacing the loud-on-silent-drop guarantee\n")
	buf.WriteString("# so missing items are operator-visible instead of disappearing.\n")
	buf.WriteString("# pathCollisions records two or more distinct objects resolving to\n")
	buf.WriteString("# the same emitted path — defense in depth against silent overwrite.\n")
	buf.WriteString("# Empty pathCollisions means every emitted path is unique.\n")
	body, err := yaml.Marshal(report)
	if err != nil {
		return nil, fmt.Errorf("marshal coverage report: %w", err)
	}
	buf.Write(body)
	return []byte(buf.String()), nil
}
