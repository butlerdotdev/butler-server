/*
Copyright 2026 The Butler Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package gitops

import (
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// TestCoverage_InlinePatchVisibility is the load-bearing env-overrides
// visibility proof per ADR-017 revision 3.
//
// The contract: when a live Flux Kustomization carries per-env controller
// value overrides as inline `spec.patches` (the convention
// butler-observability-pipeline-reference uses for kube-prometheus-stack's
// per-env replicas/retention/storage tweaks), the coverage report MUST
// surface those patches so the operator can SEE them — they're not
// preserved as separate overlays in the v1 export tree (D3/Negative
// consequences), and without coverage-report visibility the limitation
// is silent.
//
// Inline patches are NOT separate inventory items — they live in the
// Kustomization CR's spec.patches field, NOT in .status.inventory.entries.
// The inventory-walk discovery alone would miss them. Coverage.go's
// inlinePatches surface is what makes this visible.
//
// This test uses the kube-prometheus-stack inline-patch pattern verbatim
// from butler-observability-pipeline-reference's
// clusters/pipeline-prd/infrastructure.yaml: a Flux Kustomization with
// a spec.patches entry targeting kind=HelmRelease name=kube-prometheus-stack
// with per-env values for replicas + retention + storage.
//
// FAIL condition: if the coverage report doesn't contain an entry under
// kustomizationObservations[*].inlinePatches identifying the patch's
// target, the limitation is silently flattened and operators have no
// signal at MR review that controller per-env tweaks were dropped. That
// IS the silent-incompleteness failure mode the user explicitly required
// this test to prove against.
func TestCoverage_InlinePatchVisibility(t *testing.T) {
	// Fixture: a single Kustomization observation carrying a real
	// kube-prometheus-stack-shaped inline patch (replicas/retention/
	// storage tweaks, from the reference).
	patchBody := `apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: kube-prometheus-stack
  namespace: observability
spec:
  chart:
    spec:
      version: "~67.0.0"
  values:
    prometheus:
      prometheusSpec:
        replicas: 1
        retention: 2h
        externalLabels:
          cluster: pipeline-prd
        storageSpec:
          volumeClaimTemplate:
            spec:
              storageClassName: longhorn
              accessModes: ["ReadWriteOnce"]
              resources:
                requests:
                  storage: 50Gi
        remoteWrite:
          - url: http://vector.vector.svc:9000
            name: vector-pipeline-prd`
	inv := &InventoryWalkResult{
		Kustomizations: []FluxKustomizationObservation{
			{
				Name:                "infra-controllers",
				Namespace:           "flux-system",
				Ready:               true,
				LastAppliedRevision: "main@sha1:abc123",
				InventoryItemCount:  5,
				SpecPatches: []ObservedInlinePatch{
					{
						TargetKind:      "HelmRelease",
						TargetName:      "kube-prometheus-stack",
						TargetNamespace: "observability",
						TargetGroup:     "helm.toolkit.fluxcd.io",
						PatchSize:       len(patchBody),
					},
				},
			},
		},
	}

	report := BuildCoverage(CoverageInput{
		ClusterName: "pipeline-prd",
		Env:         "prd",
		Inventory:   inv,
	})

	// Assertion 1: the kustomizationObservations list contains the
	// infra-controllers Kustomization.
	var found *KustomizationCoverage
	for i := range report.KustomizationObservations {
		if report.KustomizationObservations[i].Name == "infra-controllers" {
			found = &report.KustomizationObservations[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("coverage report missing infra-controllers Kustomization observation; without it env-overrides are SILENTLY dropped")
	}

	// Assertion 2: the observation surfaces the inline patch.
	if len(found.InlinePatches) == 0 {
		t.Fatalf("infra-controllers observation has empty inlinePatches; the kube-prometheus-stack patch is SILENTLY DROPPED — env-overrides limitation is invisible to the operator")
	}

	// Assertion 3: the inline patch identifies the kube-prometheus-stack
	// HelmRelease as its target — operator can trace the patch to the
	// affected resource.
	patch := found.InlinePatches[0]
	if patch.TargetKind != "HelmRelease" {
		t.Errorf("inline patch targetKind = %q, want HelmRelease", patch.TargetKind)
	}
	if patch.TargetName != "kube-prometheus-stack" {
		t.Errorf("inline patch targetName = %q, want kube-prometheus-stack", patch.TargetName)
	}
	if patch.TargetNamespace != "observability" {
		t.Errorf("inline patch targetNamespace = %q, want observability", patch.TargetNamespace)
	}
	if patch.PatchSize <= 0 {
		t.Errorf("inline patch patchSize = %d, want >0 (signals how much override content is being dropped)", patch.PatchSize)
	}

	// Assertion 4: the patch entry carries the explanatory Note so the
	// operator reading coverage.yaml understands the visibility-not-
	// preservation semantics.
	if !strings.Contains(strings.ToLower(patch.Note), "env-override") ||
		!strings.Contains(strings.ToLower(patch.Note), "not captured in the base export") {
		t.Errorf("inline patch Note must explain the limitation; got %q", patch.Note)
	}

	// Assertion 5: the marshaled YAML actually contains the patch
	// target — proves the visibility survives serialization to the
	// emitted coverage.yaml file.
	yamlBytes, err := MarshalCoverage(report)
	if err != nil {
		t.Fatalf("MarshalCoverage: %v", err)
	}
	yamlStr := string(yamlBytes)
	for _, must := range []string{
		"kube-prometheus-stack",
		"HelmRelease",
		"observability",
		"infra-controllers",
		"inlinePatches",
	} {
		if !strings.Contains(yamlStr, must) {
			t.Errorf("marshaled coverage.yaml missing required visibility string %q; the limitation would be SILENT to operators reading the file\n%s", must, yamlStr)
		}
	}

	// Assertion 6 (negative control): a Kustomization with NO inline
	// patches has empty InlinePatches in the report — confirms we're
	// not just emitting noise.
	invNoPatches := &InventoryWalkResult{
		Kustomizations: []FluxKustomizationObservation{
			{Name: "apps", Namespace: "flux-system", Ready: true, InventoryItemCount: 3},
		},
	}
	reportNoPatches := BuildCoverage(CoverageInput{ClusterName: "c", Env: "prd", Inventory: invNoPatches})
	if len(reportNoPatches.KustomizationObservations) != 1 {
		t.Fatalf("expected 1 Kustomization observation, got %d", len(reportNoPatches.KustomizationObservations))
	}
	if len(reportNoPatches.KustomizationObservations[0].InlinePatches) != 0 {
		t.Errorf("Kustomization with no spec.patches should have empty InlinePatches; got %d entries (false-positive noise)",
			len(reportNoPatches.KustomizationObservations[0].InlinePatches))
	}
}

// TestCoverage_RoundTripsYAML confirms the report serializes to valid
// YAML and round-trips back to an equivalent structure. Guards against
// silent serialization bugs that would hide fields from the operator.
func TestCoverage_RoundTripsYAML(t *testing.T) {
	report := &CoverageReport{
		ClusterName: "test",
		Env:         "prd",
		Captured: []CoverageItem{
			{APIVersion: "v1", Kind: "ConfigMap", Namespace: "butler-system", Name: "butler-gitops-config", Path: "infrastructure/configs/butler-gitops-config.yaml"},
		},
		KustomizationObservations: []KustomizationCoverage{
			{
				Name:                "infra-controllers",
				Namespace:           "flux-system",
				Ready:               true,
				LastAppliedRevision: "main@sha1:deadbeef",
				InventoryItemCount:  3,
				InlinePatches: []InlinePatchCoverage{
					{TargetKind: "HelmRelease", TargetName: "kube-prometheus-stack", TargetNamespace: "observability", PatchSize: 512, Note: "env-override present, not captured"},
				},
			},
		},
	}
	yamlBytes, err := MarshalCoverage(report)
	if err != nil {
		t.Fatalf("MarshalCoverage: %v", err)
	}

	var roundTrip CoverageReport
	if err := yaml.Unmarshal(yamlBytes, &roundTrip); err != nil {
		t.Fatalf("yaml round-trip unmarshal: %v\n%s", err, yamlBytes)
	}
	if roundTrip.ClusterName != "test" {
		t.Errorf("round-trip ClusterName = %q, want test", roundTrip.ClusterName)
	}
	if len(roundTrip.KustomizationObservations) != 1 {
		t.Fatalf("round-trip KustomizationObservations count = %d, want 1", len(roundTrip.KustomizationObservations))
	}
	if len(roundTrip.KustomizationObservations[0].InlinePatches) != 1 {
		t.Fatalf("round-trip InlinePatches count = %d, want 1; serialization dropped the visibility surface",
			len(roundTrip.KustomizationObservations[0].InlinePatches))
	}
}

// TestCoverage_UnifiedPathRule verifies a cluster-scoped CRD lands in
// Captured under the unified placement rule (D4 correction): every
// native item gets a path via PathForNative; the previous
// InScopeUncaptured distinction is gone because there is no longer an
// explicit-table vs default-bucket split. The CRD must land in
// infrastructure/configs/ via the cluster-scoped → infra tier rule,
// with group-short + kind-in-filename naming.
func TestCoverage_UnifiedPathRule(t *testing.T) {
	stewardCRD := &DiscoveredNative{
		APIVersion: "apiextensions.k8s.io/v1",
		Kind:       "CustomResourceDefinition",
		Name:       "stewardcontrolplanes.controlplane.cluster.x-k8s.io",
		// Cluster-scoped — routes to infra tier.
		IsNamespaced: false,
	}
	report := BuildCoverage(CoverageInput{
		ClusterName:   "mgmt",
		Env:           "prd",
		NativeResults: []*DiscoveredNative{stewardCRD},
	})
	if len(report.Captured) != 1 {
		t.Fatalf("Captured count = %d, want 1 (the CRD)", len(report.Captured))
	}
	entry := report.Captured[0]
	if entry.Kind != "CustomResourceDefinition" {
		t.Errorf("Captured entry Kind = %q, want CustomResourceDefinition", entry.Kind)
	}
	if !strings.HasPrefix(entry.Path, "infrastructure/configs/") {
		t.Errorf("Cluster-scoped CRD should land in infrastructure/configs/, got %q", entry.Path)
	}
	// Filename should be <kind-lower>-<name>.yaml (no namespace segment
	// because cluster-scoped). Group-short for apiextensions.k8s.io →
	// "k8s" (TLD-strip then last segment).
	if !strings.HasSuffix(entry.Path, "/customresourcedefinition-stewardcontrolplanes.controlplane.cluster.x-k8s.io.yaml") {
		t.Errorf("expected filename <kind-lower>-<name>.yaml shape, got %q", entry.Path)
	}
	if len(report.PathCollisions) != 0 {
		t.Errorf("PathCollisions should be empty for single item, got %d", len(report.PathCollisions))
	}
}
