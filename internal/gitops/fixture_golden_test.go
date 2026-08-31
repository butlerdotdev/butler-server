/*
Copyright 2026 The Butler Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package gitops

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// TestFixtureGoldenLayout exercises the layout + coverage pipeline against
// recorded discovery output captured from real clusters. The fixture pair
// for each scenario (input/ + expected/) is recorded by cmd/_dev-tenant-dump
// with DEV_DUMP_FIXTURE_OUT set, so input and expected ALWAYS come from
// the same coherent discovery+layout pass — a regression in the recording
// path can't produce green tests over an inconsistent fixture.
//
// Scope per ADR-016/017's option (D) choice: this exercises layout +
// coverage end-to-end against realistic cluster shapes. Discovery itself
// (DiscoverFluxInventory, DiscoverNativeResources, DiscoverHelmReleases,
// DiscoverNamespaceMetadata) is NOT exercised here; it is covered by its
// own unit tests and by continuous live-cluster validation through the
// dev tools. The accepted gap: a regression IN discovery would not show
// up as a fixture diff. The accepted coverage: any regression in the
// layout/coverage logic that this session has iterated on heavily (path
// classes, base/env split, kustomization chaining, label/annotation
// filtering, conditional infra-configs) WILL surface as a fixture diff.
//
// Scenarios:
//   - mature-tenant-prd: mature tenant, full inventory, exercises
//     every code path that emits content (Strimzi + KEDA + ClusterIssuer +
//     StorageClass + SealedSecret + standalone Namespaces + all 3 native
//     tiers + base/env split + Flux ownership filter).
//   - fresh-tenant-dev: near-empty fresh-bootstrap shape, exercises the
//     conditional infra-configs gate (no infra-configs Flux Kustomization
//     when there's no infra-configs content) and the minimal-tenant
//     overlay path.
func TestFixtureGoldenLayout(t *testing.T) {
	scenarios := []struct {
		name        string
		cluster     string
		env         string
		fixtureRoot string
	}{
		{
			name:        "mature_tenant_prd",
			cluster:     "mature-tenant-prd",
			env:         "prd",
			fixtureRoot: "testdata/mature-tenant-prd",
		},
		{
			name:        "fresh_tenant_dev",
			cluster:     "fresh-tenant-dev",
			env:         "dev",
			fixtureRoot: "testdata/fresh-tenant-dev",
		},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			input := loadFixtureInput(t, sc.fixtureRoot)
			expected := loadFixtureExpected(t, sc.fixtureRoot)

			tree, err := GenerateLayoutV2(ExportInput{
				ClusterName:   sc.cluster,
				Env:           sc.env,
				Helm:          input.helm,
				Native:        input.native,
				NamespaceMeta: input.nsMeta,
			})
			if err != nil {
				t.Fatalf("GenerateLayoutV2: %v", err)
			}

			// Synthesize coverage.yaml the same way RunExportV2 does so the
			// rendered tree includes it for the diff.
			nativeItems := input.native.Items
			report := BuildCoverage(CoverageInput{
				ClusterName:   sc.cluster,
				Env:           sc.env,
				EmittedFiles:  tree,
				Helm:          input.helm,
				Inventory:     input.native.InventoryWalk,
				NativeResults: nativeItems,
				NamespaceMeta: input.nsMeta,
			})
			covYAML, err := MarshalCoverage(report)
			if err != nil {
				t.Fatalf("MarshalCoverage: %v", err)
			}
			tree["coverage.yaml"] = covYAML

			// Explicit defense-in-depth assertions on the loud-on-unknown
			// surfaces. The byte-diff against expected/ catches these too
			// (the recorded fixtures have both lists empty), but an
			// explicit assertion makes intent visible and protects against
			// someone re-recording a fixture that bakes in a non-empty
			// surface without noticing.
			if len(report.PathCollisions) != 0 {
				t.Errorf("PathCollisions must be empty for the recorded fixture; got %d", len(report.PathCollisions))
				for _, c := range report.PathCollisions {
					t.Errorf("  collision at %s: %+v", c.Path, c.Conflicts)
				}
			}
			if len(report.DiscoveryFailures) != 0 {
				t.Errorf("DiscoveryFailures must be empty for the recorded fixture; got %d", len(report.DiscoveryFailures))
				for _, f := range report.DiscoveryFailures {
					t.Errorf("  failure: %s/%s (%s)", f.Kind, f.Name, f.Hint)
				}
			}

			diffTree(t, expected, tree)
		})
	}
}

type fixtureInput struct {
	helm   *DiscoveryResult
	native *NativeDiscoveryResult
	nsMeta NamespaceMetadataMap
}

func loadFixtureInput(t *testing.T, root string) fixtureInput {
	t.Helper()
	var in fixtureInput
	in.helm = &DiscoveryResult{}
	if err := unmarshalYAMLFile(filepath.Join(root, "input", "helm-discovery.yaml"), in.helm); err != nil {
		t.Fatalf("load helm-discovery.yaml: %v", err)
	}
	in.native = &NativeDiscoveryResult{}
	if err := unmarshalYAMLFile(filepath.Join(root, "input", "native-discovery.yaml"), in.native); err != nil {
		t.Fatalf("load native-discovery.yaml: %v", err)
	}
	in.nsMeta = NamespaceMetadataMap{}
	if err := unmarshalYAMLFile(filepath.Join(root, "input", "namespace-metadata.yaml"), &in.nsMeta); err != nil {
		t.Fatalf("load namespace-metadata.yaml: %v", err)
	}
	return in
}

func loadFixtureExpected(t *testing.T, root string) map[string][]byte {
	t.Helper()
	expectedDir := filepath.Join(root, "expected")
	out := map[string][]byte{}
	err := filepath.Walk(expectedDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(expectedDir, path)
		if err != nil {
			return err
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		out[filepath.ToSlash(rel)] = content
		return nil
	})
	if err != nil {
		t.Fatalf("walk expected/: %v", err)
	}
	return out
}

func unmarshalYAMLFile(path string, v interface{}) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, v)
}

// diffTree compares the expected fixture tree against the produced tree
// path-by-path, byte-by-byte. Reports the smallest set of differences
// possible: missing files, extra files, and content mismatches with a
// short snippet of the first diverging line.
func diffTree(t *testing.T, expected, produced map[string][]byte) {
	t.Helper()
	expectedPaths := sortedKeys(expected)
	producedPaths := sortedKeys(produced)

	expectedSet := map[string]bool{}
	for _, p := range expectedPaths {
		expectedSet[p] = true
	}
	producedSet := map[string]bool{}
	for _, p := range producedPaths {
		producedSet[p] = true
	}

	var missing, extra, mismatched []string
	for _, p := range expectedPaths {
		if !producedSet[p] {
			missing = append(missing, p)
		}
	}
	for _, p := range producedPaths {
		if !expectedSet[p] {
			extra = append(extra, p)
		}
	}
	for _, p := range expectedPaths {
		if !producedSet[p] {
			continue
		}
		if string(expected[p]) != string(produced[p]) {
			mismatched = append(mismatched, p)
		}
	}

	if len(missing) == 0 && len(extra) == 0 && len(mismatched) == 0 {
		return
	}

	for _, p := range missing {
		t.Errorf("MISSING from produced tree: %s", p)
	}
	for _, p := range extra {
		t.Errorf("EXTRA in produced tree (not in fixture): %s", p)
	}
	for _, p := range mismatched {
		t.Errorf("CONTENT DIFFERS: %s\n%s", p, firstDiff(expected[p], produced[p]))
	}
}

// firstDiff returns a short snippet showing the first diverging line
// between expected and actual. Keeps test output compact while still
// pointing at the relevant line.
func firstDiff(expected, actual []byte) string {
	expLines := strings.Split(string(expected), "\n")
	actLines := strings.Split(string(actual), "\n")
	limit := len(expLines)
	if len(actLines) < limit {
		limit = len(actLines)
	}
	for i := 0; i < limit; i++ {
		if expLines[i] != actLines[i] {
			return "  line " + itoaSimple(i+1) + ":\n    expected: " + expLines[i] + "\n    actual:   " + actLines[i]
		}
	}
	if len(expLines) != len(actLines) {
		return "  line counts differ: expected " + itoaSimple(len(expLines)) + ", actual " + itoaSimple(len(actLines))
	}
	return "  (content equal byte-for-byte but check failed — race?)"
}

func itoaSimple(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func sortedKeys(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
