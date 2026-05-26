/*
Copyright 2026 The Butler Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package gitops

import (
	"bytes"
	"testing"

	"sigs.k8s.io/yaml"
)

func TestAccumulatorListsEveryFile(t *testing.T) {
	acc := NewDirectoryAccumulator()
	acc.Add("infrastructure/controllers/cilium.yaml", []byte("a"))
	acc.Add("infrastructure/controllers/cert-manager.yaml", []byte("b"))
	acc.Add("apps/base/butler-controller/release.yaml", []byte("c"))
	acc.Add("apps/base/butler-controller/repository.yaml", []byte("d"))

	out, err := acc.Finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}

	kf := unmarshalKust(t, out["infrastructure/controllers/kustomization.yaml"])
	wantInfra := []string{"cert-manager.yaml", "cilium.yaml"}
	if !equalStringSlices(kf.Resources, wantInfra) {
		t.Errorf("infra controllers kustomization resources = %v, want %v", kf.Resources, wantInfra)
	}

	kf2 := unmarshalKust(t, out["apps/base/butler-controller/kustomization.yaml"])
	wantApp := []string{"release.yaml", "repository.yaml"}
	if !equalStringSlices(kf2.Resources, wantApp) {
		t.Errorf("app butler-controller kustomization resources = %v, want %v", kf2.Resources, wantApp)
	}
}

func TestAccumulatorIdempotent(t *testing.T) {
	build := func() map[string][]byte {
		acc := NewDirectoryAccumulator()
		acc.Add("a/b.yaml", []byte("x"))
		acc.Add("a/a.yaml", []byte("y"))
		out, err := acc.Finalize()
		if err != nil {
			t.Fatalf("finalize: %v", err)
		}
		return out
	}
	first := build()
	second := build()
	for k, v := range first {
		if !bytes.Equal(v, second[k]) {
			t.Errorf("output for %s differs between runs: %s vs %s", k, v, second[k])
		}
	}
}

func TestAccumulatorOverrideWins(t *testing.T) {
	acc := NewDirectoryAccumulator()
	acc.Add("dir/a.yaml", []byte("a"))
	acc.Add("dir/kustomization.yaml", []byte("user-supplied"))
	out, _ := acc.Finalize()
	if string(out["dir/kustomization.yaml"]) != "user-supplied" {
		t.Errorf("user-supplied kustomization should win, got %s", out["dir/kustomization.yaml"])
	}
}

func TestAccumulatorOverrideCallback(t *testing.T) {
	acc := NewDirectoryAccumulator()
	acc.Add("apps/prd/a-values.yaml", []byte("a"))
	out, err := acc.FinalizeWithKustomizations(map[string]func(*KustomizeFile){
		"apps/prd": func(kf *KustomizeFile) {
			kf.Resources = []string{"../base/a"}
			kf.Patches = []KustomizePatch{{
				Path:   "a-values.yaml",
				Target: KustomizePatchTarget{Kind: "HelmRelease", Name: "a"},
			}}
		},
	})
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	kf := unmarshalKust(t, out["apps/prd/kustomization.yaml"])
	if len(kf.Patches) != 1 || kf.Patches[0].Path != "a-values.yaml" {
		t.Errorf("override callback patches = %+v", kf.Patches)
	}
	wantRes := []string{"../base/a"}
	if !equalStringSlices(kf.Resources, wantRes) {
		t.Errorf("override callback resources = %v, want %v", kf.Resources, wantRes)
	}
}

func TestAccumulatorEnsureDirectory(t *testing.T) {
	acc := NewDirectoryAccumulator()
	acc.EnsureDirectory("apps/prd/teams")
	out, err := acc.Finalize()
	if err != nil {
		t.Fatalf("finalize: %v", err)
	}
	if _, ok := out["apps/prd/teams/kustomization.yaml"]; !ok {
		t.Errorf("EnsureDirectory should produce a kustomization.yaml for the empty dir")
	}
}

func unmarshalKust(t *testing.T, data []byte) *KustomizeFile {
	t.Helper()
	var kf KustomizeFile
	if err := yaml.Unmarshal(data, &kf); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return &kf
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
