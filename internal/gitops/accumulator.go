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
	"path"
	"sort"

	"sigs.k8s.io/yaml"
)

// DirectoryAccumulator collects files emitted by the export and, at finalize
// time, synthesizes one kustomization.yaml per directory listing every file
// in that directory as a resource. This is the mechanical half of the
// prune-safety guarantee (ADR-016 subsection 6.1): Kustomize ignores files
// not listed as resources, so an unlisted file produces no manifest and Flux
// prunes the corresponding live resource. By construction every emitted file
// here gets listed.
//
// The accumulator is not safe for concurrent use; callers serialize emits.
type DirectoryAccumulator struct {
	files map[string][]byte
	// dirs tracks the set of directories the accumulator has seen any file
	// in, so directories that should hold only a kustomization.yaml (e.g.
	// apps/<env>/teams/ when there are no other resources) still get one.
	dirs map[string]bool
}

// NewDirectoryAccumulator returns an empty accumulator. The zero value is
// not usable.
func NewDirectoryAccumulator() *DirectoryAccumulator {
	return &DirectoryAccumulator{
		files: map[string][]byte{},
		dirs:  map[string]bool{},
	}
}

// Add records a file at filePath with the given content. filePath is a
// repo-relative POSIX path (e.g. "infrastructure/controllers/cilium.yaml").
// The directory containing the file is automatically tracked for
// kustomization.yaml synthesis.
//
// Adding the same path twice overwrites; this lets generators emit
// idempotently when the same logical artifact is computed by multiple
// code paths.
func (a *DirectoryAccumulator) Add(filePath string, content []byte) {
	a.files[filePath] = content
	a.dirs[path.Dir(filePath)] = true
}

// EnsureDirectory records that a directory exists even if no files have
// been added to it yet. Use when a downstream kustomization.yaml needs to
// reference an empty subdirectory.
func (a *DirectoryAccumulator) EnsureDirectory(dir string) {
	a.dirs[dir] = true
}

// HasFile reports whether a path has been recorded.
func (a *DirectoryAccumulator) HasFile(filePath string) bool {
	_, ok := a.files[filePath]
	return ok
}

// FinalizeWithKustomizations returns the full set of files including a
// synthesized kustomization.yaml per tracked directory listing every resource
// file in it. The synthesis is deterministic: resources are listed in
// lexicographic order so identical inputs produce byte-identical outputs.
//
// Callers may supply per-directory transforms via the kustomizationOverrides
// map keyed by directory path. The override receives the default-resources
// kustomize file and may mutate it (e.g. to add a patches block for an env
// overlay). A nil map disables overrides.
//
// kustomization.yaml is itself never listed as a resource — Kustomize treats
// it as the entry point, not a resource. EnsureDirectory'd directories with
// no files get an empty resources list, which is valid Kustomize that
// reconciles to nothing.
func (a *DirectoryAccumulator) FinalizeWithKustomizations(
	kustomizationOverrides map[string]func(*KustomizeFile),
) (map[string][]byte, error) {
	out := make(map[string][]byte, len(a.files)+len(a.dirs))
	for p, c := range a.files {
		out[p] = c
	}

	// Build the per-directory resources list. Skip any directory where the
	// caller already supplied a kustomization.yaml manually — let manual
	// emission win to support the rare cases where the synthesized file is
	// not what we want.
	for dir := range a.dirs {
		kustPath := path.Join(dir, "kustomization.yaml")
		if _, exists := out[kustPath]; exists {
			continue
		}

		var resources []string
		for filePath := range a.files {
			if path.Dir(filePath) != dir {
				continue
			}
			base := path.Base(filePath)
			if base == "kustomization.yaml" {
				continue
			}
			resources = append(resources, base)
		}
		sort.Strings(resources)

		kf := NewKustomizeFile()
		kf.Resources = resources

		if kustomizationOverrides != nil {
			if override, ok := kustomizationOverrides[dir]; ok && override != nil {
				override(kf)
			}
		}

		yml, err := yaml.Marshal(kf)
		if err != nil {
			return nil, fmt.Errorf("marshal kustomization for %s: %w", dir, err)
		}
		out[kustPath] = yml
	}

	return out, nil
}

// Finalize is a convenience wrapper around FinalizeWithKustomizations with
// no per-directory overrides.
func (a *DirectoryAccumulator) Finalize() (map[string][]byte, error) {
	return a.FinalizeWithKustomizations(nil)
}

// Directories returns the sorted list of directories the accumulator has
// recorded. Useful for property tests asserting that every expected
// directory got a kustomization.yaml.
func (a *DirectoryAccumulator) Directories() []string {
	dirs := make([]string, 0, len(a.dirs))
	for d := range a.dirs {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs
}
