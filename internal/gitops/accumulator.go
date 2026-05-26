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
// synthesized kustomization.yaml per tracked directory listing every direct
// child resource (files AND immediate subdirectories) in lexicographic
// order so identical inputs produce byte-identical outputs.
//
// AGNOSTIC CHAINING: every directory on the path from each emitted file
// up to the repo root is auto-tracked, and each tracked directory's
// kustomization.yaml lists both files and subdirectories. This is what
// Kustomize needs to actually build the tree — without subdirectory
// references in parent kustomization.yaml files, Kustomize ignores any
// emitted leaf and Flux would prune the corresponding live state. The
// rule derives entirely from the emitted directory structure; no
// hardcoded paths or depth limits.
//
// Callers may supply per-directory transforms via kustomizationOverrides
// keyed by directory path. The override receives the auto-built kustomize
// file (with resources already populated from files + subdirs) and may
// mutate it (e.g. to add a patches block). Overrides that need to add
// resources should APPEND to kf.Resources, not replace it, so the
// agnostic chain stays intact.
//
// Manually-emitted kustomization.yaml at a directory wins over synthesis;
// the caller is taking full responsibility for that directory's resources
// list (and must include any subdirectory references themselves).
//
// kustomization.yaml is itself never listed as a resource — Kustomize
// treats it as the entry point, not a resource.
func (a *DirectoryAccumulator) FinalizeWithKustomizations(
	kustomizationOverrides map[string]func(*KustomizeFile),
) (map[string][]byte, error) {
	out := make(map[string][]byte, len(a.files)+len(a.dirs))
	for p, c := range a.files {
		out[p] = c
	}

	// Walk-up: ensure every INTERMEDIATE ancestor of every tracked
	// directory is itself tracked, so the chain of kustomization.yaml
	// files from each leaf up to a Flux entry path exists. Stop one
	// level above the repo root — top-level dirs (apps/, clusters/,
	// infrastructure/) are NOT Flux entry paths and don't need their
	// own kustomization.yaml; Flux points at depth-2 paths like
	// apps/<env>/ or infrastructure/<tier>/.
	for dir := range a.dirs {
		cur := dir
		for {
			parent := path.Dir(cur)
			if parent == "." || parent == "/" || parent == cur {
				break
			}
			// Stop before walking into a top-level dir — we want
			// kustomization.yaml synthesized at depth-2 and below
			// (e.g., apps/prd/workloads), not at depth-1 (apps/).
			if path.Dir(parent) == "." {
				break
			}
			a.dirs[parent] = true
			cur = parent
		}
	}

	// Build the per-directory resources list (files + direct subdirs).
	// Skip any directory where the caller already supplied a
	// kustomization.yaml manually — manual emission wins.
	for dir := range a.dirs {
		kustPath := path.Join(dir, "kustomization.yaml")
		if _, exists := out[kustPath]; exists {
			continue
		}

		// Direct child files.
		var fileResources []string
		for filePath := range a.files {
			if path.Dir(filePath) != dir {
				continue
			}
			base := path.Base(filePath)
			if base == "kustomization.yaml" {
				continue
			}
			fileResources = append(fileResources, base)
		}

		// Direct child subdirectories. A tracked dir D is a direct child
		// of dir iff path.Dir(D) == dir. Each child is listed by basename
		// so Kustomize descends via its own kustomization.yaml.
		var subdirResources []string
		for other := range a.dirs {
			if other == dir {
				continue
			}
			if path.Dir(other) != dir {
				continue
			}
			subdirResources = append(subdirResources, path.Base(other))
		}

		resources := append(fileResources, subdirResources...)
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
