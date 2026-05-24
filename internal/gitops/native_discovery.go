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
	"context"
	"fmt"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// DiscoveredNative represents a single native (non-HelmRelease) Kubernetes
// resource discovered during export. The Object field carries the full
// unstructured manifest so the layout generator can write it verbatim
// after any export-time cleanup (status stripping, server-generated field
// removal).
type DiscoveredNative struct {
	Kind       string
	APIVersion string
	Namespace  string
	Name       string
	// IsNamespaced is the cluster-derived scope for this kind (RESTMapper
	// scope at fetch time). True for namespaced kinds, false for
	// cluster-scoped. Consumed by the placement layer to decide whether
	// the emitted filename should include the namespace segment.
	IsNamespaced bool
	Object       *unstructured.Unstructured
}

// NativeDiscoveryResult holds the output of native-resource discovery:
// the flat list of items the inventory walk produced plus the walk
// metadata used by coverage.go (per-Kustomization observations, inline
// patches, fetch failures).
//
// AGNOSTIC DISCOVERY PRINCIPLE: this package does NOT pre-bucket items
// by kind. Kind-aware behavior belongs to placement (layout_paths.go) and
// to the layout/coverage code that consumes the flat list. The discovery
// path itself names exactly one irreducible seed — the Flux Kustomization
// GVK — and derives everything else from the cluster.
type NativeDiscoveryResult struct {
	// Items is every native resource the Flux inventory walk fetched.
	// Each item carries its own (Kind, APIVersion, Namespace, Name) so
	// downstream code can route or count by kind without the discovery
	// layer having to enumerate kinds in advance.
	Items []*DiscoveredNative

	// InventoryWalk carries the per-Kustomization observations
	// (Ready, lastAppliedRevision, inline patches) and the FetchFailures
	// list. coverage.go uses both: the observations populate
	// kustomizationObservations; the failures populate discoveryFailures
	// so an inventory entry the walk found but couldn't fetch is
	// operator-visible rather than disappearing.
	InventoryWalk *InventoryWalkResult
}

// DiscoverNativeResources enumerates native (non-HelmRelease) resources
// gitops-managed on the cluster. Per ADR-017 D1, discovery routes through
// DiscoverFluxInventory: walks every Flux Kustomization on the cluster,
// reads its inventory, filters Flux-self-management (derived from the
// bootstrap Kustomization's self-referential inventory), fetches each
// remaining inventory item via RESTMapper-resolved dynamic-client calls.
//
// Read-only: only List and Get are called; no cluster writes.
//
// The function deliberately returns a flat Items list — no per-kind
// pre-bucketing happens here. Kind-aware routing is the layout layer's
// job (PathForNativeWithDefault). This keeps discovery agnostic to which
// kinds happen to exist on a given cluster.
func DiscoverNativeResources(ctx context.Context, kubeconfig []byte) (*NativeDiscoveryResult, error) {
	walk, err := DiscoverFluxInventory(ctx, kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("inventory walk failed: %w", err)
	}
	return &NativeDiscoveryResult{
		Items:         walk.Items,
		InventoryWalk: walk,
	}, nil
}

// stripServerGeneratedFields removes the runtime/server-managed parts
// of a fetched object so the exported manifest is declarative-only:
//
//   - top-level fields the API server populates (uid, resourceVersion,
//     generation, creationTimestamp, managedFields, selfLink)
//   - the entire status subtree
//   - metadata.finalizers (admission controllers stamp these; never
//     part of an operator's declaration)
//   - runtime labels per isRuntimeLabel (Flux ownership, etc.)
//   - runtime annotations per isRuntimeAnnotation
//   - any nested creationTimestamp: null artifact in sub-objects
//     (spec.template.metadata.creationTimestamp is a known marshaling
//     leakage when the unstructured object round-trips through the
//     API server)
//
// Operator-declared labels and annotations (anything not matched by
// the runtime predicates) pass through unchanged.
func stripServerGeneratedFields(obj *unstructured.Unstructured) {
	meta, ok := obj.Object["metadata"].(map[string]interface{})
	if !ok {
		return
	}
	for _, field := range []string{
		"uid",
		"resourceVersion",
		"generation",
		"creationTimestamp",
		"managedFields",
		"selfLink",
		"finalizers",
	} {
		delete(meta, field)
	}
	stripRuntimeLabelsAnnotations(meta)
	delete(obj.Object, "status")
	stripNestedCreationTimestamps(obj.Object)
	stripNamespaceLifecycleFinalizer(obj.Object)
}

// stripNamespaceLifecycleFinalizer removes the well-known k8s namespace
// lifecycle marker spec.finalizers: [kubernetes]. The API server stamps
// this on every Namespace at creation; operators never declare it.
// Path 1's NewK8sNamespace builder doesn't emit it, so this keeps
// path 2's Namespace emission consistent with path 1.
//
// Value-based filter: only strips when spec.finalizers is exactly the
// single-element ["kubernetes"] slice. Any other spec.finalizers value
// is operator-declared and preserved (no CRD in current use has
// user-declared spec.finalizers, but the value check guards against
// over-filtering if one appears).
func stripNamespaceLifecycleFinalizer(obj map[string]interface{}) {
	spec, ok := obj["spec"].(map[string]interface{})
	if !ok {
		return
	}
	finalizers, ok := spec["finalizers"].([]interface{})
	if !ok {
		return
	}
	if len(finalizers) == 1 {
		if s, ok := finalizers[0].(string); ok && s == "kubernetes" {
			delete(spec, "finalizers")
			if len(spec) == 0 {
				delete(obj, "spec")
			}
		}
	}
}

// stripRuntimeLabelsAnnotations removes runtime entries from
// metadata.labels and metadata.annotations using the same predicates
// the namespace-enrichment path uses. Keeps operator-declared keys.
func stripRuntimeLabelsAnnotations(meta map[string]interface{}) {
	if labels, ok := meta["labels"].(map[string]interface{}); ok {
		for k := range labels {
			if isRuntimeLabel(k) {
				delete(labels, k)
			}
		}
		if len(labels) == 0 {
			delete(meta, "labels")
		}
	}
	if annotations, ok := meta["annotations"].(map[string]interface{}); ok {
		for k := range annotations {
			if isRuntimeAnnotation(k) {
				delete(annotations, k)
			}
		}
		if len(annotations) == 0 {
			delete(meta, "annotations")
		}
	}
}

// stripNestedCreationTimestamps walks the object recursively and
// removes creationTimestamp keys whose value is nil. This appears in
// nested metadata blocks (e.g. spec.template.metadata) as a
// round-tripping artifact from the API server. The top-level
// metadata.creationTimestamp is handled by the explicit delete above;
// this catches the nested cases.
func stripNestedCreationTimestamps(v interface{}) {
	switch t := v.(type) {
	case map[string]interface{}:
		if val, ok := t["creationTimestamp"]; ok && val == nil {
			delete(t, "creationTimestamp")
		}
		for _, child := range t {
			stripNestedCreationTimestamps(child)
		}
	case []interface{}:
		for _, child := range t {
			stripNestedCreationTimestamps(child)
		}
	}
}
