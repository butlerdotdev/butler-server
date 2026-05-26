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
	"log/slog"
	"strings"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

// inventory_discovery.go implements the ADR-017 D1 discovery approach:
// walk every Flux Kustomization on the cluster, read its inventory,
// filter Flux-self-management, fetch each remaining object via the
// dynamic client.
//
// AGNOSTIC DISCOVERY PRINCIPLE (post-Step-A audit): this file references
// EXACTLY ONE specific group/kind — the irreducible seed
// kustomize.toolkit.fluxcd.io/v1 Kustomization that the inventory walk
// must list to start at all. Everything else is derived from the cluster:
//
//   - The set of resources Flux serves: read from the cluster's
//     discovery endpoints via RESTMapper.
//   - The GVR (plural resource name + served version) for any given
//     (group, kind): resolved via RESTMapper.RESTMapping.
//   - Whether a resource is namespaced or cluster-scoped: resolved via
//     RESTMapping.Scope.
//   - The set of Flux-operational items (controllers, RBAC, CRDs Flux
//     installed for itself): derived as the inventory of the bootstrap
//     Kustomization, which identifies itself by self-reference (it
//     manages a Kustomization CR pointing at itself).
//
// The acceptance test for agnosticism: a tenant running an operator
// none of this code has seen, with CRDs this code has never named,
// exports correctly with zero changes here. The placement layer
// (layout_paths.go) is opinionated-over-default and is allowed to
// know about specific kinds for nice paths; discovery is not.

// FluxKustomizationObservation captures the per-Kustomization state at
// the moment its inventory was read. Used by coverage.go to record the
// snapshot moment and surface inline patches that are part of the
// Kustomization's spec but NOT part of its inventory (ADR-017 revision 3
// env-overrides visibility requirement).
type FluxKustomizationObservation struct {
	Name                string
	Namespace           string
	Ready               bool
	LastAppliedRevision string
	InventoryItemCount  int
	Skipped             bool
	SkipReason          string
	SpecPatches         []ObservedInlinePatch
}

// ObservedInlinePatch represents one inline patch observed on a Flux
// Kustomization's spec.patches block. PatchSize is the byte length of
// the patch body (proxy for "how much is being overridden"); the body
// itself is not stored to keep the coverage report compact.
type ObservedInlinePatch struct {
	TargetKind      string
	TargetName      string
	TargetNamespace string
	TargetGroup     string
	PatchSize       int
}

// InventoryWalkResult holds the discovered native objects + the per-
// Kustomization observations + any fetch failures.
//
// FetchFailures: Step A tenant validation surfaced silent fetch-drop
// as a load-bearing failure mode (an inventory entry referenced a CRD
// version the cluster no longer served, and the fetch error was
// swallowed — 11 user-workload items dropped invisibly). Every fetch
// failure is now captured here AND logged loudly via slog.Warn —
// coverage report surfaces this list under discoveryFailures so an
// item the inventory walk found but couldn't fetch is operator-visible
// rather than disappearing beneath the prune-safety property test.
type InventoryWalkResult struct {
	Items          []*DiscoveredNative
	Kustomizations []FluxKustomizationObservation
	FetchFailures  []InventoryFetchFailure
}

// InventoryFetchFailure records an inventory entry the walk discovered
// in some Flux Kustomization's inventory but could not fetch via the
// dynamic client. Surfaces in coverage.yaml under discoveryFailures so
// fetch-found-nothing is loud, not silent.
type InventoryFetchFailure struct {
	InventoryID         string
	Group               string
	Kind                string
	Namespace           string
	Name                string
	SourceKustomization string
	Error               string
	Hint                string
}

// kustomizationGVR is the ONE irreducible seed for the inventory walk.
// We must name some GVR to list the cluster's Flux Kustomizations and
// start the walk at all; the Kustomization GVK is that seed. Every
// other group/kind in the discovery path is derived from the cluster
// via RESTMapper or from this seed's recursive self-reference.
var kustomizationGVR = schema.GroupVersionResource{
	Group:    "kustomize.toolkit.fluxcd.io",
	Version:  "v1",
	Resource: "kustomizations",
}

// parseInventoryID parses a Flux Kustomization inventory entry id of
// the format <namespace>_<name>_<group>_<kind>. Empty namespace or
// group render as empty between underscores. Name can contain
// underscores; parse from the right (kind, then group) since both are
// bounded identifiers.
func parseInventoryID(id string) (namespace, name, group, kind string, ok bool) {
	idx := strings.LastIndex(id, "_")
	if idx < 0 {
		return "", "", "", "", false
	}
	kind = id[idx+1:]
	rest := id[:idx]
	idx = strings.LastIndex(rest, "_")
	if idx < 0 {
		return "", "", "", "", false
	}
	group = rest[idx+1:]
	rest = rest[:idx]
	idx = strings.Index(rest, "_")
	if idx < 0 {
		return "", "", "", "", false
	}
	namespace = rest[:idx]
	name = rest[idx+1:]
	return namespace, name, group, kind, true
}

// buildInventoryID renders a Flux inventory entry id from its components.
// Inverse of parseInventoryID, used to compare inventory items against
// a known set (e.g., the bootstrap Kustomization's inventory).
func buildInventoryID(namespace, name, group, kind string) string {
	return fmt.Sprintf("%s_%s_%s_%s", namespace, name, group, kind)
}

// DiscoverFluxInventory walks all Flux Kustomization CRs cluster-wide,
// reads their inventories, derives the Flux-self-management filter from
// the bootstrap Kustomization's inventory, and fetches each remaining
// inventory item via RESTMapper-resolved dynamic client calls.
//
// Read-only: only List and Get are called on the cluster.
//
// V1 reconcile-state handling (ADR-017 D6 V1): for each Kustomization,
// capture Ready + lastAppliedRevision at inventory-read moment; skip
// Kustomizations whose Ready is False AND inventory is empty (no
// consistent state to read); record observed revisions per Kustomization
// so the coverage report surfaces the snapshot moment.
//
// Loud-on-silent-drop (ADR-017 Step A correction): every fetch failure
// is recorded in result.FetchFailures AND logged at WARN level. The
// inventory-walked-but-not-fetched class is the silent-drop pattern
// the Step A validation exposed (a hardcoded GVR table that named a
// CRD version the cluster no longer served); this architecture makes
// that class structurally impossible to hide.
func DiscoverFluxInventory(ctx context.Context, kubeconfig []byte) (*InventoryWalkResult, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}
	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery client: %w", err)
	}
	grResources, err := restmapper.GetAPIGroupResources(discoveryClient)
	if err != nil {
		return nil, fmt.Errorf("failed to load API group resources: %w", err)
	}
	mapper := restmapper.NewDiscoveryRESTMapper(grResources)

	// Seed: list all Kustomizations cluster-wide via the named GVK.
	kustList, err := dynClient.Resource(kustomizationGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list Flux Kustomizations: %w", err)
	}

	// Derive Flux-self-management set from the bootstrap Kustomization's
	// own inventory. A Kustomization is "the bootstrap" if it manages
	// itself (self-referential inventory entry pointing back at its own
	// GVK + namespace/name). This identification uses ONLY the seed GVK
	// — no hand-kept list of Flux controller names, namespaces, or kinds.
	fluxOperational := deriveFluxOperationalSet(kustList)

	result := &InventoryWalkResult{}
	seen := map[string]bool{}

	for i := range kustList.Items {
		ks := &kustList.Items[i]
		obs := observeKustomization(ks)
		result.Kustomizations = append(result.Kustomizations, obs)
		if obs.Skipped {
			slog.Debug("inventory walk skipped Kustomization",
				"name", obs.Name, "reason", obs.SkipReason)
			continue
		}
		entries, _, _ := unstructured.NestedSlice(ks.Object, "status", "inventory", "entries")
		for _, e := range entries {
			entry, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			id, _ := entry["id"].(string)
			ns, name, group, kind, ok := parseInventoryID(id)
			if !ok {
				continue
			}
			if fluxOperational[id] {
				continue
			}
			if seen[id] {
				continue
			}
			seen[id] = true

			obj, isNamespaced, err := fetchInventoryObject(ctx, dynClient, mapper, group, kind, ns, name)
			if err != nil {
				// Loud-on-silent-drop: WARN log AND record in
				// FetchFailures. Coverage report surfaces this under
				// discoveryFailures so the operator sees what was
				// found-but-not-fetched.
				slog.Warn("inventory item fetch failed — possible discovery bug",
					"id", id, "group", group, "kind", kind,
					"namespace", ns, "name", name,
					"sourceKustomization", ks.GetName(),
					"error", err.Error())
				result.FetchFailures = append(result.FetchFailures, InventoryFetchFailure{
					InventoryID:         id,
					Group:               group,
					Kind:                kind,
					Namespace:           ns,
					Name:                name,
					SourceKustomization: ks.GetName(),
					Error:               err.Error(),
					Hint:                fetchFailureHint(err),
				})
				continue
			}
			result.Items = append(result.Items, &DiscoveredNative{
				Kind:         kind,
				APIVersion:   obj.GetAPIVersion(),
				Namespace:    ns,
				Name:         name,
				IsNamespaced: isNamespaced,
				Object:       obj,
			})
		}
	}

	return result, nil
}

// deriveFluxOperationalSet returns the set of inventory IDs that
// belong to the Flux bootstrap — derived from the bootstrap
// Kustomization's own inventory, NOT from any hand-kept list of Flux
// groups, kinds, or controller names.
//
// A Kustomization is "the bootstrap" if it manages itself: its
// inventory contains a reference to itself (built from the seed
// Kustomization GVK + its own namespace/name). This identification
// uses ONLY the seed; it doesn't name any other Flux component.
//
// If no bootstrap Kustomization is found (Flux installed via some
// non-standard path), the filter is empty — fail-open, over-include
// rather than silently exclude user state. Operators reviewing the
// export would see Flux machinery in the tree (visible noise) rather
// than have user state silently dropped (invisible loss).
func deriveFluxOperationalSet(kustList *unstructured.UnstructuredList) map[string]bool {
	out := map[string]bool{}
	for i := range kustList.Items {
		ks := &kustList.Items[i]
		selfID := buildInventoryID(
			ks.GetNamespace(), ks.GetName(),
			kustomizationGVR.Group, "Kustomization",
		)
		entries, _, _ := unstructured.NestedSlice(ks.Object, "status", "inventory", "entries")
		hasSelf := false
		for _, e := range entries {
			entry, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			id, _ := entry["id"].(string)
			if id == selfID {
				hasSelf = true
				break
			}
		}
		if !hasSelf {
			continue
		}
		// This Kustomization manages itself — it's the bootstrap.
		// Its entire inventory is Flux-operational.
		for _, e := range entries {
			entry, ok := e.(map[string]interface{})
			if !ok {
				continue
			}
			id, _ := entry["id"].(string)
			if id != "" {
				out[id] = true
			}
		}
	}
	return out
}

// observeKustomization extracts the per-Kustomization observation:
// Ready condition, lastAppliedRevision, inline patches. Decides
// whether to skip (Ready=False AND empty inventory).
func observeKustomization(ks *unstructured.Unstructured) FluxKustomizationObservation {
	obs := FluxKustomizationObservation{
		Name:      ks.GetName(),
		Namespace: ks.GetNamespace(),
	}

	conditions, _, _ := unstructured.NestedSlice(ks.Object, "status", "conditions")
	for _, c := range conditions {
		cm, ok := c.(map[string]interface{})
		if !ok {
			continue
		}
		if t, _ := cm["type"].(string); t == "Ready" {
			if s, _ := cm["status"].(string); s == "True" {
				obs.Ready = true
			}
			break
		}
	}

	rev, _, _ := unstructured.NestedString(ks.Object, "status", "lastAppliedRevision")
	obs.LastAppliedRevision = rev

	patches, _, _ := unstructured.NestedSlice(ks.Object, "spec", "patches")
	for _, p := range patches {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		obs.SpecPatches = append(obs.SpecPatches, observePatch(pm))
	}

	inventory, _, _ := unstructured.NestedSlice(ks.Object, "status", "inventory", "entries")
	obs.InventoryItemCount = len(inventory)
	if !obs.Ready && len(inventory) == 0 {
		obs.Skipped = true
		obs.SkipReason = "Ready=False AND empty inventory — no consistent state to read"
	}

	return obs
}

func observePatch(p map[string]interface{}) ObservedInlinePatch {
	op := ObservedInlinePatch{}
	if patchStr, ok := p["patch"].(string); ok {
		op.PatchSize = len(patchStr)
	}
	target, ok := p["target"].(map[string]interface{})
	if ok {
		op.TargetKind, _ = target["kind"].(string)
		op.TargetName, _ = target["name"].(string)
		op.TargetNamespace, _ = target["namespace"].(string)
		op.TargetGroup, _ = target["group"].(string)
	}
	return op
}

// fetchInventoryObject pulls the live object for an inventory entry
// via the dynamic client. RESTMapper resolves (group, kind) → GVR +
// scope using the cluster's own discovery endpoints — no hardcoded
// resource-name or version table. The cluster says what it serves;
// this code doesn't guess.
//
// Returns (object, isNamespaced, error). The scope bit is plumbed to the
// caller so the placement layer can decide whether to include the
// namespace segment in the emitted filename without consulting the
// RESTMapper a second time.
//
// Error returned is plumbed through to the caller's FetchFailures
// recording so any fetch that fails is loud, not silent.
func fetchInventoryObject(ctx context.Context, dyn dynamic.Interface, mapper meta.RESTMapper, group, kind, namespace, name string) (*unstructured.Unstructured, bool, error) {
	mapping, err := mapper.RESTMapping(schema.GroupKind{Group: group, Kind: kind})
	if err != nil {
		return nil, false, fmt.Errorf("RESTMapping: %w", err)
	}

	isNamespaced := mapping.Scope.Name() == meta.RESTScopeNameNamespace
	var obj *unstructured.Unstructured
	if isNamespaced {
		obj, err = dyn.Resource(mapping.Resource).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	} else {
		obj, err = dyn.Resource(mapping.Resource).Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		return nil, false, err
	}
	stripServerGeneratedFields(obj)
	return obj, isNamespaced, nil
}

// fetchFailureHint classifies a fetch error by error-string pattern.
// The hint is short prose intended for operator triage; it does NOT
// reference specific kinds or groups (kind-agnostic).
func fetchFailureHint(err error) string {
	es := err.Error()
	switch {
	case strings.Contains(es, "no matches for kind") || strings.Contains(es, "the server could not find the requested resource"):
		return "RESTMapper could not resolve this GroupKind to a served resource — CRD may not be installed at the version the inventory entry references, or the API version was deprecated since the inventory snapshot"
	case strings.Contains(es, "forbidden"):
		return "RBAC denial fetching this resource — the export caller's identity lacks get permission for this kind"
	case strings.Contains(es, "not found"):
		return "inventory entry references an object that no longer exists on the cluster — stale inventory, possibly mid-prune"
	default:
		return "unknown fetch failure class — surface with operator for diagnosis"
	}
}
