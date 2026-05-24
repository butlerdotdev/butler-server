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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/tools/clientcmd"
)

// inventory_discovery.go implements the ADR-017 D1 discovery approach:
// walk every Flux Kustomization on the cluster, read its inventory, filter
// Flux-self-management, fetch each remaining object via the dynamic client.
// Replaces the v1 fixed-kind table — generalizes to any kind Flux is
// reconciling without code changes per kind.

// FluxKustomizationObservation captures the per-Kustomization state at
// the moment its inventory was read. Used by coverage.go to record the
// snapshot moment and surface inline patches that are part of the
// Kustomization's spec but NOT part of its inventory (the env-overrides
// visibility requirement from ADR-017 revision 3 — operators applying
// per-env controller values via `spec.patches` would otherwise see the
// limitation silently flattened by the export).
type FluxKustomizationObservation struct {
	Name                 string
	Namespace            string
	Ready                bool
	LastAppliedRevision  string
	InventoryItemCount   int
	Skipped              bool
	SkipReason           string
	// SpecPatches captures the inline patches applied by the Kustomization
	// at reconcile time. Each entry is one patch with its target identifier
	// — the coverage report surfaces these so env-override-via-inline-patch
	// is operator-visible rather than silently dropped.
	SpecPatches []ObservedInlinePatch
}

// ObservedInlinePatch represents one inline patch observed on a Flux
// Kustomization's spec.patches block. PatchSize is the byte length of the
// patch body (a proxy for "how much is being overridden"); the body itself
// is not stored to keep the coverage report compact.
type ObservedInlinePatch struct {
	TargetKind      string
	TargetName      string
	TargetNamespace string
	TargetGroup     string
	PatchSize       int
}

// InventoryWalkResult holds the discovered native objects + the per-
// Kustomization observations. Layout v2 uses Items for placement; the
// coverage report uses Kustomizations to surface reconcile state + inline
// patches.
type InventoryWalkResult struct {
	Items          []*DiscoveredNative
	Kustomizations []FluxKustomizationObservation
}

// fluxGVRs enumerates the Flux GVRs whose resources are filtered as Flux
// operational (excluded from the export tree). ADR-017 D1 revised filter
// precision: every kind in these groups is part of Flux runtime
// machinery (HelmRelease + HelmRepository on user-declared releases are
// re-emitted from the existing Helm-secret discovery path, NOT from
// inventory walk, so listing helm.toolkit.fluxcd.io here filters Flux's
// own copies without dropping user state).
var fluxGVRs = map[string]bool{
	"helm.toolkit.fluxcd.io":         true,
	"source.toolkit.fluxcd.io":       true,
	"kustomize.toolkit.fluxcd.io":    true,
	"notification.toolkit.fluxcd.io": true,
	"image.toolkit.fluxcd.io":        true,
}

// fluxControllerNamePatterns is the set of NAME PREFIXES that identify
// Flux controller-managed objects in the flux-system namespace — used
// in combination with kind to filter without depending on Kustomization
// name (which would be fragile to user-defined "flux-system"-named
// Kustomizations).
var fluxControllerNamePrefixes = []string{
	"source-controller",
	"kustomize-controller",
	"helm-controller",
	"notification-controller",
	"image-reflector-controller",
	"image-automation-controller",
	"webhook-receiver",
	"crd-controller-flux-system",
	"cluster-reconciler-flux-system",
	"flux-edit-flux-system",
	"flux-view-flux-system",
	"critical-pods-flux-system",
	"allow-egress",
	"allow-scraping",
	"allow-webhooks",
}

// fluxControllerKindsInFluxSystem is the set of kinds that, when in the
// flux-system namespace AND whose name matches a fluxControllerNamePrefix,
// are filtered as Flux operational. ADR-017 D1: filter by kind + name
// pattern rather than by Kustomization name.
var fluxControllerKindsInFluxSystem = map[string]bool{
	"ServiceAccount":     true,
	"Role":               true,
	"RoleBinding":        true,
	"ClusterRole":        true,
	"ClusterRoleBinding": true,
	"Service":            true,
	"Deployment":         true,
	"ResourceQuota":      true,
	"NetworkPolicy":      true,
}

// isFluxOperational decides whether an inventory item is Flux's own
// machinery (filter out) vs user-declared gitops state (include).
// ADR-017 D1 revised filter — explicit GVR enumeration + group+kind+
// name-pattern rule. User-defined Kustomization CRs are filtered as
// operational because the v2 cluster-pointer files replace them.
func isFluxOperational(group, kind, namespace, name string) bool {
	// Rule 1: anything in a Flux GVR group is Flux operational.
	if fluxGVRs[group] {
		return true
	}
	// Rule 2: the CRDs for Flux GVRs themselves.
	if kind == "CustomResourceDefinition" {
		for fluxGroup := range fluxGVRs {
			if strings.HasSuffix(name, "."+fluxGroup) {
				return true
			}
		}
	}
	// Rule 3: Flux controller-shaped objects in flux-system namespace.
	if namespace == "flux-system" && fluxControllerKindsInFluxSystem[kind] {
		for _, prefix := range fluxControllerNamePrefixes {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
		// Names like crd-controller-flux-system also match without prefix
		// trim; cluster-scoped variants caught above. Explicit ClusterRole
		// + ClusterRoleBinding lookups whose namespace is "" but name
		// starts with a Flux pattern get caught in the cluster-scope rule
		// below.
	}
	// Rule 4: cluster-scoped Flux controller bindings (ClusterRole,
	// ClusterRoleBinding) — namespace == "" but name matches Flux pattern.
	if namespace == "" && (kind == "ClusterRole" || kind == "ClusterRoleBinding") {
		for _, prefix := range fluxControllerNamePrefixes {
			if strings.HasPrefix(name, prefix) {
				return true
			}
		}
	}
	return false
}

// parseInventoryID parses a Flux Kustomization inventory entry id of the
// format <namespace>_<name>_<group>_<kind>. Empty namespace or group
// render as empty between underscores. Name can contain underscores;
// parse from the right (kind, then group) since both are bounded
// identifiers.
func parseInventoryID(id string) (namespace, name, group, kind string, ok bool) {
	// Right-split off kind.
	idx := strings.LastIndex(id, "_")
	if idx < 0 {
		return "", "", "", "", false
	}
	kind = id[idx+1:]
	rest := id[:idx]
	// Right-split off group.
	idx = strings.LastIndex(rest, "_")
	if idx < 0 {
		return "", "", "", "", false
	}
	group = rest[idx+1:]
	rest = rest[:idx]
	// Remainder is <ns>_<name>. Split on first underscore — empty ns
	// renders as "_<name>".
	idx = strings.Index(rest, "_")
	if idx < 0 {
		return "", "", "", "", false
	}
	namespace = rest[:idx]
	name = rest[idx+1:]
	return namespace, name, group, kind, true
}

// DiscoverFluxInventory walks all Flux Kustomization CRs cluster-wide,
// reads their inventories, filters Flux-self-management, and fetches
// each remaining inventory item via the dynamic client. Returns the
// flattened items plus per-Kustomization observations the coverage
// report uses.
//
// V1 reconcile-state handling (ADR-017 D6 V1):
//   - For each Kustomization, capture Ready condition + lastAppliedRevision
//     at inventory-read moment.
//   - Skip Kustomizations whose Ready is False AND inventory is empty —
//     there's no consistent state to read.
//   - Snapshot drift across N reads is acknowledged in the per-
//     Kustomization observed-revision field; the coverage report
//     surfaces it so the operator sees the snapshot moment per
//     Kustomization.
//
// Read-only: only List and Get are called.
func DiscoverFluxInventory(ctx context.Context, kubeconfig []byte) (*InventoryWalkResult, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}
	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	kustGVR := schema.GroupVersionResource{
		Group:    "kustomize.toolkit.fluxcd.io",
		Version:  "v1",
		Resource: "kustomizations",
	}
	kustList, err := dynClient.Resource(kustGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list Flux Kustomizations: %w", err)
	}

	result := &InventoryWalkResult{}
	seen := map[string]bool{} // dedup across Kustomization inventories

	for i := range kustList.Items {
		ks := &kustList.Items[i]
		obs := observeKustomization(ks)
		if obs.Skipped {
			slog.Debug("inventory walk skipped Kustomization",
				"name", obs.Name, "reason", obs.SkipReason)
			result.Kustomizations = append(result.Kustomizations, obs)
			continue
		}
		// Read inventory entries from .status.inventory.entries.
		entries, _, _ := unstructured.NestedSlice(ks.Object, "status", "inventory", "entries")
		obs.InventoryItemCount = len(entries)
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
			if isFluxOperational(group, kind, ns, name) {
				continue
			}
			dedupKey := id
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true

			// Helm releases come from the secret-label path, NOT inventory walk.
			// (HelmRelease + HelmRepository are filtered above via fluxGVRs.)
			obj, err := fetchInventoryObject(ctx, dynClient, group, kind, ns, name)
			if err != nil {
				slog.Debug("inventory item fetch failed",
					"id", id, "error", err)
				continue
			}
			result.Items = append(result.Items, &DiscoveredNative{
				Kind:       kind,
				APIVersion: obj.GetAPIVersion(),
				Namespace:  ns,
				Name:       name,
				Object:     obj,
			})
		}
		result.Kustomizations = append(result.Kustomizations, obs)
	}

	return result, nil
}

// observeKustomization extracts the per-Kustomization observation:
// Ready condition, lastAppliedRevision, inline patches. Decides whether
// to skip (Ready=False AND empty inventory).
func observeKustomization(ks *unstructured.Unstructured) FluxKustomizationObservation {
	obs := FluxKustomizationObservation{
		Name:      ks.GetName(),
		Namespace: ks.GetNamespace(),
	}

	// Ready condition.
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

	// lastAppliedRevision.
	rev, _, _ := unstructured.NestedString(ks.Object, "status", "lastAppliedRevision")
	obs.LastAppliedRevision = rev

	// Inline patches from spec.patches. These are NOT inventory items —
	// they're spec fields on the Kustomization itself, which means an
	// inventory-walk discovery would miss them. The coverage report
	// surfaces them per ADR-017 revision 3.
	patches, _, _ := unstructured.NestedSlice(ks.Object, "spec", "patches")
	for _, p := range patches {
		pm, ok := p.(map[string]interface{})
		if !ok {
			continue
		}
		obs.SpecPatches = append(obs.SpecPatches, observePatch(pm))
	}

	// Skip decision: Ready=False AND empty inventory. The inventory
	// emptiness is checked AFTER this function returns (it's
	// .status.inventory.entries on the unstructured); we pre-compute
	// the skip-on-not-ready signal here based on the convention that
	// not-ready Kustomizations may have stale/empty inventory.
	inventory, _, _ := unstructured.NestedSlice(ks.Object, "status", "inventory", "entries")
	if !obs.Ready && len(inventory) == 0 {
		obs.Skipped = true
		obs.SkipReason = "Ready=False AND empty inventory — no consistent state to read"
	}

	return obs
}

// observePatch extracts an ObservedInlinePatch from a spec.patches
// entry. The patch body text is summarized by its byte length; the
// target is captured verbatim from the patches[].target field.
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

// fetchInventoryObject pulls the live object for an inventory entry via
// the dynamic client. The Resource (plural lowercase) is derived from
// Kind via a small map — covers the kinds the v2 export's placement
// table actually handles. For kinds outside the map, falls back to a
// best-effort guess (lowercase + 's') which works for most CRDs but is
// known-fallible for irregular plurals (e.g. NetworkPolicy →
// networkpolicies, not networkpolicys); critical kinds are in the
// explicit map.
func fetchInventoryObject(ctx context.Context, dyn dynamic.Interface, group, kind, namespace, name string) (*unstructured.Unstructured, error) {
	resource, version := resourceAndVersionForKind(group, kind)
	gvr := schema.GroupVersionResource{Group: group, Version: version, Resource: resource}

	var obj *unstructured.Unstructured
	var err error
	if namespace != "" {
		obj, err = dyn.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	} else {
		obj, err = dyn.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
	}
	if err != nil {
		return nil, err
	}
	stripServerGeneratedFields(obj)
	return obj, nil
}

// resourceAndVersionForKind returns the plural resource name and API
// version for an inventory item's Kind+Group. Covers core + Butler +
// the tenant kinds ADR-017 D4 lists, plus a fallback for unknown kinds.
func resourceAndVersionForKind(group, kind string) (string, string) {
	switch group {
	case "":
		// Core resources.
		switch kind {
		case "Namespace":
			return "namespaces", "v1"
		case "ConfigMap":
			return "configmaps", "v1"
		case "Secret":
			return "secrets", "v1"
		case "Service":
			return "services", "v1"
		case "ServiceAccount":
			return "serviceaccounts", "v1"
		}
	case "apiextensions.k8s.io":
		if kind == "CustomResourceDefinition" {
			return "customresourcedefinitions", "v1"
		}
	case "rbac.authorization.k8s.io":
		switch kind {
		case "Role":
			return "roles", "v1"
		case "RoleBinding":
			return "rolebindings", "v1"
		case "ClusterRole":
			return "clusterroles", "v1"
		case "ClusterRoleBinding":
			return "clusterrolebindings", "v1"
		}
	case "apps":
		if kind == "Deployment" {
			return "deployments", "v1"
		}
	case "networking.k8s.io":
		if kind == "NetworkPolicy" {
			return "networkpolicies", "v1"
		}
	case "storage.k8s.io":
		if kind == "StorageClass" {
			return "storageclasses", "v1"
		}
	case "cert-manager.io":
		switch kind {
		case "ClusterIssuer":
			return "clusterissuers", "v1"
		case "Issuer":
			return "issuers", "v1"
		}
	case "butler.butlerlabs.dev":
		// Lowercased kind + 's' works for every Butler CRD plural
		// (identityproviders, networkpools, providerconfigs, teams,
		// clustercreationpolicies all match this pattern).
		return strings.ToLower(kind) + "s", "v1alpha1"
	case "bitnami.com":
		if kind == "SealedSecret" {
			return "sealedsecrets", "v1alpha1"
		}
	case "metallb.io":
		switch kind {
		case "IPAddressPool":
			return "ipaddresspools", "v1beta1"
		case "L2Advertisement":
			return "l2advertisements", "v1beta1"
		}
	case "kafka.strimzi.io":
		switch kind {
		case "Kafka":
			return "kafkas", "v1beta2"
		case "KafkaNodePool":
			return "kafkanodepools", "v1beta2"
		case "KafkaTopic":
			return "kafkatopics", "v1beta2"
		case "KafkaUser":
			return "kafkausers", "v1beta2"
		case "KafkaConnect":
			return "kafkaconnects", "v1beta2"
		}
	case "keda.sh":
		switch kind {
		case "ScaledObject":
			return "scaledobjects", "v1alpha1"
		case "ScaledJob":
			return "scaledjobs", "v1alpha1"
		case "TriggerAuthentication":
			return "triggerauthentications", "v1alpha1"
		}
	}
	// Fallback: lowercased kind + 's'. Works for most CRDs; irregular
	// plurals fail Get and fall through to the skip-on-error path.
	return strings.ToLower(kind) + "s", "v1"
}
