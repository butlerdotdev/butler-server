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
	Object     *unstructured.Unstructured
}

// NativeDiscoveryResult buckets discovered native resources by kind so the
// layout generator can iterate them with kind-specific placement rules.
//
// ADR-017 D1 changed the discovery source from a fixed-kind list to a
// Flux-inventory walk. The typed buckets remain for caller ergonomics
// (counts per kind for logging/coverage), populated by routing each
// inventory item to its bucket by Kind. Items whose Kind doesn't match
// a typed bucket land in Other, which the layout generator still
// iterates so the scope-tiered default placement (D4) catches them.
//
// Only kinds that are gitops-managed desired-state belong here.
// Controller-owned runtime objects (e.g. StewardControlPlane, reconciled
// by butler-controller from TenantCluster CRs) are deliberately excluded
// at the inventory-walk level: anything that Flux is not managing is not
// in the inventory.
type NativeDiscoveryResult struct {
	IdentityProviders       []*DiscoveredNative
	NetworkPools            []*DiscoveredNative
	ProviderConfigs         []*DiscoveredNative
	Teams                   []*DiscoveredNative
	ClusterCreationPolicies []*DiscoveredNative
	ButlerGitOpsConfig      *DiscoveredNative
	SealedSecrets           []*DiscoveredNative
	MetalLBIPAddressPools   []*DiscoveredNative
	MetalLBL2Advertisements []*DiscoveredNative
	// Other holds inventory items whose Kind doesn't match a typed
	// bucket. Layout v2 routes them via PathForNativeWithDefault
	// (scope-tiered default placement); the coverage report surfaces
	// them as InScopeUncaptured so operators can request explicit
	// path-table entries.
	Other []*DiscoveredNative
	// InventoryWalk captures the per-Kustomization observations
	// (Ready, lastAppliedRevision, inline patches) so coverage.go can
	// surface them. Empty when discovery falls back to the v1 fixed-
	// kind path (e.g., a cluster with no Flux Kustomizations).
	InventoryWalk *InventoryWalkResult
}

// DiscoverNativeResources enumerates native (non-HelmRelease) resources
// gitops-managed on the cluster. Per ADR-017 D1, discovery now routes
// through DiscoverFluxInventory: walks every Flux Kustomization on the
// cluster, reads its inventory, filters Flux-self-management, fetches
// each remaining inventory item via the dynamic client. The v1 fixed-
// kind table is gone — the inventory walk handles any kind Flux is
// reconciling without per-kind code.
//
// Read-only: only List and Get are called; no cluster writes.
//
// ADR-017 D1: discovery now routes through DiscoverFluxInventory (walks
// every Flux Kustomization on the cluster, reads inventories, filters
// Flux-self-management, fetches each remaining inventory item). The
// typed-bucket signature is preserved for caller compatibility; items
// are bucketed by Kind after the walk. Items whose Kind doesn't match
// a typed bucket land in result.Other and flow through scope-tiered
// default placement (D4) at layout time.
func DiscoverNativeResources(ctx context.Context, kubeconfig []byte) (*NativeDiscoveryResult, error) {
	walk, err := DiscoverFluxInventory(ctx, kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("inventory walk failed: %w", err)
	}

	result := &NativeDiscoveryResult{InventoryWalk: walk}
	for _, item := range walk.Items {
		bucketize(result, item)
	}
	return result, nil
}

// bucketize routes a discovered native item to its typed bucket on
// NativeDiscoveryResult, or to Other if the Kind doesn't match a typed
// bucket. The typed buckets exist for caller ergonomics (per-kind
// counts in logging + coverage); the layout generator flattens all
// buckets including Other for emission.
func bucketize(result *NativeDiscoveryResult, item *DiscoveredNative) {
	switch item.Kind {
	case "IdentityProvider":
		result.IdentityProviders = append(result.IdentityProviders, item)
	case "NetworkPool":
		result.NetworkPools = append(result.NetworkPools, item)
	case "ProviderConfig":
		result.ProviderConfigs = append(result.ProviderConfigs, item)
	case "Team":
		result.Teams = append(result.Teams, item)
	case "ClusterCreationPolicy":
		result.ClusterCreationPolicies = append(result.ClusterCreationPolicies, item)
	case "SealedSecret":
		result.SealedSecrets = append(result.SealedSecrets, item)
	case "IPAddressPool":
		result.MetalLBIPAddressPools = append(result.MetalLBIPAddressPools, item)
	case "L2Advertisement":
		result.MetalLBL2Advertisements = append(result.MetalLBL2Advertisements, item)
	case "ConfigMap":
		if item.Name == "butler-gitops-config" && item.Namespace == "butler-system" {
			result.ButlerGitOpsConfig = item
			return
		}
		result.Other = append(result.Other, item)
	default:
		result.Other = append(result.Other, item)
	}
}

// stripServerGeneratedFields removes fields that the API server populates
// (uid, resourceVersion, generation, status, managedFields, creationTimestamp).
// These should not appear in exported manifests — they belong to a specific
// cluster instance, not to the declarative config that the GitOps tree carries.
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
	} {
		delete(meta, field)
	}
	delete(obj.Object, "status")
}
