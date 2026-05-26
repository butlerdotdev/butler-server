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

import "context"

// InventoryDiscoverer returns the gitops-managed inventory of a
// cluster: native items + per-Kustomization observations + fetch
// failures, in the shape the coverage report consumes.
type InventoryDiscoverer interface {
	DiscoverInventory(ctx context.Context, kubeconfig []byte) (*InventoryWalkResult, error)
}

// FluxInventoryDiscoverer walks Flux Kustomization CRs and their
// .status.inventory.entries.
type FluxInventoryDiscoverer struct{}

func (FluxInventoryDiscoverer) DiscoverInventory(ctx context.Context, kubeconfig []byte) (*InventoryWalkResult, error) {
	return DiscoverFluxInventory(ctx, kubeconfig)
}

var _ InventoryDiscoverer = FluxInventoryDiscoverer{}
