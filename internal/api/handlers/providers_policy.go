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

package handlers

import (
	"context"

	butlerv1alpha1 "github.com/butlerdotdev/butler-api/api/v1alpha1"
	butlerpolicy "github.com/butlerdotdev/butler-api/pkg/policy"

	"github.com/butlerdotdev/butler-server/internal/api/policy"
	"github.com/butlerdotdev/butler-server/internal/auth"
)

// GetID methods satisfy the policy.HasID interface so the generic
// policy.Apply filter can compare option-list entries against rule
// values without per-type code. See ADR-018 Decision section 7.

// GetID returns the image's stable identifier (Nutanix UUID, Harvester
// namespace/name).
func (i ImageInfo) GetID() string { return i.ID }

// GetID returns the network's stable identifier.
func (n NetworkInfo) GetID() string { return n.ID }

// GetID returns the cluster's stable identifier.
func (c ClusterInfo) GetID() string { return c.ID }

// GetID returns the storage container's stable identifier.
func (s StorageContainerInfo) GetID() string { return s.ID }

// resolutionContext builds the ADR-018 resolution context from the
// request session and the resolved provider type.
func (h *ProvidersHandler) resolutionContext(ctx context.Context, providerType string) butlerpolicy.ResolutionContext {
	rc := butlerpolicy.ResolutionContext{ProviderType: butlerv1alpha1.ProviderType(providerType)}
	user := auth.UserFromContext(ctx)
	if user != nil {
		rc.TeamName = user.SelectedTeam
		rc.EnvironmentName = user.SelectedEnvironment
	}
	return rc
}

// applyImagePolicy filters and decorates an image list according to any
// applicable ClusterCreationPolicy. Errors fetching policies are
// non-fatal: the unfiltered list is returned so a transient List
// failure does not block the modal entirely.
func (h *ProvidersHandler) applyImagePolicy(ctx context.Context, providerType string, items []ImageInfo) ([]ImageInfo, *policy.Metadata) {
	rc := h.resolutionContext(ctx, providerType)
	filtered, meta, err := policy.Apply(ctx, h.k8sClient.Dynamic(), items, butlerv1alpha1.OptionTypeImage, rc, nil)
	if err != nil {
		return items, nil
	}
	return filtered, meta
}

// applyNetworkPolicy filters and decorates a network list.
func (h *ProvidersHandler) applyNetworkPolicy(ctx context.Context, providerType string, items []NetworkInfo) ([]NetworkInfo, *policy.Metadata) {
	rc := h.resolutionContext(ctx, providerType)
	filtered, meta, err := policy.Apply(ctx, h.k8sClient.Dynamic(), items, butlerv1alpha1.OptionTypeNetwork, rc, nil)
	if err != nil {
		return items, nil
	}
	return filtered, meta
}

// applyClusterPolicy filters and decorates a Nutanix cluster list.
func (h *ProvidersHandler) applyClusterPolicy(ctx context.Context, providerType string, items []ClusterInfo) ([]ClusterInfo, *policy.Metadata) {
	rc := h.resolutionContext(ctx, providerType)
	filtered, meta, err := policy.Apply(ctx, h.k8sClient.Dynamic(), items, butlerv1alpha1.OptionTypeCluster, rc, nil)
	if err != nil {
		return items, nil
	}
	return filtered, meta
}

// applyStorageContainerPolicy filters and decorates a Nutanix storage
// container list.
func (h *ProvidersHandler) applyStorageContainerPolicy(ctx context.Context, providerType string, items []StorageContainerInfo) ([]StorageContainerInfo, *policy.Metadata) {
	rc := h.resolutionContext(ctx, providerType)
	filtered, meta, err := policy.Apply(ctx, h.k8sClient.Dynamic(), items, butlerv1alpha1.OptionTypeStorageContainer, rc, nil)
	if err != nil {
		return items, nil
	}
	return filtered, meta
}
