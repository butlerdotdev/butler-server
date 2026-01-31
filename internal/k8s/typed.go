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

package k8s

import (
	"context"
	"fmt"

	butlerv1alpha1 "github.com/butlerdotdev/butler-api/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
)

// =============================================================================
// Typed Client Methods
// =============================================================================
//
// These methods provide type-safe access to Butler CRDs by converting from
// the dynamic/unstructured client responses to proper butler-api types.
//
// This approach allows butler-server to use the same dynamic client infrastructure
// while providing typed access for handlers that need it.
// =============================================================================

// GetTenantClusterTyped retrieves a TenantCluster and returns the typed struct.
func (c *Client) GetTenantClusterTyped(ctx context.Context, namespace, name string) (*butlerv1alpha1.TenantCluster, error) {
	unstructuredTC, err := c.GetTenantCluster(ctx, namespace, name)
	if err != nil {
		return nil, err
	}

	tc := &butlerv1alpha1.TenantCluster{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredTC.Object, tc); err != nil {
		return nil, fmt.Errorf("failed to convert TenantCluster to typed: %w", err)
	}

	return tc, nil
}

// UpdateTenantClusterTyped updates a TenantCluster from the typed struct.
func (c *Client) UpdateTenantClusterTyped(ctx context.Context, tc *butlerv1alpha1.TenantCluster) (*butlerv1alpha1.TenantCluster, error) {
	// Convert typed to unstructured
	unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc)
	if err != nil {
		return nil, fmt.Errorf("failed to convert TenantCluster to unstructured: %w", err)
	}

	// Get existing to preserve resourceVersion
	existing, err := c.GetTenantCluster(ctx, tc.Namespace, tc.Name)
	if err != nil {
		return nil, err
	}

	existing.Object = unstructuredMap
	updated, err := c.dynamicClient.Resource(TenantClusterGVR).Namespace(tc.Namespace).Update(ctx, existing, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}

	// Convert back to typed
	result := &butlerv1alpha1.TenantCluster{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(updated.Object, result); err != nil {
		return nil, fmt.Errorf("failed to convert updated TenantCluster: %w", err)
	}

	return result, nil
}

// GetAddonDefinitionTyped retrieves an AddonDefinition and returns the typed struct.
func (c *Client) GetAddonDefinitionTyped(ctx context.Context, name string) (*butlerv1alpha1.AddonDefinition, error) {
	unstructuredAD, err := c.GetAddonDefinition(ctx, name)
	if err != nil {
		return nil, err
	}

	ad := &butlerv1alpha1.AddonDefinition{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredAD.Object, ad); err != nil {
		return nil, fmt.Errorf("failed to convert AddonDefinition to typed: %w", err)
	}

	return ad, nil
}

// GetButlerConfigTyped retrieves the singleton ButlerConfig and returns the typed struct.
func (c *Client) GetButlerConfigTyped(ctx context.Context) (*butlerv1alpha1.ButlerConfig, error) {
	unstructuredBC, err := c.dynamicClient.Resource(ButlerConfigGVR).Get(ctx, "butler", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	bc := &butlerv1alpha1.ButlerConfig{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredBC.Object, bc); err != nil {
		return nil, fmt.Errorf("failed to convert ButlerConfig to typed: %w", err)
	}

	return bc, nil
}

// UpdateButlerConfigTyped updates the ButlerConfig from the typed struct.
func (c *Client) UpdateButlerConfigTyped(ctx context.Context, bc *butlerv1alpha1.ButlerConfig) (*butlerv1alpha1.ButlerConfig, error) {
	unstructuredMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(bc)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ButlerConfig to unstructured: %w", err)
	}

	existing, err := c.dynamicClient.Resource(ButlerConfigGVR).Get(ctx, "butler", metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	existing.Object = unstructuredMap
	updated, err := c.dynamicClient.Resource(ButlerConfigGVR).Update(ctx, existing, metav1.UpdateOptions{})
	if err != nil {
		return nil, err
	}

	result := &butlerv1alpha1.ButlerConfig{}
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(updated.Object, result); err != nil {
		return nil, fmt.Errorf("failed to convert updated ButlerConfig: %w", err)
	}

	return result, nil
}

// ListTenantClustersTyped lists all TenantClusters in a namespace and returns typed structs.
func (c *Client) ListTenantClustersTyped(ctx context.Context, namespace string) (*butlerv1alpha1.TenantClusterList, error) {
	var unstructuredList *unstructured.UnstructuredList
	var err error

	if namespace == "" {
		unstructuredList, err = c.dynamicClient.Resource(TenantClusterGVR).List(ctx, metav1.ListOptions{})
	} else {
		unstructuredList, err = c.dynamicClient.Resource(TenantClusterGVR).Namespace(namespace).List(ctx, metav1.ListOptions{})
	}
	if err != nil {
		return nil, err
	}

	tcList := &butlerv1alpha1.TenantClusterList{
		Items: make([]butlerv1alpha1.TenantCluster, 0, len(unstructuredList.Items)),
	}

	for _, item := range unstructuredList.Items {
		tc := butlerv1alpha1.TenantCluster{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &tc); err != nil {
			return nil, fmt.Errorf("failed to convert TenantCluster item: %w", err)
		}
		tcList.Items = append(tcList.Items, tc)
	}

	return tcList, nil
}

// ListAddonDefinitionsTyped lists all AddonDefinitions and returns typed structs.
func (c *Client) ListAddonDefinitionsTyped(ctx context.Context) (*butlerv1alpha1.AddonDefinitionList, error) {
	unstructuredList, err := c.ListAddonDefinitions(ctx)
	if err != nil {
		return nil, err
	}

	adList := &butlerv1alpha1.AddonDefinitionList{
		Items: make([]butlerv1alpha1.AddonDefinition, 0, len(unstructuredList.Items)),
	}

	for _, item := range unstructuredList.Items {
		ad := butlerv1alpha1.AddonDefinition{}
		if err := runtime.DefaultUnstructuredConverter.FromUnstructured(item.Object, &ad); err != nil {
			return nil, fmt.Errorf("failed to convert AddonDefinition item: %w", err)
		}
		adList.Items = append(adList.Items, ad)
	}

	return adList, nil
}
