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
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// NetworksHandler handles network pool and IP allocation endpoints.
type NetworksHandler struct {
	k8sClient *k8s.Client
	config    *config.Config
}

// NewNetworksHandler creates a new networks handler.
func NewNetworksHandler(k8sClient *k8s.Client, cfg *config.Config) *NetworksHandler {
	return &NetworksHandler{
		k8sClient: k8sClient,
		config:    cfg,
	}
}

// CreateNetworkPoolRequest represents a network pool creation request.
type CreateNetworkPoolRequest struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	CIDR      string `json:"cidr"`
	Reserved  []struct {
		CIDR        string `json:"cidr"`
		Description string `json:"description,omitempty"`
	} `json:"reserved,omitempty"`
	TenantAllocation *struct {
		Start    string `json:"start,omitempty"`
		End      string `json:"end,omitempty"`
		Defaults *struct {
			NodesPerTenant  *int32 `json:"nodesPerTenant,omitempty"`
			LBPoolPerTenant *int32 `json:"lbPoolPerTenant,omitempty"`
		} `json:"defaults,omitempty"`
	} `json:"tenantAllocation,omitempty"`
}

// ListNetworkPools returns all NetworkPool resources.
func (h *NetworksHandler) ListNetworkPools(w http.ResponseWriter, r *http.Request) {
	pools, err := h.k8sClient.Dynamic().Resource(k8s.NetworkPoolGVR).List(r.Context(), metav1.ListOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list network pools: %v", err))
		return
	}

	response := map[string]interface{}{
		"pools": make([]map[string]interface{}, 0, len(pools.Items)),
	}
	for _, pool := range pools.Items {
		response["pools"] = append(response["pools"].([]map[string]interface{}), pool.Object)
	}

	writeJSON(w, http.StatusOK, response)
}

// GetNetworkPool returns a specific NetworkPool.
func (h *NetworksHandler) GetNetworkPool(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	pool, err := h.k8sClient.Dynamic().Resource(k8s.NetworkPoolGVR).Namespace(namespace).Get(r.Context(), name, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("network pool not found: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, pool.Object)
}

// CreateNetworkPool creates a new NetworkPool.
func (h *NetworksHandler) CreateNetworkPool(w http.ResponseWriter, r *http.Request) {
	var req CreateNetworkPoolRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.CIDR == "" {
		writeError(w, http.StatusBadRequest, "cidr is required")
		return
	}
	if req.Namespace == "" {
		req.Namespace = "butler-system"
	}

	spec := map[string]interface{}{
		"cidr": req.CIDR,
	}

	if len(req.Reserved) > 0 {
		reserved := make([]interface{}, 0, len(req.Reserved))
		for _, r := range req.Reserved {
			entry := map[string]interface{}{
				"cidr": r.CIDR,
			}
			if r.Description != "" {
				entry["description"] = r.Description
			}
			reserved = append(reserved, entry)
		}
		spec["reserved"] = reserved
	}

	if req.TenantAllocation != nil {
		ta := map[string]interface{}{}
		if req.TenantAllocation.Start != "" {
			ta["start"] = req.TenantAllocation.Start
		}
		if req.TenantAllocation.End != "" {
			ta["end"] = req.TenantAllocation.End
		}
		if req.TenantAllocation.Defaults != nil {
			defaults := map[string]interface{}{}
			if req.TenantAllocation.Defaults.NodesPerTenant != nil {
				defaults["nodesPerTenant"] = *req.TenantAllocation.Defaults.NodesPerTenant
			}
			if req.TenantAllocation.Defaults.LBPoolPerTenant != nil {
				defaults["lbPoolPerTenant"] = *req.TenantAllocation.Defaults.LBPoolPerTenant
			}
			if len(defaults) > 0 {
				ta["defaults"] = defaults
			}
		}
		if len(ta) > 0 {
			spec["tenantAllocation"] = ta
		}
	}

	pool := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "NetworkPool",
			"metadata": map[string]interface{}{
				"name":      req.Name,
				"namespace": req.Namespace,
			},
			"spec": spec,
		},
	}

	created, err := h.k8sClient.Dynamic().Resource(k8s.NetworkPoolGVR).Namespace(req.Namespace).Create(
		r.Context(), pool, metav1.CreateOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create network pool: %v", err))
		return
	}

	writeJSON(w, http.StatusCreated, created.Object)
}

// DeleteNetworkPool deletes a NetworkPool.
func (h *NetworksHandler) DeleteNetworkPool(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	err := h.k8sClient.Dynamic().Resource(k8s.NetworkPoolGVR).Namespace(namespace).Delete(
		r.Context(), name, metav1.DeleteOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete network pool: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "network pool deleted"})
}

// ListAllocations returns IP allocations for a specific network pool.
func (h *NetworksHandler) ListAllocations(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	labelSelector := fmt.Sprintf("butler.butlerlabs.dev/network-pool=%s", name)
	allocations, err := h.k8sClient.Dynamic().Resource(k8s.IPAllocationGVR).Namespace(namespace).List(r.Context(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list allocations: %v", err))
		return
	}

	response := map[string]interface{}{
		"allocations": make([]map[string]interface{}, 0, len(allocations.Items)),
	}
	for _, alloc := range allocations.Items {
		response["allocations"] = append(response["allocations"].([]map[string]interface{}), alloc.Object)
	}

	writeJSON(w, http.StatusOK, response)
}

// ListAllAllocations returns all IP allocations across all namespaces.
func (h *NetworksHandler) ListAllAllocations(w http.ResponseWriter, r *http.Request) {
	allocations, err := h.k8sClient.Dynamic().Resource(k8s.IPAllocationGVR).List(r.Context(), metav1.ListOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list allocations: %v", err))
		return
	}

	response := map[string]interface{}{
		"allocations": make([]map[string]interface{}, 0, len(allocations.Items)),
	}
	for _, alloc := range allocations.Items {
		response["allocations"] = append(response["allocations"].([]map[string]interface{}), alloc.Object)
	}

	writeJSON(w, http.StatusOK, response)
}

// ReleaseAllocation deletes an IP allocation.
func (h *NetworksHandler) ReleaseAllocation(w http.ResponseWriter, r *http.Request) {
	namespace := chi.URLParam(r, "namespace")
	name := chi.URLParam(r, "name")

	err := h.k8sClient.Dynamic().Resource(k8s.IPAllocationGVR).Namespace(namespace).Delete(
		r.Context(), name, metav1.DeleteOptions{},
	)
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to release allocation: %v", err))
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"message": "allocation released"})
}
