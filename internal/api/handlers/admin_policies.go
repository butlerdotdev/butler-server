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

	"github.com/go-chi/chi/v5"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/butlerdotdev/butler-server/internal/k8s"
)

// AdminPoliciesHandler serves CRUD endpoints for ClusterCreationPolicy
// resources. Platform-admin only per ADR-018 Decision section 3 (RBAC
// scope reasoning).
//
// Implementation is a thin dynamic-client wrapper around the cluster's
// ClusterCreationPolicy resources. The CRD admission webhook in
// butler-controller validates structure on Create and Update; webhook
// denials are unwrapped via writeWebhookError into a structured 403
// that butler-console renders inline against the offending field.
type AdminPoliciesHandler struct {
	k8sClient *k8s.Client
}

// NewAdminPoliciesHandler creates an admin policies handler.
func NewAdminPoliciesHandler(k8sClient *k8s.Client) *AdminPoliciesHandler {
	return &AdminPoliciesHandler{k8sClient: k8sClient}
}

// PolicyListResponse wraps the list endpoint return shape.
type PolicyListResponse struct {
	Policies []map[string]interface{} `json:"policies"`
	Count    int                      `json:"count"`
}

// List returns all ClusterCreationPolicy resources.
// GET /admin/policies
func (h *AdminPoliciesHandler) List(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	list, err := h.k8sClient.Dynamic().Resource(k8s.ClusterCreationPolicyGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to list policies: %v", err))
		return
	}
	out := make([]map[string]interface{}, 0, len(list.Items))
	for _, item := range list.Items {
		out = append(out, item.Object)
	}
	writeJSON(w, http.StatusOK, PolicyListResponse{Policies: out, Count: len(out)})
}

// Get returns a single ClusterCreationPolicy by name.
// GET /admin/policies/{name}
func (h *AdminPoliciesHandler) Get(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	ctx := r.Context()
	got, err := h.k8sClient.Dynamic().Resource(k8s.ClusterCreationPolicyGVR).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("policy %q not found", name))
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to get policy: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, got.Object)
}

// Create creates a new ClusterCreationPolicy. The request body is the
// full unstructured policy object; the admission webhook validates
// structure. Webhook denials are surfaced via writeWebhookError as a
// structured 403 the console can render inline.
// POST /admin/policies
func (h *AdminPoliciesHandler) Create(w http.ResponseWriter, r *http.Request) {
	obj, err := decodePolicyBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Force the resource kind and apiVersion so a partial body still
	// produces a valid CR. The console can omit these; the server
	// stamps the canonical values.
	obj.SetAPIVersion("butler.butlerlabs.dev/v1alpha1")
	obj.SetKind("ClusterCreationPolicy")

	ctx := r.Context()
	created, err := h.k8sClient.Dynamic().Resource(k8s.ClusterCreationPolicyGVR).Create(ctx, obj, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			writeError(w, http.StatusConflict, fmt.Sprintf("policy %q already exists", obj.GetName()))
			return
		}
		if writeWebhookError(w, err) {
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create policy: %v", err))
		return
	}
	writeJSON(w, http.StatusCreated, created.Object)
}

// Update replaces an existing ClusterCreationPolicy. Preserves
// metadata.resourceVersion for optimistic concurrency: the console
// posts the resourceVersion it last fetched so a concurrent edit
// produces a 409 rather than silently overwriting.
// PUT /admin/policies/{name}
func (h *AdminPoliciesHandler) Update(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	obj, err := decodePolicyBody(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if obj.GetName() != "" && obj.GetName() != name {
		writeError(w, http.StatusBadRequest, "request body name does not match URL name")
		return
	}
	obj.SetName(name)
	obj.SetAPIVersion("butler.butlerlabs.dev/v1alpha1")
	obj.SetKind("ClusterCreationPolicy")

	ctx := r.Context()
	updated, err := h.k8sClient.Dynamic().Resource(k8s.ClusterCreationPolicyGVR).Update(ctx, obj, metav1.UpdateOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("policy %q not found", name))
			return
		}
		if apierrors.IsConflict(err) {
			writeError(w, http.StatusConflict, "policy was modified by another caller; reload and retry")
			return
		}
		if writeWebhookError(w, err) {
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to update policy: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, updated.Object)
}

// Delete removes a ClusterCreationPolicy.
// DELETE /admin/policies/{name}
func (h *AdminPoliciesHandler) Delete(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	if name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	ctx := r.Context()
	err := h.k8sClient.Dynamic().Resource(k8s.ClusterCreationPolicyGVR).Delete(ctx, name, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			writeError(w, http.StatusNotFound, fmt.Sprintf("policy %q not found", name))
			return
		}
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to delete policy: %v", err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// decodePolicyBody unmarshals the request body into an
// unstructured.Unstructured. Returns a friendly error on parse
// failure or empty body.
func decodePolicyBody(r *http.Request) (*unstructured.Unstructured, error) {
	var raw map[string]interface{}
	if err := json.NewDecoder(r.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("invalid request body: %w", err)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("request body is empty")
	}
	return &unstructured.Unstructured{Object: raw}, nil
}
