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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/butlerdotdev/butler-server/internal/auth"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// EnvironmentLimits mirrors the ADR-009 EnvironmentLimits shape.
// Pointer fields so "not specified" round-trips without forcing a cap
// of 0 on the CRD.
type EnvironmentLimits struct {
	MaxClusters          *int32 `json:"maxClusters,omitempty"`
	MaxClustersPerMember *int32 `json:"maxClustersPerMember,omitempty"`
}

// EnvironmentRequest is the POST/PUT body for env create/update.
// Omitted limits fields leave the env uncapped within the Team ceiling.
type EnvironmentRequest struct {
	Name   string             `json:"name"`
	Limits *EnvironmentLimits `json:"limits,omitempty"`
}

// AddEnvironment appends an environment to Team.spec.environments[].
// The Team admission webhook (ADR-009) gates spec.environments[].limits
// mutations to team admins; spec.resourceLimits mutations require a
// platform admin. Both gates key on UserInfo.Username, so every write
// path here routes through the impersonating client.
// POST /api/teams/{name}/environments
func (h *TeamHandler) AddEnvironment(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	user := auth.UserFromContext(r.Context())

	var req EnvironmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Environment name is required")
		return
	}

	team, err := h.getTeam(r.Context(), name)
	if err != nil {
		h.writeTeamReadError(w, name, err)
		return
	}

	envs, _, _ := unstructured.NestedSlice(team.Object, "spec", "environments")
	for _, e := range envs {
		em, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		existing, _, _ := unstructured.NestedString(em, "name")
		if strings.EqualFold(existing, req.Name) {
			writeError(w, http.StatusConflict, fmt.Sprintf("Environment %q already exists", req.Name))
			return
		}
	}

	envs = append(envs, envToUnstructured(&req))
	if err := unstructured.SetNestedSlice(team.Object, envs, "spec", "environments"); err != nil {
		h.logger.Error("Failed to set team environments", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to add environment")
		return
	}

	if err := h.updateTeamAsUser(r.Context(), team, user); err != nil {
		if writeWebhookError(w, err) {
			h.logger.Warn("Environment add denied by admission webhook", "team", name, "env", req.Name, "user", user.Email, "error", err)
			return
		}
		h.logger.Error("Failed to add environment", "team", name, "env", req.Name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to add environment")
		return
	}

	h.logger.Info("Environment added", "team", name, "env", req.Name)
	writeJSON(w, http.StatusCreated, req)
}

// UpdateEnvironment replaces the entry whose name matches the URL
// parameter. Name is immutable at the CRD layer (listMapKey=name);
// a rename would delete-and-recreate.
// PUT /api/teams/{name}/environments/{env}
func (h *TeamHandler) UpdateEnvironment(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	envName := chi.URLParam(r, "env")
	user := auth.UserFromContext(r.Context())

	var req EnvironmentRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.Name != "" && !strings.EqualFold(req.Name, envName) {
		writeError(w, http.StatusBadRequest, "Environment name is immutable; delete and recreate to rename")
		return
	}
	req.Name = envName

	team, err := h.getTeam(r.Context(), name)
	if err != nil {
		h.writeTeamReadError(w, name, err)
		return
	}

	envs, _, _ := unstructured.NestedSlice(team.Object, "spec", "environments")
	updated := false
	for i, e := range envs {
		em, ok := e.(map[string]interface{})
		if !ok {
			continue
		}
		existing, _, _ := unstructured.NestedString(em, "name")
		if strings.EqualFold(existing, envName) {
			envs[i] = envToUnstructured(&req)
			updated = true
			break
		}
	}
	if !updated {
		writeError(w, http.StatusNotFound, "Environment not found")
		return
	}

	if err := unstructured.SetNestedSlice(team.Object, envs, "spec", "environments"); err != nil {
		h.logger.Error("Failed to set team environments", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to update environment")
		return
	}

	if err := h.updateTeamAsUser(r.Context(), team, user); err != nil {
		if writeWebhookError(w, err) {
			h.logger.Warn("Environment update denied by admission webhook", "team", name, "env", envName, "user", user.Email, "error", err)
			return
		}
		h.logger.Error("Failed to update environment", "team", name, "env", envName, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to update environment")
		return
	}

	h.logger.Info("Environment updated", "team", name, "env", envName)
	writeJSON(w, http.StatusOK, req)
}

// RemoveEnvironment drops the named environment from
// Team.spec.environments[]. The webhook enforces label immutability on
// existing TenantClusters independently; removing an env that still
// has labeled clusters is allowed (they are grandfathered against the
// team total per ADR-009 phase-2 migration).
// DELETE /api/teams/{name}/environments/{env}
func (h *TeamHandler) RemoveEnvironment(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	envName := chi.URLParam(r, "env")
	user := auth.UserFromContext(r.Context())

	team, err := h.getTeam(r.Context(), name)
	if err != nil {
		h.writeTeamReadError(w, name, err)
		return
	}

	envs, _, _ := unstructured.NestedSlice(team.Object, "spec", "environments")
	filtered := make([]interface{}, 0, len(envs))
	removed := false
	for _, e := range envs {
		em, ok := e.(map[string]interface{})
		if !ok {
			filtered = append(filtered, e)
			continue
		}
		existing, _, _ := unstructured.NestedString(em, "name")
		if strings.EqualFold(existing, envName) {
			removed = true
			continue
		}
		filtered = append(filtered, e)
	}
	if !removed {
		writeError(w, http.StatusNotFound, "Environment not found")
		return
	}

	if len(filtered) == 0 {
		unstructured.RemoveNestedField(team.Object, "spec", "environments")
	} else if err := unstructured.SetNestedSlice(team.Object, filtered, "spec", "environments"); err != nil {
		h.logger.Error("Failed to set team environments", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to remove environment")
		return
	}

	if err := h.updateTeamAsUser(r.Context(), team, user); err != nil {
		if writeWebhookError(w, err) {
			h.logger.Warn("Environment delete denied by admission webhook", "team", name, "env", envName, "user", user.Email, "error", err)
			return
		}
		h.logger.Error("Failed to delete environment", "team", name, "env", envName, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to delete environment")
		return
	}

	h.logger.Info("Environment deleted", "team", name, "env", envName)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// getTeam fetches the Team via the shared server-SA client (no webhook
// fires on reads, so impersonation is unnecessary here).
func (h *TeamHandler) getTeam(ctx context.Context, name string) (*unstructured.Unstructured, error) {
	return h.k8sClient.Dynamic().Resource(auth.TeamGVR).Get(ctx, name, metav1.GetOptions{})
}

func (h *TeamHandler) writeTeamReadError(w http.ResponseWriter, name string, err error) {
	if strings.Contains(err.Error(), "not found") {
		writeError(w, http.StatusNotFound, "Team not found")
		return
	}
	h.logger.Error("Failed to get team", "name", name, "error", err)
	writeError(w, http.StatusInternalServerError, "Failed to get team")
}

// updateTeamAsUser issues the Team Update with the caller's impersonated
// identity so the admission webhook can enforce the ADR-009 mutation
// split.
func (h *TeamHandler) updateTeamAsUser(ctx context.Context, team *unstructured.Unstructured, user *auth.UserSession) error {
	if user == nil || user.Email == "" {
		return fmt.Errorf("missing session identity for impersonation")
	}
	impClient, err := h.k8sClient.AsUser(user.Email)
	if err != nil {
		return fmt.Errorf("build impersonating client: %w", err)
	}
	_, err = impClient.Dynamic().Resource(auth.TeamGVR).Update(ctx, team, metav1.UpdateOptions{})
	return err
}

// envToUnstructured renders an EnvironmentRequest into the
// map[string]interface{} shape Team.spec.environments[] expects.
// Limits fields are only emitted when set so unset fields do not pin
// a cap of zero on the CRD.
func envToUnstructured(req *EnvironmentRequest) map[string]interface{} {
	env := map[string]interface{}{
		"name": req.Name,
	}
	if req.Limits != nil {
		limits := map[string]interface{}{}
		if req.Limits.MaxClusters != nil {
			limits["maxClusters"] = int64(*req.Limits.MaxClusters)
		}
		if req.Limits.MaxClustersPerMember != nil {
			limits["maxClustersPerMember"] = int64(*req.Limits.MaxClustersPerMember)
		}
		if len(limits) > 0 {
			env["limits"] = limits
		}
	}
	return env
}
