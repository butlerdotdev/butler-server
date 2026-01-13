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
	"log/slog"
	"net/http"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/k8s"
	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TeamHandler handles team management endpoints.
type TeamHandler struct {
	k8sClient    *k8s.Client
	teamResolver *auth.TeamResolver
	logger       *slog.Logger
}

// NewTeamHandler creates a new team handler.
func NewTeamHandler(k8sClient *k8s.Client, teamResolver *auth.TeamResolver, logger *slog.Logger) *TeamHandler {
	return &TeamHandler{
		k8sClient:    k8sClient,
		teamResolver: teamResolver,
		logger:       logger,
	}
}

// TeamResponse represents a team in API responses.
type TeamResponse struct {
	Name         string            `json:"name"`
	DisplayName  string            `json:"displayName"`
	Description  string            `json:"description,omitempty"`
	Users        []TeamUserAccess  `json:"users,omitempty"`
	Groups       []TeamGroupAccess `json:"groups,omitempty"`
	ClusterCount int               `json:"clusterCount"`
	Phase        string            `json:"phase"`
	CreatedAt    string            `json:"createdAt"`
}

// TeamUserAccess represents a user's access to a team.
type TeamUserAccess struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// TeamGroupAccess represents a group's access to a team.
type TeamGroupAccess struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// CreateTeamRequest is the request body for creating a team.
type CreateTeamRequest struct {
	Name        string            `json:"name"`
	DisplayName string            `json:"displayName"`
	Description string            `json:"description,omitempty"`
	Users       []TeamUserAccess  `json:"users,omitempty"`
	Groups      []TeamGroupAccess `json:"groups,omitempty"`
}

// List returns all teams the current user has access to.
// GET /api/teams
func (h *TeamHandler) List(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	// List all teams
	teams, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).List(r.Context(), metav1.ListOptions{})
	if err != nil {
		h.logger.Error("Failed to list teams", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to list teams")
		return
	}

	// Filter to teams user has access to and convert to response
	var response []TeamResponse
	for _, team := range teams.Items {
		teamName := team.GetName()

		// Check if user has access to this team
		if !user.HasTeamMembership(teamName) && !user.IsAdmin() {
			continue
		}

		response = append(response, h.teamToResponse(&team))
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"teams": response,
	})
}

// Get returns a specific team.
// GET /api/teams/{name}
func (h *TeamHandler) Get(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	teamName := chi.URLParam(r, "name")

	// Check access
	if !user.HasTeamMembership(teamName) && !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "Access denied to this team")
		return
	}

	team, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Get(r.Context(), teamName, metav1.GetOptions{})
	if err != nil {
		h.logger.Error("Failed to get team", "name", teamName, "error", err)
		writeError(w, http.StatusNotFound, "Team not found")
		return
	}

	writeJSON(w, http.StatusOK, h.teamToResponse(team))
}

// Create creates a new team.
// POST /api/teams
func (h *TeamHandler) Create(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	// Only admins can create teams
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "Admin role required to create teams")
		return
	}

	var req CreateTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Team name is required")
		return
	}

	// Build Team CRD
	team := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "Team",
			"metadata": map[string]interface{}{
				"name": req.Name,
			},
			"spec": map[string]interface{}{
				"displayName": req.DisplayName,
				"description": req.Description,
			},
		},
	}

	// Add users if specified
	if len(req.Users) > 0 {
		users := make([]interface{}, len(req.Users))
		for i, u := range req.Users {
			users[i] = map[string]interface{}{
				"name": u.Name,
				"role": u.Role,
			}
		}
		unstructured.SetNestedSlice(team.Object, users, "spec", "access", "users")
	}

	// Add groups if specified
	if len(req.Groups) > 0 {
		groups := make([]interface{}, len(req.Groups))
		for i, g := range req.Groups {
			groups[i] = map[string]interface{}{
				"name": g.Name,
				"role": g.Role,
			}
		}
		unstructured.SetNestedSlice(team.Object, groups, "spec", "access", "groups")
	}

	// Create the team
	created, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Create(r.Context(), team, metav1.CreateOptions{})
	if err != nil {
		h.logger.Error("Failed to create team", "name", req.Name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to create team")
		return
	}

	h.logger.Info("Team created", "name", req.Name, "by", user.Email)
	writeJSON(w, http.StatusCreated, h.teamToResponse(created))
}

// Update updates a team.
// PUT /api/teams/{name}
func (h *TeamHandler) Update(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	teamName := chi.URLParam(r, "name")

	// Check if user is admin of this team
	if !user.IsAdminOfTeam(teamName) && !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "Admin role required to update team")
		return
	}

	var req CreateTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get existing team
	team, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Get(r.Context(), teamName, metav1.GetOptions{})
	if err != nil {
		writeError(w, http.StatusNotFound, "Team not found")
		return
	}

	// Update fields
	if req.DisplayName != "" {
		unstructured.SetNestedField(team.Object, req.DisplayName, "spec", "displayName")
	}
	if req.Description != "" {
		unstructured.SetNestedField(team.Object, req.Description, "spec", "description")
	}

	// Update users if specified
	if len(req.Users) > 0 {
		users := make([]interface{}, len(req.Users))
		for i, u := range req.Users {
			users[i] = map[string]interface{}{
				"name": u.Name,
				"role": u.Role,
			}
		}
		unstructured.SetNestedSlice(team.Object, users, "spec", "access", "users")
	}

	// Update groups if specified
	if len(req.Groups) > 0 {
		groups := make([]interface{}, len(req.Groups))
		for i, g := range req.Groups {
			groups[i] = map[string]interface{}{
				"name": g.Name,
				"role": g.Role,
			}
		}
		unstructured.SetNestedSlice(team.Object, groups, "spec", "access", "groups")
	}

	// Apply update
	updated, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Update(r.Context(), team, metav1.UpdateOptions{})
	if err != nil {
		h.logger.Error("Failed to update team", "name", teamName, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to update team")
		return
	}

	h.logger.Info("Team updated", "name", teamName, "by", user.Email)
	writeJSON(w, http.StatusOK, h.teamToResponse(updated))
}

// Delete deletes a team.
// DELETE /api/teams/{name}
func (h *TeamHandler) Delete(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	teamName := chi.URLParam(r, "name")

	// Only admins can delete teams
	if !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "Admin role required to delete teams")
		return
	}

	err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Delete(r.Context(), teamName, metav1.DeleteOptions{})
	if err != nil {
		h.logger.Error("Failed to delete team", "name", teamName, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to delete team")
		return
	}

	h.logger.Info("Team deleted", "name", teamName, "by", user.Email)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ListClusters returns clusters belonging to a team.
// GET /api/teams/{name}/clusters
func (h *TeamHandler) ListClusters(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	teamName := chi.URLParam(r, "name")

	// Check access
	if !user.HasTeamMembership(teamName) && !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "Access denied to this team")
		return
	}

	// Get clusters with team label
	labelSelector := "butler.butlerlabs.dev/team=" + teamName
	clusters, err := h.k8sClient.Dynamic().Resource(k8s.TenantClusterGVR).List(r.Context(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		h.logger.Error("Failed to list team clusters", "team", teamName, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to list clusters")
		return
	}

	// Convert to response format
	var response []map[string]interface{}
	for _, cluster := range clusters.Items {
		name := cluster.GetName()
		namespace := cluster.GetNamespace()

		phase, _, _ := unstructured.NestedString(cluster.Object, "status", "phase")
		k8sVersion, _, _ := unstructured.NestedString(cluster.Object, "spec", "kubernetesVersion")

		response = append(response, map[string]interface{}{
			"name":              name,
			"namespace":         namespace,
			"phase":             phase,
			"kubernetesVersion": k8sVersion,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"clusters": response,
	})
}

// teamToResponse converts a Team CRD to API response format.
func (h *TeamHandler) teamToResponse(team *unstructured.Unstructured) TeamResponse {
	displayName, _, _ := unstructured.NestedString(team.Object, "spec", "displayName")
	if displayName == "" {
		displayName = team.GetName()
	}

	description, _, _ := unstructured.NestedString(team.Object, "spec", "description")
	phase, _, _ := unstructured.NestedString(team.Object, "status", "phase")
	if phase == "" {
		phase = "Ready"
	}

	clusterCount, _, _ := unstructured.NestedInt64(team.Object, "status", "clusterCount")

	// Extract users
	var users []TeamUserAccess
	usersRaw, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users")
	if found {
		for _, u := range usersRaw {
			if userMap, ok := u.(map[string]interface{}); ok {
				name, _, _ := unstructured.NestedString(userMap, "name")
				role, _, _ := unstructured.NestedString(userMap, "role")
				if role == "" {
					role = "viewer"
				}
				users = append(users, TeamUserAccess{Name: name, Role: role})
			}
		}
	}

	// Extract groups
	var groups []TeamGroupAccess
	groupsRaw, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "groups")
	if found {
		for _, g := range groupsRaw {
			if groupMap, ok := g.(map[string]interface{}); ok {
				name, _, _ := unstructured.NestedString(groupMap, "name")
				role, _, _ := unstructured.NestedString(groupMap, "role")
				if role == "" {
					role = "viewer"
				}
				groups = append(groups, TeamGroupAccess{Name: name, Role: role})
			}
		}
	}

	return TeamResponse{
		Name:         team.GetName(),
		DisplayName:  displayName,
		Description:  description,
		Users:        users,
		Groups:       groups,
		ClusterCount: int(clusterCount),
		Phase:        phase,
		CreatedAt:    team.GetCreationTimestamp().Format("2006-01-02T15:04:05Z"),
	}
}
