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
	"net/url"
	"strings"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// TeamHandler handles team-related endpoints.
type TeamHandler struct {
	k8sClient    *k8s.Client
	teamResolver *auth.TeamResolver
	logger       *slog.Logger
}

// NewTeamHandler creates a new teams handler.
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
	DisplayName  string            `json:"displayName,omitempty"`
	Description  string            `json:"description,omitempty"`
	Namespace    string            `json:"namespace,omitempty"`
	Phase        string            `json:"phase"`
	ClusterCount int               `json:"clusterCount"`
	MemberCount  int               `json:"memberCount"`
	Labels       map[string]string `json:"labels,omitempty"`
	CreatedAt    string            `json:"createdAt,omitempty"`
}

// TeamMemberResponse represents a team member in API responses.
type TeamMemberResponse struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
	Role  string `json:"role"`
}

// List returns all teams.
// GET /api/teams
func (h *TeamHandler) List(w http.ResponseWriter, r *http.Request) {
	teams, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).List(r.Context(), metav1.ListOptions{})
	if err != nil {
		h.logger.Error("Failed to list teams", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to list teams")
		return
	}

	// Get all clusters to count per team
	allClusters, err := h.k8sClient.Dynamic().Resource(k8s.TenantClusterGVR).List(r.Context(), metav1.ListOptions{})
	if err != nil {
		h.logger.Warn("Failed to list clusters for counting", "error", err)
		// Continue without cluster counts
	}

	// Build cluster count map by team using spec.teamRef.name
	clusterCountByTeam := make(map[string]int)
	if allClusters != nil {
		for _, cluster := range allClusters.Items {
			// Check spec.teamRef.name for team association
			teamRefName, found, _ := unstructured.NestedString(cluster.Object, "spec", "teamRef", "name")
			if found && teamRefName != "" {
				clusterCountByTeam[teamRefName]++
			}
		}
	}

	response := make([]TeamResponse, 0, len(teams.Items))
	for _, team := range teams.Items {
		displayName, _, _ := unstructured.NestedString(team.Object, "spec", "displayName")
		description, _, _ := unstructured.NestedString(team.Object, "spec", "description")
		namespace, _, _ := unstructured.NestedString(team.Object, "status", "namespace")
		phase, _, _ := unstructured.NestedString(team.Object, "status", "phase")

		// Fallback namespace to team name if not set
		if namespace == "" {
			namespace = team.GetName()
		}

		// Count members from spec.access.users
		memberCount := 0
		if users, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users"); found {
			memberCount = len(users)
		}

		if displayName == "" {
			displayName = team.GetName()
		}

		// Default phase if not set
		if phase == "" {
			phase = "Ready"
		}

		// Get cluster count from map
		clusterCount := clusterCountByTeam[team.GetName()]

		response = append(response, TeamResponse{
			Name:         team.GetName(),
			DisplayName:  displayName,
			Description:  description,
			Namespace:    namespace,
			Phase:        phase,
			ClusterCount: clusterCount,
			MemberCount:  memberCount,
			Labels:       team.GetLabels(),
			CreatedAt:    team.GetCreationTimestamp().Format("2006-01-02T15:04:05Z"),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"teams": response,
	})
}

// Get returns a specific team.
// GET /api/teams/{name}
func (h *TeamHandler) Get(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	team, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Get(r.Context(), name, metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Team not found")
			return
		}
		h.logger.Error("Failed to get team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get team")
		return
	}

	displayName, _, _ := unstructured.NestedString(team.Object, "spec", "displayName")
	description, _, _ := unstructured.NestedString(team.Object, "spec", "description")
	namespace, _, _ := unstructured.NestedString(team.Object, "status", "namespace")
	phase, _, _ := unstructured.NestedString(team.Object, "status", "phase")

	// Fallback namespace to team name if not set
	if namespace == "" {
		namespace = team.GetName()
	}

	// Count members from spec.access.users
	memberCount := 0
	if users, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users"); found {
		memberCount = len(users)
	}

	// Count clusters by checking spec.teamRef.name
	clusterCount := 0
	allClusters, err := h.k8sClient.Dynamic().Resource(k8s.TenantClusterGVR).List(r.Context(), metav1.ListOptions{})
	if err == nil && allClusters != nil {
		for _, cluster := range allClusters.Items {
			teamRefName, found, _ := unstructured.NestedString(cluster.Object, "spec", "teamRef", "name")
			if found && teamRefName == name {
				clusterCount++
			}
		}
	}

	if displayName == "" {
		displayName = team.GetName()
	}

	// Default phase if not set
	if phase == "" {
		phase = "Ready"
	}

	writeJSON(w, http.StatusOK, TeamResponse{
		Name:         team.GetName(),
		DisplayName:  displayName,
		Description:  description,
		Namespace:    namespace,
		Phase:        phase,
		ClusterCount: clusterCount,
		MemberCount:  memberCount,
		Labels:       team.GetLabels(),
		CreatedAt:    team.GetCreationTimestamp().Format("2006-01-02T15:04:05Z"),
	})
}

// CreateTeamRequest represents the request body for creating a team.
type CreateTeamRequest struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Description string `json:"description,omitempty"`
	Namespace   string `json:"namespace,omitempty"`
}

// Create creates a new team.
// POST /api/teams
func (h *TeamHandler) Create(w http.ResponseWriter, r *http.Request) {
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

	if req.Namespace != "" {
		if err := unstructured.SetNestedField(team.Object, req.Namespace, "spec", "namespace"); err != nil {
			h.logger.Error("Failed to set namespace", "error", err)
		}
	}

	created, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Create(r.Context(), team, metav1.CreateOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, "Team already exists")
			return
		}
		h.logger.Error("Failed to create team", "name", req.Name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to create team")
		return
	}

	h.logger.Info("Team created", "name", req.Name)

	displayName, _, _ := unstructured.NestedString(created.Object, "spec", "displayName")
	if displayName == "" {
		displayName = created.GetName()
	}

	writeJSON(w, http.StatusCreated, TeamResponse{
		Name:        created.GetName(),
		DisplayName: displayName,
		CreatedAt:   created.GetCreationTimestamp().Format("2006-01-02T15:04:05Z"),
	})
}

// Update updates a team.
// PUT /api/teams/{name}
func (h *TeamHandler) Update(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var req CreateTeamRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Get existing team
	team, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Get(r.Context(), name, metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Team not found")
			return
		}
		h.logger.Error("Failed to get team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get team")
		return
	}

	// Update fields
	if req.DisplayName != "" {
		unstructured.SetNestedField(team.Object, req.DisplayName, "spec", "displayName")
	}
	if req.Description != "" {
		unstructured.SetNestedField(team.Object, req.Description, "spec", "description")
	}

	updated, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Update(r.Context(), team, metav1.UpdateOptions{})
	if err != nil {
		h.logger.Error("Failed to update team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to update team")
		return
	}

	h.logger.Info("Team updated", "name", name)

	displayName, _, _ := unstructured.NestedString(updated.Object, "spec", "displayName")
	if displayName == "" {
		displayName = updated.GetName()
	}

	writeJSON(w, http.StatusOK, TeamResponse{
		Name:        updated.GetName(),
		DisplayName: displayName,
	})
}

// Delete deletes a team.
// DELETE /api/teams/{name}
func (h *TeamHandler) Delete(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Delete(r.Context(), name, metav1.DeleteOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Team not found")
			return
		}
		h.logger.Error("Failed to delete team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to delete team")
		return
	}

	h.logger.Info("Team deleted", "name", name)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// ListClusters returns clusters owned by a team.
// GET /api/teams/{name}/clusters
func (h *TeamHandler) ListClusters(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	// Get team's cluster selector
	selector, err := h.teamResolver.GetTeamClusterSelector(r.Context(), name)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Team not found")
			return
		}
		h.logger.Error("Failed to get team cluster selector", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get team")
		return
	}

	// Build label selector string
	var labelParts []string
	for k, v := range selector {
		labelParts = append(labelParts, k+"="+v)
	}
	labelSelector := strings.Join(labelParts, ",")

	// List clusters with label selector
	clusters, err := h.k8sClient.Dynamic().Resource(k8s.TenantClusterGVR).List(r.Context(), metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		h.logger.Error("Failed to list team clusters", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to list clusters")
		return
	}

	response := make([]map[string]interface{}, 0, len(clusters.Items))
	for _, cluster := range clusters.Items {
		response = append(response, cluster.Object)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"clusters": response,
	})
}

// ListMembers returns members of a team.
// GET /api/teams/{name}/members
func (h *TeamHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	// Check if requesting user has access to this team
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	// User must be a member of the team to view members (or be admin)
	if !user.HasTeamMembership(name) && !user.IsAdmin() {
		writeError(w, http.StatusForbidden, "Access denied to team")
		return
	}

	// Get the team CRD
	team, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Get(r.Context(), name, metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Team not found")
			return
		}
		h.logger.Error("Failed to get team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get team")
		return
	}

	// Extract spec.access.users[]
	users, found, err := unstructured.NestedSlice(team.Object, "spec", "access", "users")
	if err != nil {
		h.logger.Error("Failed to get team users", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get team members")
		return
	}

	members := make([]TeamMemberResponse, 0)
	if found {
		for _, u := range users {
			userMap, ok := u.(map[string]interface{})
			if !ok {
				continue
			}

			email, _, _ := unstructured.NestedString(userMap, "name")
			role, _, _ := unstructured.NestedString(userMap, "role")
			displayName, _, _ := unstructured.NestedString(userMap, "displayName")

			if email == "" {
				continue
			}
			if role == "" {
				role = auth.RoleViewer
			}

			members = append(members, TeamMemberResponse{
				Email: email,
				Name:  displayName,
				Role:  role,
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"members": members,
	})
}

// AddMemberRequest represents the request body for adding a team member.
type AddMemberRequest struct {
	Email string `json:"email"`
	Role  string `json:"role,omitempty"`
}

// AddMember adds a member to a team.
// POST /api/admin/teams/{name}/members
func (h *TeamHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var req AddMemberRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "Email is required")
		return
	}

	if req.Role == "" {
		req.Role = auth.RoleViewer
	}

	// Validate role
	if req.Role != auth.RoleAdmin && req.Role != auth.RoleOperator && req.Role != auth.RoleViewer {
		writeError(w, http.StatusBadRequest, "Invalid role. Must be admin, operator, or viewer")
		return
	}

	// Get existing team
	team, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Get(r.Context(), name, metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Team not found")
			return
		}
		h.logger.Error("Failed to get team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get team")
		return
	}

	// Get existing users
	users, _, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users")
	if users == nil {
		users = []interface{}{}
	}

	// Check if user already exists
	emailLower := strings.ToLower(req.Email)
	for _, u := range users {
		userMap, ok := u.(map[string]interface{})
		if !ok {
			continue
		}
		existingEmail, _, _ := unstructured.NestedString(userMap, "name")
		if strings.EqualFold(existingEmail, emailLower) {
			writeError(w, http.StatusConflict, "User is already a member of this team")
			return
		}
	}

	// Add new user
	newUser := map[string]interface{}{
		"name": emailLower,
		"role": req.Role,
	}
	users = append(users, newUser)

	// Ensure spec.access exists
	access, _, _ := unstructured.NestedMap(team.Object, "spec", "access")
	if access == nil {
		unstructured.SetNestedMap(team.Object, map[string]interface{}{}, "spec", "access")
	}

	// Update team
	if err := unstructured.SetNestedSlice(team.Object, users, "spec", "access", "users"); err != nil {
		h.logger.Error("Failed to update team users", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to add member")
		return
	}

	_, err = h.k8sClient.Dynamic().Resource(auth.TeamGVR).Update(r.Context(), team, metav1.UpdateOptions{})
	if err != nil {
		h.logger.Error("Failed to update team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to add member")
		return
	}

	h.logger.Info("Member added to team", "team", name, "email", req.Email, "role", req.Role)
	writeJSON(w, http.StatusCreated, map[string]string{
		"status": "added",
		"email":  req.Email,
		"role":   req.Role,
	})
}

// UpdateMemberRoleRequest represents the request body for updating a member's role.
type UpdateMemberRoleRequest struct {
	Role string `json:"role"`
}

// UpdateMemberRole updates a team member's role.
// PATCH /api/admin/teams/{name}/members/{email}
func (h *TeamHandler) UpdateMemberRole(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	email := chi.URLParam(r, "email")

	// URL decode the email
	decodedEmail, err := url.QueryUnescape(email)
	if err != nil {
		decodedEmail = email
	}

	var req UpdateMemberRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Role == "" {
		writeError(w, http.StatusBadRequest, "Role is required")
		return
	}

	// Validate role
	if req.Role != auth.RoleAdmin && req.Role != auth.RoleOperator && req.Role != auth.RoleViewer {
		writeError(w, http.StatusBadRequest, "Invalid role. Must be admin, operator, or viewer")
		return
	}

	// Get existing team
	team, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Get(r.Context(), name, metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Team not found")
			return
		}
		h.logger.Error("Failed to get team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get team")
		return
	}

	// Get existing users
	users, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users")
	if !found || users == nil {
		writeError(w, http.StatusNotFound, "Member not found")
		return
	}

	// Find and update user
	memberFound := false
	for i, u := range users {
		userMap, ok := u.(map[string]interface{})
		if !ok {
			continue
		}
		existingEmail, _, _ := unstructured.NestedString(userMap, "name")
		if strings.EqualFold(existingEmail, decodedEmail) {
			userMap["role"] = req.Role
			users[i] = userMap
			memberFound = true
			break
		}
	}

	if !memberFound {
		writeError(w, http.StatusNotFound, "Member not found")
		return
	}

	// Update team
	if err := unstructured.SetNestedSlice(team.Object, users, "spec", "access", "users"); err != nil {
		h.logger.Error("Failed to update team users", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to update member role")
		return
	}

	_, err = h.k8sClient.Dynamic().Resource(auth.TeamGVR).Update(r.Context(), team, metav1.UpdateOptions{})
	if err != nil {
		h.logger.Error("Failed to update team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to update member role")
		return
	}

	h.logger.Info("Member role updated", "team", name, "email", decodedEmail, "role", req.Role)
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "updated",
		"email":  decodedEmail,
		"role":   req.Role,
	})
}

// RemoveMember removes a member from a team.
// DELETE /api/admin/teams/{name}/members/{email}
func (h *TeamHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	email := chi.URLParam(r, "email")

	// URL decode the email
	decodedEmail, err := url.QueryUnescape(email)
	if err != nil {
		decodedEmail = email
	}

	// Get existing team
	team, err := h.k8sClient.Dynamic().Resource(auth.TeamGVR).Get(r.Context(), name, metav1.GetOptions{})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			writeError(w, http.StatusNotFound, "Team not found")
			return
		}
		h.logger.Error("Failed to get team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get team")
		return
	}

	// Get existing users
	users, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users")
	if !found || users == nil {
		writeError(w, http.StatusNotFound, "Member not found")
		return
	}

	// Find and remove user
	memberFound := false
	newUsers := make([]interface{}, 0, len(users)-1)
	for _, u := range users {
		userMap, ok := u.(map[string]interface{})
		if !ok {
			newUsers = append(newUsers, u)
			continue
		}
		existingEmail, _, _ := unstructured.NestedString(userMap, "name")
		if strings.EqualFold(existingEmail, decodedEmail) {
			memberFound = true
			continue // Skip this user (remove)
		}
		newUsers = append(newUsers, u)
	}

	if !memberFound {
		writeError(w, http.StatusNotFound, "Member not found")
		return
	}

	// Update team
	if err := unstructured.SetNestedSlice(team.Object, newUsers, "spec", "access", "users"); err != nil {
		h.logger.Error("Failed to update team users", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to remove member")
		return
	}

	_, err = h.k8sClient.Dynamic().Resource(auth.TeamGVR).Update(r.Context(), team, metav1.UpdateOptions{})
	if err != nil {
		h.logger.Error("Failed to update team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to remove member")
		return
	}

	h.logger.Info("Member removed from team", "team", name, "email", decodedEmail)
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "removed",
		"email":  decodedEmail,
	})
}
