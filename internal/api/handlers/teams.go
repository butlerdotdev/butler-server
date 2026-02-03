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

// TeamHandler handles team-related API endpoints.
type TeamHandler struct {
	k8sClient    *k8s.Client
	teamResolver *auth.TeamResolver
	logger       *slog.Logger
}

// NewTeamHandler creates a new TeamHandler.
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
	GroupCount   int               `json:"groupCount"`
	Labels       map[string]string `json:"labels,omitempty"`
	CreatedAt    string            `json:"createdAt,omitempty"`
}

// TeamMemberResponse represents a team member in API responses.
// Source indicates how the user has access: "direct", "group", or "elevated".
// Elevated means the user has group access but was given a higher role directly.
type TeamMemberResponse struct {
	Email      string `json:"email"`
	Name       string `json:"name,omitempty"`
	Role       string `json:"role"`
	Source     string `json:"source"`
	GroupName  string `json:"groupName,omitempty"`
	GroupRole  string `json:"groupRole,omitempty"`
	DirectRole string `json:"directRole,omitempty"`
	CanRemove  bool   `json:"canRemove"`
	RemoveNote string `json:"removeNote,omitempty"`
}

// TeamGroupAccessResponse represents a group access rule for a team.
type TeamGroupAccessResponse struct {
	Name string `json:"name"`
	Role string `json:"role"`
}

// roleLevel returns a numeric level for role comparison (higher = more privilege).
func roleLevel(role string) int {
	switch role {
	case auth.RoleAdmin:
		return 3
	case auth.RoleOperator:
		return 2
	case auth.RoleViewer:
		return 1
	default:
		return 0
	}
}

// isHigherRole returns true if role1 has higher privilege than role2.
func isHigherRole(role1, role2 string) bool {
	return roleLevel(role1) > roleLevel(role2)
}

// groupMatchesEmail checks if an email's domain matches a group's domain.
// This is a heuristic for potential group membership when we don't have IdP data.
func groupMatchesEmail(groupName, email string) bool {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return false
	}
	emailDomain := strings.ToLower(parts[1])

	groupLower := strings.ToLower(groupName)
	groupParts := strings.Split(groupLower, "@")
	if len(groupParts) == 2 {
		return emailDomain == groupParts[1]
	}
	return false
}

// getTeamGroups extracts group access rules from a Team CRD.
func getTeamGroups(team *unstructured.Unstructured) []TeamGroupAccessResponse {
	groups := make([]TeamGroupAccessResponse, 0)
	groupsSlice, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "groups")
	if !found {
		return groups
	}

	for _, g := range groupsSlice {
		groupMap, ok := g.(map[string]interface{})
		if !ok {
			continue
		}
		name, _, _ := unstructured.NestedString(groupMap, "name")
		role, _, _ := unstructured.NestedString(groupMap, "role")
		if name == "" {
			continue
		}
		if role == "" {
			role = auth.RoleViewer
		}
		groups = append(groups, TeamGroupAccessResponse{Name: name, Role: role})
	}
	return groups
}

// findPotentialGroupAccess checks if an email might have access via team groups.
// Returns the highest-privilege matching group if found.
func findPotentialGroupAccess(email string, groups []TeamGroupAccessResponse) (bool, string, string) {
	var bestGroup string
	var bestRole string
	found := false

	for _, group := range groups {
		if groupMatchesEmail(group.Name, email) {
			if !found || isHigherRole(group.Role, bestRole) {
				found = true
				bestGroup = group.Name
				bestRole = group.Role
			}
		}
	}
	return found, bestGroup, bestRole
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

	allClusters, err := h.k8sClient.Dynamic().Resource(k8s.TenantClusterGVR).List(r.Context(), metav1.ListOptions{})
	if err != nil {
		h.logger.Warn("Failed to list clusters for counting", "error", err)
	}

	clusterCountByTeam := make(map[string]int)
	if allClusters != nil {
		for _, cluster := range allClusters.Items {
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

		if namespace == "" {
			namespace = team.GetName()
		}

		memberCount := 0
		if users, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users"); found {
			memberCount = len(users)
		}

		groupCount := 0
		if groups, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "groups"); found {
			groupCount = len(groups)
		}

		if displayName == "" {
			displayName = team.GetName()
		}
		if phase == "" {
			phase = "Ready"
		}

		response = append(response, TeamResponse{
			Name:         team.GetName(),
			DisplayName:  displayName,
			Description:  description,
			Namespace:    namespace,
			Phase:        phase,
			ClusterCount: clusterCountByTeam[team.GetName()],
			MemberCount:  memberCount,
			GroupCount:   groupCount,
			Labels:       team.GetLabels(),
			CreatedAt:    team.GetCreationTimestamp().Format("2006-01-02T15:04:05Z"),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"teams": response})
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

	if namespace == "" {
		namespace = team.GetName()
	}

	memberCount := 0
	if users, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users"); found {
		memberCount = len(users)
	}

	groupCount := 0
	if groups, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "groups"); found {
		groupCount = len(groups)
	}

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
		GroupCount:   groupCount,
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
		unstructured.SetNestedField(team.Object, req.Namespace, "spec", "namespace")
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

	var labelParts []string
	for k, v := range selector {
		labelParts = append(labelParts, k+"="+v)
	}

	clusters, err := h.k8sClient.Dynamic().Resource(k8s.TenantClusterGVR).List(r.Context(), metav1.ListOptions{
		LabelSelector: strings.Join(labelParts, ","),
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

	writeJSON(w, http.StatusOK, map[string]interface{}{"clusters": response})
}

// ListMembers returns members of a team including both explicit users and group-synced users.
// GET /api/teams/{name}/members
func (h *TeamHandler) ListMembers(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	if !user.HasTeamMembership(name) && !user.IsPlatformAdmin {
		writeError(w, http.StatusForbidden, "Access denied to team")
		return
	}

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

	groups := getTeamGroups(team)

	// findUserGroupAccess checks group access for an email.
	// For the current user, we use actual IdP groups. For others, we use domain matching.
	findUserGroupAccess := func(email string) (bool, string, string) {
		if user == nil || !strings.EqualFold(user.Email, email) {
			return findPotentialGroupAccess(email, groups)
		}

		var hasAccess bool
		var groupName, groupRole string
		for _, userGroup := range user.Groups {
			userGroupLower := strings.ToLower(userGroup)
			for _, teamGroup := range groups {
				teamGroupLower := strings.ToLower(teamGroup.Name)
				if userGroupLower == teamGroupLower ||
					strings.HasPrefix(userGroupLower, teamGroupLower+"@") ||
					strings.HasPrefix(teamGroupLower, userGroupLower+"@") ||
					strings.Contains(userGroupLower, teamGroupLower) ||
					strings.Contains(teamGroupLower, userGroupLower) {
					if !hasAccess || isHigherRole(teamGroup.Role, groupRole) {
						hasAccess = true
						groupName = teamGroup.Name
						groupRole = teamGroup.Role
					}
				}
			}
		}
		return hasAccess, groupName, groupRole
	}

	seenEmails := make(map[string]bool)
	members := make([]TeamMemberResponse, 0)

	// Process explicit members from spec.access.users
	usersSlice, _, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users")
	for _, u := range usersSlice {
		userMap, ok := u.(map[string]interface{})
		if !ok {
			continue
		}

		email, _, _ := unstructured.NestedString(userMap, "name")
		directRole, _, _ := unstructured.NestedString(userMap, "role")
		displayName, _, _ := unstructured.NestedString(userMap, "displayName")

		if email == "" {
			continue
		}
		if directRole == "" {
			directRole = auth.RoleViewer
		}

		emailLower := strings.ToLower(email)
		seenEmails[emailLower] = true

		hasGroupAccess, groupName, groupRole := findUserGroupAccess(email)

		member := TeamMemberResponse{
			Email: email,
			Name:  displayName,
		}

		if hasGroupAccess && isHigherRole(directRole, groupRole) {
			// Elevated: has group access but direct role is higher
			member.Role = directRole
			member.Source = "elevated"
			member.GroupName = groupName
			member.GroupRole = groupRole
			member.DirectRole = directRole
			member.CanRemove = true
			member.RemoveNote = "Will revert to " + groupRole + " via " + groupName
		} else if hasGroupAccess {
			// Group access at same or higher level (shouldn't happen with Option A enforcement)
			member.Role = groupRole
			member.Source = "group"
			member.GroupName = groupName
			member.GroupRole = groupRole
			member.DirectRole = directRole
			member.CanRemove = true
			member.RemoveNote = "Redundant direct membership"
		} else {
			// Direct only
			member.Role = directRole
			member.Source = "direct"
			member.CanRemove = email != user.Email
		}

		members = append(members, member)
	}

	// Add current user if they have group access but no direct membership
	if user.Email != "" {
		emailLower := strings.ToLower(user.Email)
		if !seenEmails[emailLower] && user.HasTeamMembership(name) {
			hasGroupAccess, groupName, groupRole := findUserGroupAccess(user.Email)
			if hasGroupAccess {
				members = append(members, TeamMemberResponse{
					Email:      user.Email,
					Name:       user.Name,
					Role:       groupRole,
					Source:     "group",
					GroupName:  groupName,
					GroupRole:  groupRole,
					CanRemove:  false,
					RemoveNote: "Access via group membership",
				})
			}
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"members": members,
		"groups":  groups,
	})
}

// AddMemberRequest represents the request body for adding a team member.
type AddMemberRequest struct {
	Email string `json:"email"`
	Role  string `json:"role,omitempty"`
}

// AddMember adds a member to a team.
// If the user has group access at same/lower role, the request is rejected.
// If the user has group access at a lower role, they can be added with a higher role (elevation).
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

	if req.Role != auth.RoleAdmin && req.Role != auth.RoleOperator && req.Role != auth.RoleViewer {
		writeError(w, http.StatusBadRequest, "Invalid role. Must be admin, operator, or viewer")
		return
	}

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

	users, _, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users")
	if users == nil {
		users = []interface{}{}
	}

	// Check if user already exists as direct member
	emailLower := strings.ToLower(req.Email)
	for _, u := range users {
		userMap, ok := u.(map[string]interface{})
		if !ok {
			continue
		}
		existingEmail, _, _ := unstructured.NestedString(userMap, "name")
		if strings.EqualFold(existingEmail, emailLower) {
			writeError(w, http.StatusConflict, "User is already a direct member. Use the role dropdown to change their role.")
			return
		}
	}

	// Check for potential group access (Option A: block redundant, allow elevation)
	groups := getTeamGroups(team)
	hasGroupAccess, groupName, groupRole := findPotentialGroupAccess(req.Email, groups)

	if hasGroupAccess {
		if !isHigherRole(req.Role, groupRole) {
			writeError(w, http.StatusConflict,
				"User may already have "+groupRole+" access via "+groupName+". "+
					"To elevate their role, add them with a higher role.")
			return
		}
		h.logger.Info("Creating elevated membership",
			"team", name, "email", req.Email, "directRole", req.Role,
			"groupRole", groupRole, "groupName", groupName)
	}

	newUser := map[string]interface{}{
		"name": emailLower,
		"role": req.Role,
	}
	users = append(users, newUser)

	access, _, _ := unstructured.NestedMap(team.Object, "spec", "access")
	if access == nil {
		unstructured.SetNestedMap(team.Object, map[string]interface{}{}, "spec", "access")
	}

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

	response := map[string]interface{}{
		"status": "added",
		"email":  req.Email,
		"role":   req.Role,
	}

	if hasGroupAccess {
		response["elevated"] = true
		response["groupName"] = groupName
		response["groupRole"] = groupRole
	}

	h.logger.Info("Member added to team", "team", name, "email", req.Email, "role", req.Role)
	writeJSON(w, http.StatusCreated, response)
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

	if req.Role != auth.RoleAdmin && req.Role != auth.RoleOperator && req.Role != auth.RoleViewer {
		writeError(w, http.StatusBadRequest, "Invalid role. Must be admin, operator, or viewer")
		return
	}

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

	users, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users")
	if !found || users == nil {
		writeError(w, http.StatusNotFound, "Member not found")
		return
	}

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
// If the user has group access, they will retain that access after removal.
// DELETE /api/admin/teams/{name}/members/{email}
func (h *TeamHandler) RemoveMember(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	email := chi.URLParam(r, "email")

	decodedEmail, err := url.QueryUnescape(email)
	if err != nil {
		decodedEmail = email
	}

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

	// Check for group access to inform response
	groups := getTeamGroups(team)
	hasGroupAccess, groupName, groupRole := findPotentialGroupAccess(decodedEmail, groups)

	users, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "users")
	if !found || users == nil {
		writeError(w, http.StatusNotFound, "Member not found")
		return
	}

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
			continue
		}
		newUsers = append(newUsers, u)
	}

	if !memberFound {
		writeError(w, http.StatusNotFound, "Member not found")
		return
	}

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

	response := map[string]interface{}{
		"status": "removed",
		"email":  decodedEmail,
	}

	if hasGroupAccess {
		response["retainsAccess"] = true
		response["groupName"] = groupName
		response["groupRole"] = groupRole
	}

	h.logger.Info("Member removed from team", "team", name, "email", decodedEmail, "retainsGroupAccess", hasGroupAccess)
	writeJSON(w, http.StatusOK, response)
}

// GroupSyncResponse represents a group sync entry in API responses.
type GroupSyncResponse struct {
	Name             string `json:"name"`
	Role             string `json:"role"`
	IdentityProvider string `json:"identityProvider,omitempty"`
}

// ListGroupSyncs returns all group sync entries for a team.
// GET /api/teams/{name}/groups
func (h *TeamHandler) ListGroupSyncs(w http.ResponseWriter, r *http.Request) {
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

	groups, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "groups")
	if !found {
		groups = []interface{}{}
	}

	response := make([]GroupSyncResponse, 0, len(groups))
	for _, g := range groups {
		group, ok := g.(map[string]interface{})
		if !ok {
			continue
		}

		groupName, _, _ := unstructured.NestedString(group, "name")
		role, _, _ := unstructured.NestedString(group, "role")
		idp, _, _ := unstructured.NestedString(group, "identityProvider")

		if groupName == "" {
			continue
		}
		if role == "" {
			role = auth.RoleViewer
		}

		response = append(response, GroupSyncResponse{
			Name:             groupName,
			Role:             role,
			IdentityProvider: idp,
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"groups": response})
}

// AddGroupSyncRequest represents the request body for adding a group sync.
type AddGroupSyncRequest struct {
	Name             string `json:"name"`
	Role             string `json:"role"`
	IdentityProvider string `json:"identityProvider,omitempty"`
}

// AddGroupSync adds a group sync entry to a team.
// POST /api/admin/teams/{name}/groups
func (h *TeamHandler) AddGroupSync(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var req AddGroupSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "Group name is required")
		return
	}

	if req.Role == "" {
		req.Role = auth.RoleViewer
	}

	if req.Role != auth.RoleAdmin && req.Role != auth.RoleOperator && req.Role != auth.RoleViewer {
		writeError(w, http.StatusBadRequest, "Invalid role. Must be admin, operator, or viewer")
		return
	}

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

	// Validate identity provider if specified
	if req.IdentityProvider != "" {
		_, err := h.k8sClient.Dynamic().Resource(auth.IdentityProviderGVR).Get(r.Context(), req.IdentityProvider, metav1.GetOptions{})
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				writeError(w, http.StatusBadRequest, "Identity provider '"+req.IdentityProvider+"' not found")
				return
			}
			h.logger.Error("Failed to validate identity provider", "name", req.IdentityProvider, "error", err)
			writeError(w, http.StatusInternalServerError, "Failed to validate identity provider")
			return
		}
	}

	groups, _, _ := unstructured.NestedSlice(team.Object, "spec", "access", "groups")
	if groups == nil {
		groups = []interface{}{}
	}

	// Check for duplicate
	groupNameLower := strings.ToLower(req.Name)
	idpLower := strings.ToLower(req.IdentityProvider)
	for _, g := range groups {
		groupMap, ok := g.(map[string]interface{})
		if !ok {
			continue
		}
		existingName, _, _ := unstructured.NestedString(groupMap, "name")
		existingIdP, _, _ := unstructured.NestedString(groupMap, "identityProvider")
		if strings.EqualFold(existingName, groupNameLower) && strings.EqualFold(existingIdP, idpLower) {
			writeError(w, http.StatusConflict, "Group sync already exists for this group and identity provider")
			return
		}
	}

	newGroup := map[string]interface{}{
		"name": req.Name,
		"role": req.Role,
	}
	if req.IdentityProvider != "" {
		newGroup["identityProvider"] = req.IdentityProvider
	}
	groups = append(groups, newGroup)

	access, _, _ := unstructured.NestedMap(team.Object, "spec", "access")
	if access == nil {
		unstructured.SetNestedMap(team.Object, map[string]interface{}{}, "spec", "access")
	}

	if err := unstructured.SetNestedSlice(team.Object, groups, "spec", "access", "groups"); err != nil {
		h.logger.Error("Failed to update team groups", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to add group sync")
		return
	}

	_, err = h.k8sClient.Dynamic().Resource(auth.TeamGVR).Update(r.Context(), team, metav1.UpdateOptions{})
	if err != nil {
		h.logger.Error("Failed to update team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to add group sync")
		return
	}

	h.logger.Info("Group sync added to team", "team", name, "group", req.Name, "role", req.Role, "idp", req.IdentityProvider)
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"status":           "added",
		"name":             req.Name,
		"role":             req.Role,
		"identityProvider": req.IdentityProvider,
	})
}

// RemoveGroupSync removes a group sync entry from a team.
// DELETE /api/admin/teams/{name}/groups/{groupName}?idp=<identityProvider>
func (h *TeamHandler) RemoveGroupSync(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	groupName := chi.URLParam(r, "groupName")
	idpFilter := r.URL.Query().Get("idp")

	decodedGroupName, err := url.QueryUnescape(groupName)
	if err != nil {
		decodedGroupName = groupName
	}

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

	groups, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "groups")
	if !found || groups == nil {
		writeError(w, http.StatusNotFound, "Group sync not found")
		return
	}

	groupFound := false
	newGroups := make([]interface{}, 0, len(groups)-1)
	for _, g := range groups {
		groupMap, ok := g.(map[string]interface{})
		if !ok {
			newGroups = append(newGroups, g)
			continue
		}
		existingName, _, _ := unstructured.NestedString(groupMap, "name")
		existingIdP, _, _ := unstructured.NestedString(groupMap, "identityProvider")

		if strings.EqualFold(existingName, decodedGroupName) {
			if idpFilter != "" && !strings.EqualFold(existingIdP, idpFilter) {
				newGroups = append(newGroups, g)
				continue
			}
			groupFound = true
			continue
		}
		newGroups = append(newGroups, g)
	}

	if !groupFound {
		writeError(w, http.StatusNotFound, "Group sync not found")
		return
	}

	if err := unstructured.SetNestedSlice(team.Object, newGroups, "spec", "access", "groups"); err != nil {
		h.logger.Error("Failed to update team groups", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to remove group sync")
		return
	}

	_, err = h.k8sClient.Dynamic().Resource(auth.TeamGVR).Update(r.Context(), team, metav1.UpdateOptions{})
	if err != nil {
		h.logger.Error("Failed to update team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to remove group sync")
		return
	}

	h.logger.Info("Group sync removed from team", "team", name, "group", decodedGroupName)
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "removed",
		"name":   decodedGroupName,
	})
}

// UpdateGroupSyncRequest represents the request body for updating a group sync's role.
type UpdateGroupSyncRequest struct {
	Role string `json:"role"`
}

// UpdateGroupSyncRole updates a group sync's role.
// PATCH /api/admin/teams/{name}/groups/{groupName}?idp=<identityProvider>
func (h *TeamHandler) UpdateGroupSyncRole(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	groupName := chi.URLParam(r, "groupName")
	idpFilter := r.URL.Query().Get("idp")

	decodedGroupName, err := url.QueryUnescape(groupName)
	if err != nil {
		decodedGroupName = groupName
	}

	var req UpdateGroupSyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Role == "" {
		writeError(w, http.StatusBadRequest, "Role is required")
		return
	}

	if req.Role != auth.RoleAdmin && req.Role != auth.RoleOperator && req.Role != auth.RoleViewer {
		writeError(w, http.StatusBadRequest, "Invalid role. Must be admin, operator, or viewer")
		return
	}

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

	groups, found, _ := unstructured.NestedSlice(team.Object, "spec", "access", "groups")
	if !found || groups == nil {
		writeError(w, http.StatusNotFound, "Group sync not found")
		return
	}

	groupFound := false
	for i, g := range groups {
		groupMap, ok := g.(map[string]interface{})
		if !ok {
			continue
		}
		existingName, _, _ := unstructured.NestedString(groupMap, "name")
		existingIdP, _, _ := unstructured.NestedString(groupMap, "identityProvider")

		if strings.EqualFold(existingName, decodedGroupName) {
			if idpFilter != "" && !strings.EqualFold(existingIdP, idpFilter) {
				continue
			}
			groupMap["role"] = req.Role
			groups[i] = groupMap
			groupFound = true
			break
		}
	}

	if !groupFound {
		writeError(w, http.StatusNotFound, "Group sync not found")
		return
	}

	if err := unstructured.SetNestedSlice(team.Object, groups, "spec", "access", "groups"); err != nil {
		h.logger.Error("Failed to update team groups", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to update group sync role")
		return
	}

	_, err = h.k8sClient.Dynamic().Resource(auth.TeamGVR).Update(r.Context(), team, metav1.UpdateOptions{})
	if err != nil {
		h.logger.Error("Failed to update team", "name", name, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to update group sync role")
		return
	}

	h.logger.Info("Group sync role updated", "team", name, "group", decodedGroupName, "role", req.Role)
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "updated",
		"name":   decodedGroupName,
		"role":   req.Role,
	})
}
