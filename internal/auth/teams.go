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

package auth

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
)

var (
	// TeamGVR is the GroupVersionResource for Team CRDs
	TeamGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "teams",
	}

	// IdentityProviderGVR is the GroupVersionResource for IdentityProvider CRDs
	IdentityProviderGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "identityproviders",
	}
)

// TeamResolver resolves team memberships for users.
type TeamResolver struct {
	client dynamic.Interface
	logger *slog.Logger
}

// NewTeamResolver creates a new team resolver.
func NewTeamResolver(client dynamic.Interface, logger *slog.Logger) *TeamResolver {
	return &TeamResolver{
		client: client,
		logger: logger,
	}
}

// ResolveTeams resolves all team memberships for a user based on their email and IdP groups.
// It checks both manual team membership (spec.access.users) and group sync (spec.access.groups).
func (r *TeamResolver) ResolveTeams(ctx context.Context, email string, idpGroups []string) ([]TeamMembership, error) {
	return r.ResolveTeamsWithIdP(ctx, email, idpGroups, "")
}

// ResolveTeamsWithIdP resolves team memberships with IdP-specific group matching.
// The idpName parameter is optional - if provided, it restricts group matching to groups
// configured for that specific identity provider. If empty, groups from any IdP are matched.
func (r *TeamResolver) ResolveTeamsWithIdP(ctx context.Context, email string, idpGroups []string, idpName string) ([]TeamMembership, error) {
	memberships := make(map[string]TeamMembership)

	// 1. Check manual membership in Team CRDs (spec.access.users)
	if err := r.resolveManualMemberships(ctx, email, memberships); err != nil {
		r.logger.Warn("Failed to resolve manual team memberships", "error", err)
		// Continue - don't fail completely if Team CRDs can't be read
	}

	// 2. Check group sync from Team CRDs (spec.access.groups)
	// This is the team-centric approach where groups are configured on teams, not on IdPs.
	if len(idpGroups) > 0 {
		if err := r.resolveGroupMappings(ctx, idpGroups, idpName, memberships); err != nil {
			r.logger.Warn("Failed to resolve group mappings", "error", err)
			// Continue - don't fail completely
		}
	}

	// Convert map to slice
	result := make([]TeamMembership, 0, len(memberships))
	for _, membership := range memberships {
		result = append(result, membership)
	}

	return result, nil
}

// resolveManualMemberships checks Team CRDs for manual membership by email.
func (r *TeamResolver) resolveManualMemberships(ctx context.Context, email string, memberships map[string]TeamMembership) error {
	// List all Team CRDs (cluster-scoped)
	teams, err := r.client.Resource(TeamGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list teams: %w", err)
	}

	for _, team := range teams.Items {
		teamName := team.GetName()

		// Check spec.access.users[]
		users, found, err := unstructured.NestedSlice(team.Object, "spec", "access", "users")
		if err != nil || !found {
			continue
		}

		for _, u := range users {
			user, ok := u.(map[string]interface{})
			if !ok {
				continue
			}

			// Get user name (email)
			name, _, _ := unstructured.NestedString(user, "name")
			if !strings.EqualFold(name, email) {
				continue
			}

			// Get user role
			role, _, _ := unstructured.NestedString(user, "role")
			if role == "" {
				role = RoleViewer // Default role
			}

			// Add or upgrade membership (highest role wins)
			r.addMembership(memberships, teamName, role)
		}
	}

	return nil
}

// normalizeGroupName extracts the base group name without domain suffix.
// Examples:
//   - "platform-engineering-viewer@butlerlabs.dev" -> "platform-engineering-viewer"
//   - "platform-engineering-viewer" -> "platform-engineering-viewer"
//   - "CN=DevOps,OU=Groups,DC=corp,DC=example,DC=com" -> "devops" (extracts CN)
func normalizeGroupName(group string) string {
	group = strings.TrimSpace(group)

	// Handle LDAP DN format (CN=GroupName,OU=...)
	if strings.HasPrefix(strings.ToUpper(group), "CN=") {
		// Extract just the CN value
		parts := strings.Split(group, ",")
		if len(parts) > 0 {
			cnPart := parts[0]
			if idx := strings.Index(cnPart, "="); idx != -1 {
				group = cnPart[idx+1:]
			}
		}
	}

	// Handle email-style groups (group@domain.com)
	if idx := strings.LastIndex(group, "@"); idx != -1 {
		group = group[:idx]
	}

	return strings.ToLower(group)
}

// buildGroupLookupSet creates a lookup set for user's IdP groups.
// It stores multiple variations of each group for flexible matching:
// - Original (lowercased)
// - Normalized (without domain suffix)
func buildGroupLookupSet(idpGroups []string) map[string]bool {
	groupSet := make(map[string]bool)

	for _, g := range idpGroups {
		// Store original (lowercased)
		lower := strings.ToLower(g)
		groupSet[lower] = true

		// Store normalized version (without domain)
		normalized := normalizeGroupName(g)
		if normalized != lower {
			groupSet[normalized] = true
		}
	}

	return groupSet
}

// groupMatches checks if a configured group name matches any of the user's IdP groups.
// This performs flexible matching that handles:
// - Exact match (case-insensitive)
// - Domain suffix differences (config has "group", IdP sends "group@domain.com")
// - LDAP DN format (CN=group,OU=...)
func (r *TeamResolver) groupMatches(configuredGroup string, groupSet map[string]bool) bool {
	// Normalize the configured group name
	normalizedConfig := normalizeGroupName(configuredGroup)

	// Check if the normalized configured group is in our lookup set
	if groupSet[normalizedConfig] {
		return true
	}

	// Also try exact match with original configured group (lowercased)
	if groupSet[strings.ToLower(configuredGroup)] {
		return true
	}

	return false
}

// resolveGroupMappings checks Team CRDs for group-based access (spec.access.groups).
// This is the team-centric approach where groups are configured on teams.
// The idpName parameter is optional - if provided, only groups matching that IdP are considered.
func (r *TeamResolver) resolveGroupMappings(ctx context.Context, idpGroups []string, idpName string, memberships map[string]TeamMembership) error {
	// Build a flexible lookup set for the user's groups
	groupSet := buildGroupLookupSet(idpGroups)

	r.logger.Debug("Group matching lookup set",
		"idpGroups", idpGroups,
		"normalizedSet", groupSet,
	)

	// List all Team CRDs (cluster-scoped)
	teams, err := r.client.Resource(TeamGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list teams: %w", err)
	}

	for _, team := range teams.Items {
		teamName := team.GetName()

		// Check spec.access.groups[]
		groups, found, err := unstructured.NestedSlice(team.Object, "spec", "access", "groups")
		if err != nil || !found {
			continue
		}

		for _, g := range groups {
			group, ok := g.(map[string]interface{})
			if !ok {
				continue
			}

			// Get group name
			groupName, _, _ := unstructured.NestedString(group, "name")
			if groupName == "" {
				continue
			}

			// Check if this group is IdP-specific
			groupIdP, _, _ := unstructured.NestedString(group, "identityProvider")

			// If the group specifies an IdP and we know the user's IdP, check they match
			if groupIdP != "" && idpName != "" {
				if !strings.EqualFold(groupIdP, idpName) {
					continue // Skip - group is for a different IdP
				}
			}

			// Check if user is in this group using flexible matching
			if !r.groupMatches(groupName, groupSet) {
				r.logger.Debug("Group sync no match",
					"team", teamName,
					"configuredGroup", groupName,
					"normalizedConfig", normalizeGroupName(groupName),
				)
				continue
			}

			// Get role
			role, _, _ := unstructured.NestedString(group, "role")
			if role == "" {
				role = RoleViewer
			}

			// Add or upgrade membership
			r.addMembership(memberships, teamName, role)

			r.logger.Debug("Group sync matched",
				"team", teamName,
				"configuredGroup", groupName,
				"groupIdP", groupIdP,
				"userIdP", idpName,
				"role", role,
			)
		}
	}

	return nil
}

// addMembership adds or upgrades a team membership (highest role wins).
func (r *TeamResolver) addMembership(memberships map[string]TeamMembership, teamName, role string) {
	existing, exists := memberships[teamName]
	if !exists {
		memberships[teamName] = TeamMembership{
			Name: teamName,
			Role: role,
		}
		return
	}

	// Keep the higher role
	if RoleHierarchy(role, existing.Role) {
		memberships[teamName] = TeamMembership{
			Name: teamName,
			Role: role,
		}
	}
}

// GetTeamClusterSelector returns the cluster selector labels for a team.
// This is used to filter clusters by team ownership.
func (r *TeamResolver) GetTeamClusterSelector(ctx context.Context, teamName string) (map[string]string, error) {
	team, err := r.client.Resource(TeamGVR).Get(ctx, teamName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get team %s: %w", teamName, err)
	}

	// Check for clusterSelector.matchLabels
	labels, found, err := unstructured.NestedStringMap(team.Object, "spec", "clusterSelector", "matchLabels")
	if err != nil || !found {
		// Default: use the standard team label
		return map[string]string{
			"butler.butlerlabs.dev/team": teamName,
		}, nil
	}

	return labels, nil
}

// ListTeamsForUser returns all teams a user has access to.
func (r *TeamResolver) ListTeamsForUser(ctx context.Context, email string, idpGroups []string) ([]TeamInfo, error) {
	memberships, err := r.ResolveTeams(ctx, email, idpGroups)
	if err != nil {
		return nil, err
	}

	// Fetch additional team info
	teams := make([]TeamInfo, 0, len(memberships))
	for _, m := range memberships {
		team, err := r.client.Resource(TeamGVR).Get(ctx, m.Name, metav1.GetOptions{})
		if err != nil {
			r.logger.Warn("Failed to get team details", "team", m.Name, "error", err)
			// Include basic info anyway - use team name as namespace fallback
			teams = append(teams, TeamInfo{
				Name:      m.Name,
				Namespace: m.Name, // Fallback to team name
				Role:      m.Role,
			})
			continue
		}

		displayName, _, _ := unstructured.NestedString(team.Object, "spec", "displayName")
		if displayName == "" {
			displayName = m.Name
		}

		// Get namespace from status.namespace, fallback to team name
		namespace, _, _ := unstructured.NestedString(team.Object, "status", "namespace")
		if namespace == "" {
			namespace = m.Name
		}

		clusterCount, _, _ := unstructured.NestedInt64(team.Object, "status", "clusterCount")

		teams = append(teams, TeamInfo{
			Name:         m.Name,
			DisplayName:  displayName,
			Namespace:    namespace,
			Role:         m.Role,
			ClusterCount: int(clusterCount),
		})
	}

	return teams, nil
}

// TeamInfo contains information about a team for display purposes.
type TeamInfo struct {
	Name         string `json:"name"`
	DisplayName  string `json:"displayName"`
	Namespace    string `json:"namespace"`
	Role         string `json:"role"`
	ClusterCount int    `json:"clusterCount"`
}

// ValidateTeamExists checks if a team exists.
func (r *TeamResolver) ValidateTeamExists(ctx context.Context, teamName string) (bool, error) {
	_, err := r.client.Resource(TeamGVR).Get(ctx, teamName, metav1.GetOptions{})
	if err != nil {
		// Check if it's a not-found error
		if strings.Contains(err.Error(), "not found") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// MemberInfo contains aggregated membership info for a user across all teams.
type MemberInfo struct {
	Email string
	Teams []string
	Roles map[string]string // team -> role
}

// ListAllMembers returns all users from all Team CRDs with their team memberships.
// This aggregates all users across all teams for the admin users list.
func (r *TeamResolver) ListAllMembers(ctx context.Context) map[string]*MemberInfo {
	members := make(map[string]*MemberInfo)

	// List all Team CRDs
	teams, err := r.client.Resource(TeamGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		r.logger.Debug("Could not list teams for member aggregation", "error", err)
		return members
	}

	for _, team := range teams.Items {
		teamName := team.GetName()

		// Check spec.access.users[]
		users, found, err := unstructured.NestedSlice(team.Object, "spec", "access", "users")
		if err != nil || !found {
			continue
		}

		for _, u := range users {
			user, ok := u.(map[string]interface{})
			if !ok {
				continue
			}

			// Get user email
			email, _, _ := unstructured.NestedString(user, "name")
			if email == "" {
				continue
			}
			email = strings.ToLower(email)

			// Get role
			role, _, _ := unstructured.NestedString(user, "role")
			if role == "" {
				role = RoleViewer
			}

			// Add to members map
			if members[email] == nil {
				members[email] = &MemberInfo{
					Email: email,
					Teams: []string{},
					Roles: make(map[string]string),
				}
			}
			members[email].Teams = append(members[email].Teams, teamName)
			members[email].Roles[teamName] = role
		}
	}

	return members
}

// GroupSyncEntry represents a group sync configuration for a team.
type GroupSyncEntry struct {
	Name             string `json:"name"`
	Role             string `json:"role"`
	IdentityProvider string `json:"identityProvider,omitempty"`
}

// GetTeamGroupSyncs returns all group sync entries for a team.
func (r *TeamResolver) GetTeamGroupSyncs(ctx context.Context, teamName string) ([]GroupSyncEntry, error) {
	team, err := r.client.Resource(TeamGVR).Get(ctx, teamName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get team %s: %w", teamName, err)
	}

	groups, found, err := unstructured.NestedSlice(team.Object, "spec", "access", "groups")
	if err != nil || !found {
		return []GroupSyncEntry{}, nil
	}

	result := make([]GroupSyncEntry, 0, len(groups))
	for _, g := range groups {
		group, ok := g.(map[string]interface{})
		if !ok {
			continue
		}

		name, _, _ := unstructured.NestedString(group, "name")
		role, _, _ := unstructured.NestedString(group, "role")
		idp, _, _ := unstructured.NestedString(group, "identityProvider")

		if name == "" {
			continue
		}
		if role == "" {
			role = RoleViewer
		}

		result = append(result, GroupSyncEntry{
			Name:             name,
			Role:             role,
			IdentityProvider: idp,
		})
	}

	return result, nil
}
