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
// It checks both manual team membership and group mappings from IdentityProviders.
func (r *TeamResolver) ResolveTeams(ctx context.Context, email string, idpGroups []string) ([]TeamMembership, error) {
	memberships := make(map[string]TeamMembership)

	// 1. Check manual membership in Team CRDs
	if err := r.resolveManualMemberships(ctx, email, memberships); err != nil {
		r.logger.Warn("Failed to resolve manual team memberships", "error", err)
		// Continue - don't fail completely if Team CRDs can't be read
	}

	// 2. Check group mappings from IdentityProvider CRDs
	if len(idpGroups) > 0 {
		if err := r.resolveGroupMappings(ctx, idpGroups, memberships); err != nil {
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

// resolveGroupMappings checks IdentityProvider CRDs for group mappings.
func (r *TeamResolver) resolveGroupMappings(ctx context.Context, idpGroups []string, memberships map[string]TeamMembership) error {
	// Create a set of user's groups for quick lookup
	groupSet := make(map[string]bool)
	for _, g := range idpGroups {
		groupSet[strings.ToLower(g)] = true
	}

	// List all IdentityProvider CRDs (cluster-scoped)
	idps, err := r.client.Resource(IdentityProviderGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list identity providers: %w", err)
	}

	for _, idp := range idps.Items {
		// Check spec.groupMapping[]
		mappings, found, err := unstructured.NestedSlice(idp.Object, "spec", "groupMapping")
		if err != nil || !found {
			continue
		}

		for _, m := range mappings {
			mapping, ok := m.(map[string]interface{})
			if !ok {
				continue
			}

			// Get IdP group name
			idpGroup, _, _ := unstructured.NestedString(mapping, "idpGroup")
			if idpGroup == "" {
				continue
			}

			// Check if user is in this group (case-insensitive)
			if !groupSet[strings.ToLower(idpGroup)] {
				continue
			}

			// Get target team and role
			team, _, _ := unstructured.NestedString(mapping, "team")
			role, _, _ := unstructured.NestedString(mapping, "role")
			if team == "" {
				continue
			}
			if role == "" {
				role = RoleViewer
			}

			// Add or upgrade membership
			r.addMembership(memberships, team, role)
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
			// Include basic info anyway
			teams = append(teams, TeamInfo{
				Name: m.Name,
				Role: m.Role,
			})
			continue
		}

		displayName, _, _ := unstructured.NestedString(team.Object, "spec", "displayName")
		if displayName == "" {
			displayName = m.Name
		}

		clusterCount, _, _ := unstructured.NestedInt64(team.Object, "status", "clusterCount")

		teams = append(teams, TeamInfo{
			Name:         m.Name,
			DisplayName:  displayName,
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
