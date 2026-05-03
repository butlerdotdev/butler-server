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
	"testing"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// makeCluster creates an unstructured TenantCluster with the given teamRef.
func makeCluster(teamRef string) *unstructured.Unstructured {
	obj := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{},
	}}
	if teamRef != "" {
		unstructured.SetNestedField(obj.Object, teamRef, "spec", "teamRef", "name")
	}
	return obj
}

func TestAddonsHandler_checkOperatePermission(t *testing.T) {
	h := &AddonsHandler{}
	cluster := makeCluster("team-alpha")

	tests := []struct {
		name    string
		user    *auth.UserSession
		wantErr bool
	}{
		{
			name: "platform admin allowed",
			user: &auth.UserSession{PlatformRole: auth.RoleAdmin},
		},
		{
			name:    "platform viewer denied",
			user:    &auth.UserSession{PlatformRole: auth.RoleViewer},
			wantErr: true,
		},
		{
			name: "team operator allowed",
			user: &auth.UserSession{
				Teams: []auth.TeamMembership{{Name: "team-alpha", Role: auth.RoleOperator}},
			},
		},
		{
			name:    "team viewer denied",
			user:    &auth.UserSession{PlatformRole: auth.RoleViewer},
			wantErr: true,
		},
		{
			name: "selected team operator allowed",
			user: &auth.UserSession{
				SelectedTeam:     "team-alpha",
				SelectedTeamRole: auth.RoleOperator,
			},
		},
		{
			name: "selected team admin allowed",
			user: &auth.UserSession{
				SelectedTeam:     "team-alpha",
				SelectedTeamRole: auth.RoleAdmin,
			},
		},
		{
			name: "selected team viewer denied",
			user: &auth.UserSession{
				SelectedTeam:     "team-alpha",
				SelectedTeamRole: auth.RoleViewer,
			},
			wantErr: true,
		},
		{
			name: "wrong team context denied",
			user: &auth.UserSession{
				SelectedTeam:     "team-beta",
				SelectedTeamRole: auth.RoleOperator,
			},
			wantErr: true,
		},
		{
			name:    "no team membership and not admin denied",
			user:    &auth.UserSession{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.checkOperatePermission(tt.user, cluster, "install addons on")
			if (err != nil) != tt.wantErr {
				t.Errorf("checkOperatePermission() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestAddonsHandler_checkOperatePermission_noTeamRef(t *testing.T) {
	h := &AddonsHandler{}
	cluster := makeCluster("")

	tests := []struct {
		name    string
		user    *auth.UserSession
		wantErr bool
	}{
		{
			name: "admin allowed even without teamRef",
			user: &auth.UserSession{PlatformRole: auth.RoleAdmin},
		},
		{
			name:    "non-admin denied without teamRef",
			user:    &auth.UserSession{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.checkOperatePermission(tt.user, cluster, "install addons on")
			if (err != nil) != tt.wantErr {
				t.Errorf("checkOperatePermission() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestGitOpsHandler_checkOperatePermission(t *testing.T) {
	h := &GitOpsHandler{}
	cluster := makeCluster("team-alpha")

	tests := []struct {
		name    string
		user    *auth.UserSession
		wantErr bool
	}{
		{
			name: "platform admin allowed",
			user: &auth.UserSession{PlatformRole: auth.RoleAdmin},
		},
		{
			name:    "platform viewer denied",
			user:    &auth.UserSession{PlatformRole: auth.RoleViewer},
			wantErr: true,
		},
		{
			name: "team operator allowed",
			user: &auth.UserSession{
				Teams: []auth.TeamMembership{{Name: "team-alpha", Role: auth.RoleOperator}},
			},
		},
		{
			name: "selected team operator allowed",
			user: &auth.UserSession{
				SelectedTeam:     "team-alpha",
				SelectedTeamRole: auth.RoleOperator,
			},
		},
		{
			name: "selected team viewer denied",
			user: &auth.UserSession{
				SelectedTeam:     "team-alpha",
				SelectedTeamRole: auth.RoleViewer,
			},
			wantErr: true,
		},
		{
			name: "wrong team context denied",
			user: &auth.UserSession{
				SelectedTeam:     "team-beta",
				SelectedTeamRole: auth.RoleAdmin,
			},
			wantErr: true,
		},
		{
			name:    "unauthenticated denied",
			user:    &auth.UserSession{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := h.checkOperatePermission(tt.user, cluster, "enable GitOps on")
			if (err != nil) != tt.wantErr {
				t.Errorf("checkOperatePermission() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckTemplatePermission(t *testing.T) {
	tests := []struct {
		name      string
		user      *auth.UserSession
		namespace string
		wantErr   bool
	}{
		{
			name:      "admin can modify cluster-scoped templates",
			user:      &auth.UserSession{PlatformRole: auth.RoleAdmin},
			namespace: "butler-system",
		},
		{
			name:      "viewer cannot modify cluster-scoped templates",
			user:      &auth.UserSession{PlatformRole: auth.RoleViewer},
			namespace: "butler-system",
			wantErr:   true,
		},
		{
			name:      "non-admin cannot modify cluster-scoped templates",
			user:      &auth.UserSession{},
			namespace: "butler-system",
			wantErr:   true,
		},
		{
			name: "team operator can modify team templates",
			user: &auth.UserSession{
				Teams: []auth.TeamMembership{{Name: "alpha", Role: auth.RoleOperator}},
			},
			namespace: "team-alpha",
		},
		{
			name: "team admin can modify team templates",
			user: &auth.UserSession{
				Teams: []auth.TeamMembership{{Name: "alpha", Role: auth.RoleAdmin}},
			},
			namespace: "team-alpha",
		},
		{
			name: "team viewer cannot modify team templates",
			user: &auth.UserSession{
				Teams: []auth.TeamMembership{{Name: "alpha", Role: auth.RoleViewer}},
			},
			namespace: "team-alpha",
			wantErr:   true,
		},
		{
			name:      "platform admin can modify any team templates",
			user:      &auth.UserSession{PlatformRole: auth.RoleAdmin},
			namespace: "team-alpha",
		},
		{
			name:      "platform viewer cannot modify team templates",
			user:      &auth.UserSession{PlatformRole: auth.RoleViewer},
			namespace: "team-alpha",
			wantErr:   true,
		},
		{
			name: "wrong team denied",
			user: &auth.UserSession{
				Teams: []auth.TeamMembership{{Name: "beta", Role: auth.RoleAdmin}},
			},
			namespace: "team-alpha",
			wantErr:   true,
		},
		{
			name:      "unknown namespace requires admin",
			user:      &auth.UserSession{PlatformRole: auth.RoleAdmin},
			namespace: "custom-ns",
		},
		{
			name:      "unknown namespace denied for non-admin",
			user:      &auth.UserSession{},
			namespace: "custom-ns",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkTemplatePermission(tt.user, tt.namespace)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkTemplatePermission(%q) error = %v, wantErr %v", tt.namespace, err, tt.wantErr)
			}
		})
	}
}
