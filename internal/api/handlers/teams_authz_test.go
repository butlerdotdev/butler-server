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
	"net/http"
	"testing"

	"github.com/butlerdotdev/butler-server/internal/auth"
)

func platformAdmin() *auth.UserSession {
	return &auth.UserSession{Email: "root@example.com", PlatformRole: auth.RoleAdmin}
}

func platformViewer() *auth.UserSession {
	return &auth.UserSession{Email: "viewer@example.com", PlatformRole: auth.RoleViewer}
}

func teamMember(team, role string) *auth.UserSession {
	return &auth.UserSession{
		Email: role + "@example.com",
		Teams: []auth.TeamMembership{{Name: team, Role: role}},
	}
}

func TestAuthorizeTeamCreate(t *testing.T) {
	tests := []struct {
		name string
		user *auth.UserSession
		want int
	}{
		{"nil session", nil, http.StatusUnauthorized},
		{"platform admin", platformAdmin(), 0},
		{"platform viewer", platformViewer(), http.StatusForbidden},
		{"team admin of another team", teamMember("alpha", auth.RoleAdmin), http.StatusForbidden},
		{"team viewer", teamMember("alpha", auth.RoleViewer), http.StatusForbidden},
		{"no memberships", &auth.UserSession{Email: "nobody@example.com"}, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := authorizeTeamCreate(tt.user); got != tt.want {
				t.Fatalf("authorizeTeamCreate = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAuthorizeTeamUpdate(t *testing.T) {
	limits := &UpdateTeamRequest{ResourceLimits: map[string]interface{}{"maxClusters": 3}}
	rename := &UpdateTeamRequest{DisplayName: "Renamed"}
	tests := []struct {
		name string
		user *auth.UserSession
		team string
		req  *UpdateTeamRequest
		want int
	}{
		{"nil session", nil, "alpha", rename, http.StatusUnauthorized},
		{"platform admin rename", platformAdmin(), "alpha", rename, 0},
		{"platform admin limits", platformAdmin(), "alpha", limits, 0},
		{"platform viewer rename", platformViewer(), "alpha", rename, http.StatusForbidden},
		{"team admin rename own team", teamMember("alpha", auth.RoleAdmin), "alpha", rename, 0},
		{"team admin nil body", teamMember("alpha", auth.RoleAdmin), "alpha", nil, 0},
		{"team admin limits own team", teamMember("alpha", auth.RoleAdmin), "alpha", limits, http.StatusForbidden},
		{"team admin other team", teamMember("alpha", auth.RoleAdmin), "beta", rename, http.StatusForbidden},
		{"team operator own team", teamMember("alpha", auth.RoleOperator), "alpha", rename, http.StatusForbidden},
		{"team viewer own team", teamMember("alpha", auth.RoleViewer), "alpha", rename, http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := authorizeTeamUpdate(tt.user, tt.team, tt.req); got != tt.want {
				t.Fatalf("authorizeTeamUpdate = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestAuthorizeTeamDelete(t *testing.T) {
	tests := []struct {
		name string
		user *auth.UserSession
		want int
	}{
		{"nil session", nil, http.StatusUnauthorized},
		{"platform admin", platformAdmin(), 0},
		{"platform viewer", platformViewer(), http.StatusForbidden},
		{"team admin", teamMember("alpha", auth.RoleAdmin), http.StatusForbidden},
		{"team operator", teamMember("alpha", auth.RoleOperator), http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := authorizeTeamDelete(tt.user); got != tt.want {
				t.Fatalf("authorizeTeamDelete = %d, want %d", got, tt.want)
			}
		})
	}
}
