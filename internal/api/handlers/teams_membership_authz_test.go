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

func TestAuthorizeTeamMembershipChange(t *testing.T) {
	adminOfAlpha := &auth.UserSession{
		Email: "alpha-admin@example.com",
		Teams: []auth.TeamMembership{{Name: "alpha", Role: auth.RoleAdmin}},
	}
	viewerOfAlphaAdminOfBeta := &auth.UserSession{
		Email: "mixed@example.com",
		Teams: []auth.TeamMembership{
			{Name: "alpha", Role: auth.RoleViewer},
			{Name: "beta", Role: auth.RoleAdmin},
		},
	}
	tests := []struct {
		name string
		user *auth.UserSession
		team string
		want int
	}{
		{"nil session", nil, "alpha", http.StatusUnauthorized},
		{"platform admin any team", &auth.UserSession{PlatformRole: auth.RoleAdmin}, "zeta", 0},
		{"platform viewer", &auth.UserSession{PlatformRole: auth.RoleViewer}, "alpha", http.StatusForbidden},
		{"team admin own team", adminOfAlpha, "alpha", 0},
		{"team admin other team", adminOfAlpha, "beta", http.StatusForbidden},
		{"admin of beta editing alpha where viewer", viewerOfAlphaAdminOfBeta, "alpha", http.StatusForbidden},
		{"admin of beta editing beta", viewerOfAlphaAdminOfBeta, "beta", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, _ := authorizeTeamMembershipChange(tt.user, tt.team); got != tt.want {
				t.Fatalf("authorizeTeamMembershipChange = %d, want %d", got, tt.want)
			}
		})
	}
}
