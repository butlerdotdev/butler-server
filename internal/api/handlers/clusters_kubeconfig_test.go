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
)

func TestCheckKubeconfigAccess(t *testing.T) {
	member := func(role string) *auth.UserSession {
		return &auth.UserSession{Teams: []auth.TeamMembership{{Name: "alpha", Role: role}}}
	}
	scoped := func(role string) *auth.UserSession {
		u := member(role)
		u.SelectedTeam = "alpha"
		u.SelectedTeamRole = role
		return u
	}
	tests := []struct {
		name    string
		user    *auth.UserSession
		team    string
		wantErr bool
	}{
		{"platform admin", &auth.UserSession{PlatformRole: auth.RoleAdmin}, "alpha", false},
		{"platform admin team-less cluster", &auth.UserSession{PlatformRole: auth.RoleAdmin}, "", false},
		{"platform viewer no grant", &auth.UserSession{PlatformRole: auth.RoleViewer}, "alpha", true},
		{"platform viewer with operator grant", &auth.UserSession{PlatformRole: auth.RoleViewer, Teams: []auth.TeamMembership{{Name: "alpha", Role: auth.RoleOperator}}}, "alpha", false},
		{"team admin", member(auth.RoleAdmin), "alpha", false},
		{"team operator", member(auth.RoleOperator), "alpha", false},
		{"team viewer", member(auth.RoleViewer), "alpha", true},
		{"member of other team", member(auth.RoleAdmin), "beta", true},
		{"non-admin team-less cluster", member(auth.RoleAdmin), "", true},
		{"scoped operator", scoped(auth.RoleOperator), "alpha", false},
		{"scoped viewer", scoped(auth.RoleViewer), "alpha", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkKubeconfigAccess(tt.user, tt.team)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkKubeconfigAccess error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
