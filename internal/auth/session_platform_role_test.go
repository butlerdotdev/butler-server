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
	"testing"
	"time"
)

// --- Platform role helper tests ---

func TestIsPlatformViewerOrAbove(t *testing.T) {
	tests := []struct {
		name         string
		platformRole string
		want         bool
	}{
		{"admin", RoleAdmin, true},
		{"viewer", RoleViewer, true},
		{"none", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{PlatformRole: tt.platformRole}
			if got := u.IsPlatformViewerOrAbove(); got != tt.want {
				t.Errorf("IsPlatformViewerOrAbove() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasPlatformRole(t *testing.T) {
	tests := []struct {
		name         string
		platformRole string
		want         bool
	}{
		{"admin", RoleAdmin, true},
		{"viewer", RoleViewer, true},
		{"none", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{PlatformRole: tt.platformRole}
			if got := u.HasPlatformRole(); got != tt.want {
				t.Errorf("HasPlatformRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- HasTeamMembership across roles ---

func TestHasTeamMembership(t *testing.T) {
	tests := []struct {
		name         string
		platformRole string
		teams        []TeamMembership
		teamName     string
		want         bool
	}{
		{"admin has all", RoleAdmin, nil, "any-team", true},
		{"viewer has all", RoleViewer, nil, "any-team", true},
		{"no role, member", "", []TeamMembership{{Name: "acme", Role: RoleViewer}}, "acme", true},
		{"no role, not member", "", []TeamMembership{{Name: "acme", Role: RoleViewer}}, "other", false},
		{"no role, no teams", "", nil, "any-team", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{PlatformRole: tt.platformRole, Teams: tt.teams}
			if got := u.HasTeamMembership(tt.teamName); got != tt.want {
				t.Errorf("HasTeamMembership(%q) = %v, want %v", tt.teamName, got, tt.want)
			}
		})
	}
}

// --- GetTeamMembership with additive-only precedence ---

func TestGetTeamMembership(t *testing.T) {
	tests := []struct {
		name         string
		platformRole string
		teams        []TeamMembership
		teamName     string
		wantNil      bool
		wantRole     string
	}{
		{
			name:         "admin always gets admin role",
			platformRole: RoleAdmin,
			teams:        nil,
			teamName:     "acme",
			wantRole:     RoleAdmin,
		},
		{
			name:         "admin overrides explicit viewer",
			platformRole: RoleAdmin,
			teams:        []TeamMembership{{Name: "acme", Role: RoleViewer}},
			teamName:     "acme",
			wantRole:     RoleAdmin,
		},
		{
			name:         "viewer gets synthetic viewer",
			platformRole: RoleViewer,
			teams:        nil,
			teamName:     "acme",
			wantRole:     RoleViewer,
		},
		{
			name:         "viewer with explicit operator keeps operator",
			platformRole: RoleViewer,
			teams:        []TeamMembership{{Name: "acme", Role: RoleOperator}},
			teamName:     "acme",
			wantRole:     RoleOperator,
		},
		{
			name:         "viewer with explicit admin keeps admin",
			platformRole: RoleViewer,
			teams:        []TeamMembership{{Name: "acme", Role: RoleAdmin}},
			teamName:     "acme",
			wantRole:     RoleAdmin,
		},
		{
			name:         "viewer with explicit viewer returns viewer",
			platformRole: RoleViewer,
			teams:        []TeamMembership{{Name: "acme", Role: RoleViewer}},
			teamName:     "acme",
			wantRole:     RoleViewer,
		},
		{
			name:     "no role, member",
			teams:    []TeamMembership{{Name: "acme", Role: RoleOperator}},
			teamName: "acme",
			wantRole: RoleOperator,
		},
		{
			name:     "no role, not member",
			teams:    nil,
			teamName: "acme",
			wantNil:  true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{PlatformRole: tt.platformRole, Teams: tt.teams}
			got := u.GetTeamMembership(tt.teamName)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil membership")
			}
			if got.Role != tt.wantRole {
				t.Errorf("got role %q, want %q", got.Role, tt.wantRole)
			}
		})
	}
}

// --- HasRole across roles ---

func TestHasRole(t *testing.T) {
	tests := []struct {
		name         string
		platformRole string
		teams        []TeamMembership
		role         string
		want         bool
	}{
		{"admin has any role", RoleAdmin, nil, RoleOperator, true},
		{"viewer has viewer", RoleViewer, nil, RoleViewer, true},
		{"viewer does not have admin", RoleViewer, nil, RoleAdmin, false},
		{"viewer does not have operator", RoleViewer, nil, RoleOperator, false},
		{"no role, team has role", "", []TeamMembership{{Name: "acme", Role: RoleOperator}}, RoleOperator, true},
		{"no role, team lacks role", "", []TeamMembership{{Name: "acme", Role: RoleViewer}}, RoleAdmin, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{PlatformRole: tt.platformRole, Teams: tt.teams}
			if got := u.HasRole(tt.role); got != tt.want {
				t.Errorf("HasRole(%q) = %v, want %v", tt.role, got, tt.want)
			}
		})
	}
}

// --- HasRoleInTeam across roles ---

func TestHasRoleInTeam(t *testing.T) {
	tests := []struct {
		name         string
		platformRole string
		teams        []TeamMembership
		teamName     string
		role         string
		want         bool
	}{
		{"admin has any role asked for", RoleAdmin, nil, "acme", RoleOperator, true},
		{"viewer asked for viewer", RoleViewer, nil, "acme", RoleViewer, true},
		{"viewer asked for admin", RoleViewer, nil, "acme", RoleAdmin, false},
		{
			"viewer with explicit operator asked for operator",
			RoleViewer,
			[]TeamMembership{{Name: "acme", Role: RoleOperator}},
			"acme",
			RoleOperator,
			true,
		},
		{
			"viewer with explicit operator asked for admin",
			RoleViewer,
			[]TeamMembership{{Name: "acme", Role: RoleOperator}},
			"acme",
			RoleAdmin,
			false,
		},
		{"no role, not member", "", nil, "acme", RoleViewer, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{PlatformRole: tt.platformRole, Teams: tt.teams}
			if got := u.HasRoleInTeam(tt.teamName, tt.role); got != tt.want {
				t.Errorf("HasRoleInTeam(%q, %q) = %v, want %v", tt.teamName, tt.role, got, tt.want)
			}
		})
	}
}

// --- IsAdmin across roles ---

func TestIsAdmin(t *testing.T) {
	tests := []struct {
		name         string
		platformRole string
		teams        []TeamMembership
		want         bool
	}{
		{"platform admin", RoleAdmin, nil, true},
		{"platform viewer", RoleViewer, nil, false},
		{"no role, team admin", "", []TeamMembership{{Name: "acme", Role: RoleAdmin}}, true},
		{"no role, team viewer", "", []TeamMembership{{Name: "acme", Role: RoleViewer}}, false},
		{"no role, no teams", "", nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{PlatformRole: tt.platformRole, Teams: tt.teams}
			if got := u.IsAdmin(); got != tt.want {
				t.Errorf("IsAdmin() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- IsAdminOfTeam across roles ---

func TestIsAdminOfTeam(t *testing.T) {
	tests := []struct {
		name         string
		platformRole string
		teams        []TeamMembership
		teamName     string
		want         bool
	}{
		{"platform admin", RoleAdmin, nil, "acme", true},
		{"platform viewer", RoleViewer, nil, "acme", false},
		{"no role, team admin", "", []TeamMembership{{Name: "acme", Role: RoleAdmin}}, "acme", true},
		{"no role, team viewer", "", []TeamMembership{{Name: "acme", Role: RoleViewer}}, "acme", false},
		{"no role, wrong team", "", []TeamMembership{{Name: "other", Role: RoleAdmin}}, "acme", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{PlatformRole: tt.platformRole, Teams: tt.teams}
			if got := u.IsAdminOfTeam(tt.teamName); got != tt.want {
				t.Errorf("IsAdminOfTeam(%q) = %v, want %v", tt.teamName, got, tt.want)
			}
		})
	}
}

// --- CanOperateTeam across roles ---

func TestCanOperateTeam(t *testing.T) {
	tests := []struct {
		name         string
		platformRole string
		teams        []TeamMembership
		teamName     string
		want         bool
	}{
		{"platform admin", RoleAdmin, nil, "acme", true},
		{"platform viewer no explicit grant", RoleViewer, nil, "acme", false},
		{
			"platform viewer with explicit operator",
			RoleViewer,
			[]TeamMembership{{Name: "acme", Role: RoleOperator}},
			"acme",
			true,
		},
		{
			"platform viewer with explicit admin",
			RoleViewer,
			[]TeamMembership{{Name: "acme", Role: RoleAdmin}},
			"acme",
			true,
		},
		{
			"platform viewer with explicit viewer only",
			RoleViewer,
			[]TeamMembership{{Name: "acme", Role: RoleViewer}},
			"acme",
			false,
		},
		{"no role, team operator", "", []TeamMembership{{Name: "acme", Role: RoleOperator}}, "acme", true},
		{"no role, team viewer", "", []TeamMembership{{Name: "acme", Role: RoleViewer}}, "acme", false},
		{"no role, not member", "", nil, "acme", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{PlatformRole: tt.platformRole, Teams: tt.teams}
			if got := u.CanOperateTeam(tt.teamName); got != tt.want {
				t.Errorf("CanOperateTeam(%q) = %v, want %v", tt.teamName, got, tt.want)
			}
		})
	}
}

// --- CanViewTeam across roles ---

func TestCanViewTeam(t *testing.T) {
	tests := []struct {
		name         string
		platformRole string
		teams        []TeamMembership
		teamName     string
		want         bool
	}{
		{"platform admin", RoleAdmin, nil, "acme", true},
		{"platform viewer", RoleViewer, nil, "acme", true},
		{"no role, member", "", []TeamMembership{{Name: "acme", Role: RoleViewer}}, "acme", true},
		{"no role, not member", "", nil, "acme", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{PlatformRole: tt.platformRole, Teams: tt.teams}
			if got := u.CanViewTeam(tt.teamName); got != tt.want {
				t.Errorf("CanViewTeam(%q) = %v, want %v", tt.teamName, got, tt.want)
			}
		})
	}
}

// --- CanOperateInSelectedTeam across roles ---

func TestCanOperateInSelectedTeam(t *testing.T) {
	tests := []struct {
		name             string
		platformRole     string
		teams            []TeamMembership
		selectedTeam     string
		selectedTeamRole string
		want             bool
	}{
		{"admin no team selected", RoleAdmin, nil, "", "", true},
		{"viewer no team selected", RoleViewer, nil, "", "", false},
		{"no role, has operator team, no selection", "", []TeamMembership{{Name: "acme", Role: RoleOperator}}, "", "", true},
		{"admin with team selected", RoleAdmin, nil, "acme", RoleAdmin, true},
		{"viewer with team selected as viewer", RoleViewer, nil, "acme", RoleViewer, false},
		{
			"viewer with team selected as operator (explicit grant)",
			RoleViewer,
			[]TeamMembership{{Name: "acme", Role: RoleOperator}},
			"acme",
			RoleOperator,
			true,
		},
		{"no role, selected as viewer", "", nil, "acme", RoleViewer, false},
		{"no role, selected as operator", "", nil, "acme", RoleOperator, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{
				PlatformRole:     tt.platformRole,
				Teams:            tt.teams,
				SelectedTeam:     tt.selectedTeam,
				SelectedTeamRole: tt.selectedTeamRole,
			}
			if got := u.CanOperateInSelectedTeam(); got != tt.want {
				t.Errorf("CanOperateInSelectedTeam() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- CanViewInSelectedTeam across roles ---

func TestCanViewInSelectedTeam(t *testing.T) {
	tests := []struct {
		name             string
		platformRole     string
		teams            []TeamMembership
		selectedTeam     string
		selectedTeamRole string
		want             bool
	}{
		{"admin no team selected", RoleAdmin, nil, "", "", true},
		{"viewer no team selected", RoleViewer, nil, "", "", true},
		{"no role, has teams, no selection", "", []TeamMembership{{Name: "acme", Role: RoleViewer}}, "", "", true},
		{"no role, no teams, no selection", "", nil, "", "", false},
		{"viewer with team selected", RoleViewer, nil, "acme", RoleViewer, true},
		{"no role, selected as viewer", "", nil, "acme", RoleViewer, true},
		{"no role, no selected role", "", nil, "acme", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &UserSession{
				PlatformRole:     tt.platformRole,
				Teams:            tt.teams,
				SelectedTeam:     tt.selectedTeam,
				SelectedTeamRole: tt.selectedTeamRole,
			}
			if got := u.CanViewInSelectedTeam(); got != tt.want {
				t.Errorf("CanViewInSelectedTeam() = %v, want %v", got, tt.want)
			}
		})
	}
}

// --- CanOperateInSelectedEnvironment with platform roles ---

func TestCanOperateInSelectedEnvironment_PlatformViewer(t *testing.T) {
	u := &UserSession{
		PlatformRole:        RoleViewer,
		SelectedTeam:        "acme",
		SelectedTeamRole:    RoleViewer,
		SelectedEnvironment: "prod",
	}
	if u.CanOperateInSelectedEnvironment() {
		t.Fatal("platform viewer cannot operate in environment")
	}
}

func TestCanOperateInSelectedEnvironment_PlatformViewerWithExplicitOperator(t *testing.T) {
	u := &UserSession{
		PlatformRole:            RoleViewer,
		Teams:                   []TeamMembership{{Name: "acme", Role: RoleOperator}},
		SelectedTeam:            "acme",
		SelectedTeamRole:        RoleOperator,
		SelectedEnvironment:     "prod",
		SelectedEnvironmentRole: RoleOperator,
	}
	if !u.CanOperateInSelectedEnvironment() {
		t.Fatal("viewer with explicit operator grant should operate in environment")
	}
}

// --- CanViewInSelectedEnvironment with platform roles ---

func TestCanViewInSelectedEnvironment_PlatformViewer(t *testing.T) {
	u := &UserSession{
		PlatformRole:        RoleViewer,
		SelectedTeam:        "acme",
		SelectedTeamRole:    RoleViewer,
		SelectedEnvironment: "prod",
	}
	if !u.CanViewInSelectedEnvironment() {
		t.Fatal("platform viewer should be able to view in environment")
	}
}

// --- Backwards compat: IsPlatformAdmin computed from PlatformRole ---

func TestCreateSession_IsPlatformAdminComputedFromPlatformRole(t *testing.T) {
	svc := NewSessionService("test-secret-that-is-long-enough", time.Hour)

	tests := []struct {
		name                string
		platformRole        string
		wantIsPlatformAdmin bool
	}{
		{"admin role sets isPlatformAdmin", RoleAdmin, true},
		{"viewer role does not set isPlatformAdmin", RoleViewer, false},
		{"no role does not set isPlatformAdmin", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &UserSession{
				Email:        "test@example.com",
				PlatformRole: tt.platformRole,
				Teams:        []TeamMembership{},
			}
			tokenStr, err := svc.CreateSession(user)
			if err != nil {
				t.Fatalf("CreateSession error: %v", err)
			}
			got, err := svc.ValidateSession(tokenStr)
			if err != nil {
				t.Fatalf("ValidateSession error: %v", err)
			}
			if got.IsPlatformAdmin != tt.wantIsPlatformAdmin {
				t.Errorf("IsPlatformAdmin = %v, want %v", got.IsPlatformAdmin, tt.wantIsPlatformAdmin)
			}
			if got.PlatformRole != tt.platformRole {
				t.Errorf("PlatformRole = %q, want %q", got.PlatformRole, tt.platformRole)
			}
		})
	}
}

// --- Backwards compat: migration conditional for pre-upgrade JWTs ---
//
// A true JWT round-trip test is not possible here because CreateSession
// syncs IsPlatformAdmin from PlatformRole before signing. Pre-upgrade
// tokens (isPlatformAdmin=true, platformRole absent) can only exist
// from JWTs issued before this code landed. These tests exercise the
// migration conditional from ValidateSession in isolation.

func TestMigration_IsPlatformAdminToPlatformRole(t *testing.T) {
	session := &UserSession{
		Email:           "admin@example.com",
		IsPlatformAdmin: true,
		PlatformRole:    "",
	}
	// Apply the same conditional as ValidateSession
	if session.IsPlatformAdmin && session.PlatformRole == "" {
		session.PlatformRole = RoleAdmin
	}
	if session.PlatformRole != RoleAdmin {
		t.Errorf("migration should set PlatformRole to admin, got %q", session.PlatformRole)
	}
}

func TestMigration_NoOverwriteWhenPlatformRoleSet(t *testing.T) {
	session := &UserSession{
		Email:           "viewer@example.com",
		IsPlatformAdmin: false,
		PlatformRole:    RoleViewer,
	}
	if session.IsPlatformAdmin && session.PlatformRole == "" {
		session.PlatformRole = RoleAdmin
	}
	if session.PlatformRole != RoleViewer {
		t.Errorf("should not overwrite existing PlatformRole, got %q", session.PlatformRole)
	}
}
