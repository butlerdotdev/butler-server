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

import "testing"

func TestResolvePlatformRole(t *testing.T) {
	tests := []struct {
		name               string
		userGroups         []string
		platformRoleGroups []PlatformRoleGroupEntry
		want               string
	}{
		{
			name:       "no groups, no config",
			userGroups: nil,
			want:       "",
		},
		{
			name:               "groups but no config",
			userGroups:         []string{"butler-admins"},
			platformRoleGroups: nil,
			want:               "",
		},
		{
			name:               "no groups, has config",
			userGroups:         nil,
			platformRoleGroups: []PlatformRoleGroupEntry{{Name: "butler-admins", Role: RoleAdmin}},
			want:               "",
		},
		{
			name:       "exact match admin",
			userGroups: []string{"butler-admins"},
			platformRoleGroups: []PlatformRoleGroupEntry{
				{Name: "butler-admins", Role: RoleAdmin},
			},
			want: RoleAdmin,
		},
		{
			name:       "exact match viewer",
			userGroups: []string{"butler-readers"},
			platformRoleGroups: []PlatformRoleGroupEntry{
				{Name: "butler-readers", Role: RoleViewer},
			},
			want: RoleViewer,
		},
		{
			name:       "case insensitive match",
			userGroups: []string{"Butler-Admins"},
			platformRoleGroups: []PlatformRoleGroupEntry{
				{Name: "butler-admins", Role: RoleAdmin},
			},
			want: RoleAdmin,
		},
		{
			name:       "email-style group stripped to match plain config",
			userGroups: []string{"butler-admins@example.com"},
			platformRoleGroups: []PlatformRoleGroupEntry{
				{Name: "butler-admins", Role: RoleAdmin},
			},
			want: RoleAdmin,
		},
		{
			name:       "email-style config matched against email-style group",
			userGroups: []string{"butler-admins@example.com"},
			platformRoleGroups: []PlatformRoleGroupEntry{
				{Name: "butler-admins@example.com", Role: RoleAdmin},
			},
			want: RoleAdmin,
		},
		{
			name:       "LDAP DN group matched against plain config",
			userGroups: []string{"CN=Butler-Admins,OU=Groups,DC=corp,DC=example,DC=com"},
			platformRoleGroups: []PlatformRoleGroupEntry{
				{Name: "butler-admins", Role: RoleAdmin},
			},
			want: RoleAdmin,
		},
		{
			name:       "multiple groups, highest wins",
			userGroups: []string{"butler-viewers", "butler-admins"},
			platformRoleGroups: []PlatformRoleGroupEntry{
				{Name: "butler-viewers", Role: RoleViewer},
				{Name: "butler-admins", Role: RoleAdmin},
			},
			want: RoleAdmin,
		},
		{
			name:       "user in viewer group only",
			userGroups: []string{"butler-viewers", "some-other-group"},
			platformRoleGroups: []PlatformRoleGroupEntry{
				{Name: "butler-viewers", Role: RoleViewer},
				{Name: "butler-admins", Role: RoleAdmin},
			},
			want: RoleViewer,
		},
		{
			name:       "no matching groups",
			userGroups: []string{"unrelated-group"},
			platformRoleGroups: []PlatformRoleGroupEntry{
				{Name: "butler-admins", Role: RoleAdmin},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolvePlatformRole(tt.userGroups, tt.platformRoleGroups)
			if got != tt.want {
				t.Errorf("ResolvePlatformRole() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestEffectivePlatformRole(t *testing.T) {
	tests := []struct {
		name            string
		crdPlatformRole string
		isPlatformAdmin bool
		groupRole       string
		want            string
	}{
		{
			name: "all empty",
			want: "",
		},
		{
			name:            "CRD admin",
			crdPlatformRole: RoleAdmin,
			want:            RoleAdmin,
		},
		{
			name:            "CRD viewer",
			crdPlatformRole: RoleViewer,
			want:            RoleViewer,
		},
		{
			name:            "deprecated isPlatformAdmin",
			isPlatformAdmin: true,
			want:            RoleAdmin,
		},
		{
			name:      "group role admin",
			groupRole: RoleAdmin,
			want:      RoleAdmin,
		},
		{
			name:      "group role viewer",
			groupRole: RoleViewer,
			want:      RoleViewer,
		},
		{
			name:            "CRD viewer + isPlatformAdmin = admin wins",
			crdPlatformRole: RoleViewer,
			isPlatformAdmin: true,
			want:            RoleAdmin,
		},
		{
			name:            "CRD viewer + group admin = admin wins",
			crdPlatformRole: RoleViewer,
			groupRole:       RoleAdmin,
			want:            RoleAdmin,
		},
		{
			name:            "all three set, admin from isPlatformAdmin",
			crdPlatformRole: RoleViewer,
			isPlatformAdmin: true,
			groupRole:       RoleViewer,
			want:            RoleAdmin,
		},
		{
			name:            "CRD admin + group viewer = admin wins",
			crdPlatformRole: RoleAdmin,
			groupRole:       RoleViewer,
			want:            RoleAdmin,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EffectivePlatformRole(tt.crdPlatformRole, tt.isPlatformAdmin, tt.groupRole)
			if got != tt.want {
				t.Errorf("EffectivePlatformRole(%q, %v, %q) = %q, want %q",
					tt.crdPlatformRole, tt.isPlatformAdmin, tt.groupRole, got, tt.want)
			}
		})
	}
}

// TestEffectivePlatformRole_LoginScenarios tests the full effective role
// computation that happens at session creation in the OIDC callback.
// Each case mirrors a real login scenario described in ADR-014.
func TestEffectivePlatformRole_LoginScenarios(t *testing.T) {
	entraAdminGroup := []PlatformRoleGroupEntry{
		{Name: "butler-platform-admin", Role: RoleAdmin},
		{Name: "butler-platform-viewers", Role: RoleViewer},
	}

	tests := []struct {
		name               string
		userGroups         []string
		platformRoleGroups []PlatformRoleGroupEntry
		crdPlatformRole    string
		crdIsPlatformAdmin bool
		want               string
	}{
		{
			name:               "admin group yields admin session",
			userGroups:         []string{"butler-platform-admin"},
			platformRoleGroups: entraAdminGroup,
			want:               RoleAdmin,
		},
		{
			name:               "viewer group yields viewer session",
			userGroups:         []string{"butler-platform-viewers"},
			platformRoleGroups: entraAdminGroup,
			want:               RoleViewer,
		},
		{
			name:               "both groups - admin wins (highest role)",
			userGroups:         []string{"butler-platform-admin", "butler-platform-viewers"},
			platformRoleGroups: entraAdminGroup,
			want:               RoleAdmin,
		},
		{
			name:               "no platform group + isPlatformAdmin on CRD - admin (backwards compat)",
			userGroups:         []string{"unrelated-team-group"},
			platformRoleGroups: entraAdminGroup,
			crdIsPlatformAdmin: true,
			want:               RoleAdmin,
		},
		{
			name:               "no platform group + platformRole viewer on CRD - viewer",
			userGroups:         []string{"unrelated-team-group"},
			platformRoleGroups: entraAdminGroup,
			crdPlatformRole:    RoleViewer,
			want:               RoleViewer,
		},
		{
			name:               "no group match, no CRD role - empty",
			userGroups:         []string{"unrelated-team-group"},
			platformRoleGroups: entraAdminGroup,
			want:               "",
		},
		{
			name:               "CRD viewer + group admin - admin wins",
			userGroups:         []string{"butler-platform-admin"},
			platformRoleGroups: entraAdminGroup,
			crdPlatformRole:    RoleViewer,
			want:               RoleAdmin,
		},
		{
			name:               "CRD admin + group viewer - admin wins",
			userGroups:         []string{"butler-platform-viewers"},
			platformRoleGroups: entraAdminGroup,
			crdPlatformRole:    RoleAdmin,
			want:               RoleAdmin,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groupRole := ResolvePlatformRole(tt.userGroups, tt.platformRoleGroups)
			got := EffectivePlatformRole(tt.crdPlatformRole, tt.crdIsPlatformAdmin, groupRole)
			if got != tt.want {
				t.Errorf("effective role = %q, want %q (groupRole=%q)", got, tt.want, groupRole)
			}
		})
	}
}

// TestResolvePlatformRole_PerIdPSeparation verifies that ResolvePlatformRole
// produces correct results when called with separate per-IdP group lists.
// Each IdP has its own platformRoleGroups config; a user in Entra's
// "butler-platform-admin" group does not match Google's config and vice versa.
// Note: this tests function-level behavior. System-level multi-IdP isolation
// requires per-provider loading when butler-server gains multi-IdP support.
func TestResolvePlatformRole_PerIdPSeparation(t *testing.T) {
	entraGroups := []PlatformRoleGroupEntry{
		{Name: "butler-platform-admin", Role: RoleAdmin},
	}
	googleGroups := []PlatformRoleGroupEntry{
		{Name: "butler-admins@example.com", Role: RoleAdmin},
	}

	// User is in the Entra admin group
	userGroups := []string{"butler-platform-admin"}

	// Resolving against Entra config should match
	entraRole := ResolvePlatformRole(userGroups, entraGroups)
	if entraRole != RoleAdmin {
		t.Errorf("Entra resolution = %q, want admin", entraRole)
	}

	// Resolving against Google config should NOT match
	googleRole := ResolvePlatformRole(userGroups, googleGroups)
	if googleRole != "" {
		t.Errorf("Google resolution = %q, want empty (isolation violated)", googleRole)
	}

	// Reverse: user in Google admin group should not match Entra config
	googleUser := []string{"butler-admins@example.com"}
	entraRoleForGoogleUser := ResolvePlatformRole(googleUser, entraGroups)
	if entraRoleForGoogleUser != "" {
		t.Errorf("Entra resolution for Google user = %q, want empty", entraRoleForGoogleUser)
	}
	googleRoleForGoogleUser := ResolvePlatformRole(googleUser, googleGroups)
	if googleRoleForGoogleUser != RoleAdmin {
		t.Errorf("Google resolution for Google user = %q, want admin", googleRoleForGoogleUser)
	}
}

// TestRefreshPermissions_RoleChange tests the pattern used in RefreshPermissions:
// re-evaluating group membership yields an updated role when group membership
// changes between login and refresh.
func TestRefreshPermissions_RoleChange(t *testing.T) {
	platformRoleGroups := []PlatformRoleGroupEntry{
		{Name: "butler-platform-admin", Role: RoleAdmin},
		{Name: "butler-platform-viewers", Role: RoleViewer},
	}

	tests := []struct {
		name            string
		groupsAtLogin   []string
		groupsAtRefresh []string
		crdPlatformRole string
		crdIsPlatformAdmin bool
		wantAtLogin     string
		wantAtRefresh   string
	}{
		{
			name:            "user removed from admin group - role downgraded",
			groupsAtLogin:   []string{"butler-platform-admin"},
			groupsAtRefresh: []string{"unrelated-group"},
			wantAtLogin:     RoleAdmin,
			wantAtRefresh:   "",
		},
		{
			name:            "user added to viewer group - role upgraded",
			groupsAtLogin:   []string{"unrelated-group"},
			groupsAtRefresh: []string{"butler-platform-viewers"},
			wantAtLogin:     "",
			wantAtRefresh:   RoleViewer,
		},
		{
			name:            "user upgraded from viewer to admin group",
			groupsAtLogin:   []string{"butler-platform-viewers"},
			groupsAtRefresh: []string{"butler-platform-admin"},
			wantAtLogin:     RoleViewer,
			wantAtRefresh:   RoleAdmin,
		},
		{
			name:            "user downgraded from admin to viewer group",
			groupsAtLogin:   []string{"butler-platform-admin"},
			groupsAtRefresh: []string{"butler-platform-viewers"},
			wantAtLogin:     RoleAdmin,
			wantAtRefresh:   RoleViewer,
		},
		{
			name:               "CRD admin preserved even if removed from group",
			groupsAtLogin:      []string{"butler-platform-admin"},
			groupsAtRefresh:    []string{"unrelated-group"},
			crdIsPlatformAdmin: true,
			wantAtLogin:        RoleAdmin,
			wantAtRefresh:      RoleAdmin, // CRD override stays
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate login
			loginGroupRole := ResolvePlatformRole(tt.groupsAtLogin, platformRoleGroups)
			loginEffective := EffectivePlatformRole(tt.crdPlatformRole, tt.crdIsPlatformAdmin, loginGroupRole)
			if loginEffective != tt.wantAtLogin {
				t.Errorf("at login: effective = %q, want %q", loginEffective, tt.wantAtLogin)
			}

			// Simulate refresh with changed groups
			refreshGroupRole := ResolvePlatformRole(tt.groupsAtRefresh, platformRoleGroups)
			refreshEffective := EffectivePlatformRole(tt.crdPlatformRole, tt.crdIsPlatformAdmin, refreshGroupRole)
			if refreshEffective != tt.wantAtRefresh {
				t.Errorf("at refresh: effective = %q, want %q", refreshEffective, tt.wantAtRefresh)
			}
		})
	}
}

func TestMatchGroup(t *testing.T) {
	tests := []struct {
		name            string
		configuredGroup string
		userGroups      []string
		want            bool
	}{
		{
			name:            "exact match",
			configuredGroup: "butler-admins",
			userGroups:      []string{"butler-admins"},
			want:            true,
		},
		{
			name:            "case insensitive",
			configuredGroup: "Butler-Admins",
			userGroups:      []string{"butler-admins"},
			want:            true,
		},
		{
			name:            "email-style user group, plain config",
			configuredGroup: "butler-admins",
			userGroups:      []string{"butler-admins@example.com"},
			want:            true,
		},
		{
			name:            "LDAP DN user group, plain config",
			configuredGroup: "butler-admins",
			userGroups:      []string{"CN=Butler-Admins,OU=Groups,DC=corp,DC=example,DC=com"},
			want:            true,
		},
		{
			name:            "no match",
			configuredGroup: "butler-admins",
			userGroups:      []string{"other-group"},
			want:            false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			groupSet := BuildGroupLookupSet(tt.userGroups)
			got := MatchGroup(tt.configuredGroup, groupSet)
			if got != tt.want {
				t.Errorf("MatchGroup(%q) = %v, want %v", tt.configuredGroup, got, tt.want)
			}
		})
	}
}
