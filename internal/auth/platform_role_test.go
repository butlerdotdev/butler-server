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
			groupSet := buildGroupLookupSet(tt.userGroups)
			got := matchGroup(tt.configuredGroup, groupSet)
			if got != tt.want {
				t.Errorf("matchGroup(%q) = %v, want %v", tt.configuredGroup, got, tt.want)
			}
		})
	}
}
