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

// ADR-009 additive-only inheritance: env access can only elevate a
// team-level role, never reduce it. These tests pin the max-composition
// semantic that delivers that promise at session time.

func TestCanOperateInSelectedEnvironment_EnvElevatesOperator(t *testing.T) {
	u := &UserSession{
		Email:                   "alice@example.com",
		SelectedTeam:            "acme",
		SelectedTeamRole:        RoleOperator,
		SelectedEnvironment:     "prod",
		SelectedEnvironmentRole: RoleAdmin,
	}
	if !u.CanOperateInSelectedEnvironment() {
		t.Fatal("operator elevated to admin in env should be able to operate")
	}
}

func TestCanOperateInSelectedEnvironment_EnvCannotReduceAdmin(t *testing.T) {
	// Team admin Alice is listed in env.access as role=viewer. ADR-009
	// says this block cannot reduce her team role; the max composition
	// keeps her at admin.
	u := &UserSession{
		Email:                   "alice@example.com",
		SelectedTeam:            "acme",
		SelectedTeamRole:        RoleAdmin,
		SelectedEnvironment:     "prod",
		SelectedEnvironmentRole: RoleViewer,
	}
	if !u.CanOperateInSelectedEnvironment() {
		t.Fatal("team admin listed as viewer in env must still be able to operate (additive-only)")
	}
}

func TestCanOperateInSelectedEnvironment_NoEnvFallsBackToTeam(t *testing.T) {
	u := &UserSession{
		Email:            "alice@example.com",
		SelectedTeam:     "acme",
		SelectedTeamRole: RoleViewer,
	}
	if u.CanOperateInSelectedEnvironment() {
		t.Fatal("viewer with no env context cannot operate")
	}
}

func TestCanOperateInSelectedEnvironment_ViewerNotElevated(t *testing.T) {
	u := &UserSession{
		Email:                   "bob@example.com",
		SelectedTeam:            "acme",
		SelectedTeamRole:        RoleViewer,
		SelectedEnvironment:     "prod",
		SelectedEnvironmentRole: RoleViewer,
	}
	if u.CanOperateInSelectedEnvironment() {
		t.Fatal("viewer with env=viewer cannot operate")
	}
}

func TestCanOperateInSelectedEnvironment_PlatformAdminBypass(t *testing.T) {
	u := &UserSession{
		Email:           "admin@example.com",
		IsPlatformAdmin: true,
	}
	if !u.CanOperateInSelectedEnvironment() {
		t.Fatal("platform admin must always be able to operate")
	}
}

func TestCanViewInSelectedEnvironment_EnvOnlyMembership(t *testing.T) {
	// User has no team role (not in team.access) but env.access elevates
	// to viewer. ADR-009 membership-check (Team webhook) will reject
	// non-team-member env.access entries at admission, so this state is
	// not reachable in practice. The helper still composes correctly.
	u := &UserSession{
		Email:                   "carol@example.com",
		SelectedTeam:            "acme",
		SelectedTeamRole:        "",
		SelectedEnvironment:     "prod",
		SelectedEnvironmentRole: RoleViewer,
	}
	if !u.CanViewInSelectedEnvironment() {
		t.Fatal("env-level viewer should be able to view in env context")
	}
}

func TestNormalizeEmail(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"Alice@Example.COM", "alice@example.com"},
		{"  bob@example.com  ", "bob@example.com"},
		{"", ""},
		{"user+tag@example.com", "user+tag@example.com"},
	}
	for _, c := range cases {
		if got := NormalizeEmail(c.in); got != c.want {
			t.Errorf("NormalizeEmail(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
