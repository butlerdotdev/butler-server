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
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/butlerdotdev/butler-server/internal/auth"
)

// Role matrix. Every principal below is evaluated against every check;
// a row lists exactly what it is allowed to do and everything else must
// be denied. That makes "nothing expands" assertable: a check that
// starts passing for a row that does not list it fails the test.
//
// Principals: team viewer, team operator and team admin are members of
// team "alpha" only and hold no platform role. Platform viewer and
// platform admin hold no team membership.
//
// Header contexts: none, own ("alpha") and foreign ("beta").
// SessionMiddleware (internal/auth/middleware.go, the "Set team context
// for non-platform-admins" block) only sets SelectedTeam when the caller
// is a member of the requested team; for a non-member it leaves
// SelectedTeam empty so the request is evaluated as header-less. A
// foreign or invalid X-Butler-Team header therefore reaches handlers as
// SelectedTeam "". Platform admins take the earlier branch, which sets
// SelectedTeam to whatever team was requested with role admin.
// applyTeamHeader below mirrors both branches.

const (
	hdrNone    = ""
	hdrAlpha   = "alpha"
	hdrBeta    = "beta"
	systemNS   = "butler-system"
	allowLabel = "ALLOW"
	denyLabel  = "DENY"
)

// applyTeamHeader mirrors how SessionMiddleware turns an X-Butler-Team
// header into SelectedTeam / SelectedTeamRole.
func applyTeamHeader(u *auth.UserSession, header string) *auth.UserSession {
	if header == "" {
		return u
	}
	if u.PlatformRole == auth.RoleAdmin {
		u.SelectedTeam = header
		u.SelectedTeamRole = auth.RoleAdmin
		for _, m := range u.Teams {
			if m.Name == header {
				u.SelectedTeamRole = m.Role
			}
		}
		return u
	}
	for _, m := range u.Teams {
		if m.Name == header {
			u.SelectedTeam = header
			u.SelectedTeamRole = m.Role
			return u
		}
	}
	// Non-member header: middleware leaves SelectedTeam empty.
	return u
}

type principal struct {
	name string
	make func() *auth.UserSession
}

var matrixPrincipals = []principal{
	{"team-viewer", func() *auth.UserSession {
		return &auth.UserSession{Email: "v@example.com", Teams: []auth.TeamMembership{{Name: "alpha", Role: auth.RoleViewer}}}
	}},
	{"team-operator", func() *auth.UserSession {
		return &auth.UserSession{Email: "o@example.com", Teams: []auth.TeamMembership{{Name: "alpha", Role: auth.RoleOperator}}}
	}},
	{"team-admin", func() *auth.UserSession {
		return &auth.UserSession{Email: "a@example.com", Teams: []auth.TeamMembership{{Name: "alpha", Role: auth.RoleAdmin}}}
	}},
	{"platform-viewer", func() *auth.UserSession {
		return &auth.UserSession{Email: "pv@example.com", PlatformRole: auth.RoleViewer}
	}},
	{"platform-admin", func() *auth.UserSession {
		return &auth.UserSession{Email: "pa@example.com", PlatformRole: auth.RoleAdmin}
	}},
}

// admits reports whether middleware mw lets the session through.
func admits(mw func(http.Handler) http.Handler, u *auth.UserSession) bool {
	passed := false
	h := mw(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { passed = true }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if u != nil {
		req = req.WithContext(auth.ContextWithUser(req.Context(), u))
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return passed
}

type matrixCheck struct {
	name string
	fn   func(u *auth.UserSession) bool
}

// matrixChecks composes the rules the way the handlers do: cluster
// update, delete and kubeconfig run checkClusterVisibility first, then
// the operate or kubeconfig rule; the /admin team member routes run
// RequirePlatformViewer, then adminMiddleware (RequireAdmin), then the
// handler's team check.
func matrixChecks() []matrixCheck {
	ch := &ClusterHandler{}
	var checks []matrixCheck
	for _, team := range []string{"alpha", "beta"} {
		team := team
		checks = append(checks,
			matrixCheck{"cluster-read:" + team, func(u *auth.UserSession) bool {
				return checkClusterVisibility(u, teamCluster(team)) == nil
			}},
			matrixCheck{"cluster-create:" + team, func(u *auth.UserSession) bool {
				return ch.checkOperatePermission(u, team, "create") == nil
			}},
			matrixCheck{"cluster-update:" + team, func(u *auth.UserSession) bool {
				return checkClusterVisibility(u, teamCluster(team)) == nil &&
					ch.checkOperatePermission(u, team, "update") == nil
			}},
			matrixCheck{"cluster-delete:" + team, func(u *auth.UserSession) bool {
				return checkClusterVisibility(u, teamCluster(team)) == nil &&
					ch.checkOperatePermission(u, team, "delete") == nil
			}},
			matrixCheck{"kubeconfig:" + team, func(u *auth.UserSession) bool {
				return checkClusterVisibility(u, teamCluster(team)) == nil &&
					checkKubeconfigAccess(u, team) == nil
			}},
			matrixCheck{"team-settings:" + team, func(u *auth.UserSession) bool {
				st, _ := authorizeTeamUpdate(u, team, &UpdateTeamRequest{DisplayName: "x"})
				return st == 0
			}},
			matrixCheck{"team-limits:" + team, func(u *auth.UserSession) bool {
				st, _ := authorizeTeamUpdate(u, team, &UpdateTeamRequest{ResourceLimits: map[string]interface{}{"maxClusters": 1}})
				return st == 0
			}},
			matrixCheck{"team-members:" + team, func(u *auth.UserSession) bool {
				if !admits(auth.RequirePlatformViewer(), u) || !admits(auth.AdminMiddleware(), u) {
					return false
				}
				st, _ := authorizeTeamMembershipChange(u, team)
				return st == 0
			}},
			matrixCheck{"env-mutate:" + team, func(u *auth.UserSession) bool {
				st, _ := authorizeTeamEnvironmentChange(u, team)
				return st == 0
			}},
			matrixCheck{"imagesync-read:" + team, func(u *auth.UserSession) bool {
				return canViewImageSync(u, "team-"+team, systemNS)
			}},
			matrixCheck{"imagesync-mutate:" + team, func(u *auth.UserSession) bool {
				return canMutateImageSync(u, "team-"+team)
			}},
			matrixCheck{"template-mutate:" + team, func(u *auth.UserSession) bool {
				return checkTemplatePermission(u, "team-"+team) == nil
			}},
			matrixCheck{"workspace-create:" + team, func(u *auth.UserSession) bool {
				return checkWorkspaceClusterOperate(u, teamCluster(team)) == nil
			}},
			matrixCheck{"workspace-others:" + team, func(u *auth.UserSession) bool {
				return u.IsPlatformAdminRole() || workspaceTeamAdmin(u, team)
			}},
		)
	}
	checks = append(checks,
		matrixCheck{"team-create", func(u *auth.UserSession) bool {
			st, _ := authorizeTeamCreate(u)
			return st == 0
		}},
		matrixCheck{"team-delete", func(u *auth.UserSession) bool {
			st, _ := authorizeTeamDelete(u)
			return st == 0
		}},
		matrixCheck{"imagesync-mutate:system", func(u *auth.UserSession) bool {
			return canMutateImageSync(u, systemNS)
		}},
		matrixCheck{"template-mutate:cluster-scope", func(u *auth.UserSession) bool {
			return checkTemplatePermission(u, systemNS) == nil
		}},
		matrixCheck{"route:RequirePlatformViewer", func(u *auth.UserSession) bool {
			return admits(auth.RequirePlatformViewer(), u)
		}},
		matrixCheck{"route:RequirePlatformAdmin", func(u *auth.UserSession) bool {
			return admits(auth.RequirePlatformAdmin(), u)
		}},
		matrixCheck{"route:RequireAdmin", func(u *auth.UserSession) bool {
			return admits(auth.RequireAdmin(), u)
		}},
		matrixCheck{"session:IsAdmin", func(u *auth.UserSession) bool { return u.IsAdmin() }},
		matrixCheck{"session:CanOperateInSelectedTeam", func(u *auth.UserSession) bool {
			return u.CanOperateInSelectedTeam()
		}},
		matrixCheck{"session:CanOperateInSelectedEnvironment", func(u *auth.UserSession) bool {
			return u.CanOperateInSelectedEnvironment()
		}},
	)
	return checks
}

func set(items ...string) map[string]bool {
	m := map[string]bool{}
	for _, i := range items {
		m[i] = true
	}
	return m
}

func union(sets ...map[string]bool) map[string]bool {
	m := map[string]bool{}
	for _, s := range sets {
		for k := range s {
			m[k] = true
		}
	}
	return m
}

func except(all map[string]bool, drop ...string) map[string]bool {
	m := union(all)
	for _, d := range drop {
		delete(m, d)
	}
	return m
}

func TestRoleMatrix(t *testing.T) {
	checks := matrixChecks()
	everything := map[string]bool{}
	for _, c := range checks {
		everything[c.name] = true
	}

	// Team viewer: reads its own team, nothing else, no kubeconfig.
	viewer := set("cluster-read:alpha", "imagesync-read:alpha")

	// Team operator: own-team cluster lifecycle and kubeconfig; no team
	// settings, limits, environments or platform routes.
	operator := union(viewer, set(
		"cluster-create:alpha", "cluster-update:alpha", "cluster-delete:alpha",
		"kubeconfig:alpha",
		"imagesync-mutate:alpha", "template-mutate:alpha", "workspace-create:alpha",
	))
	// The same operator with header alpha also passes the selected-team
	// session helpers; header-less it does not (no any-team fallback).
	operatorScoped := union(operator, set("session:CanOperateInSelectedTeam", "session:CanOperateInSelectedEnvironment"))

	// Team admin: operator rights plus own team settings and
	// environments; never resourceLimits, team create/delete, member
	// management (an /admin route) or any platform route.
	admin := union(operator, set("team-settings:alpha", "env-mutate:alpha", "workspace-others:alpha"))
	adminScoped := union(admin, set("session:CanOperateInSelectedTeam", "session:CanOperateInSelectedEnvironment"))

	// Platform viewer: reads across teams and the platform-viewer
	// routes; no mutation of any kind, no kubeconfig.
	platformViewer := set(
		"cluster-read:alpha", "cluster-read:beta",
		"imagesync-read:alpha", "imagesync-read:beta",
		"route:RequirePlatformViewer",
	)

	// Platform admin: everything. With a team header the cluster
	// handlers pin the request to that team's clusters; that is a
	// scoping guard for the team-scoped console view, not a privilege
	// limit (the same admin without the header is allowed).
	clusterChecks := func(team string) []string {
		return []string{"cluster-read:" + team, "cluster-create:" + team, "cluster-update:" + team, "cluster-delete:" + team, "kubeconfig:" + team}
	}
	platformAdmin := everything
	platformAdminAlpha := except(everything, clusterChecks("beta")...)
	platformAdminBeta := except(everything, clusterChecks("alpha")...)

	rows := []struct {
		principal string
		header    string
		allow     map[string]bool
	}{
		{"team-viewer", hdrNone, viewer},
		{"team-viewer", hdrAlpha, viewer},
		{"team-viewer", hdrBeta, viewer},
		{"team-operator", hdrNone, operator},
		{"team-operator", hdrAlpha, operatorScoped},
		{"team-operator", hdrBeta, operator},
		{"team-admin", hdrNone, admin},
		{"team-admin", hdrAlpha, adminScoped},
		{"team-admin", hdrBeta, admin},
		{"platform-viewer", hdrNone, platformViewer},
		{"platform-viewer", hdrAlpha, platformViewer},
		{"platform-viewer", hdrBeta, platformViewer},
		{"platform-admin", hdrNone, platformAdmin},
		{"platform-admin", hdrAlpha, platformAdminAlpha},
		{"platform-admin", hdrBeta, platformAdminBeta},
	}

	makers := map[string]func() *auth.UserSession{}
	for _, p := range matrixPrincipals {
		makers[p.name] = p.make
	}

	for _, row := range rows {
		for k := range row.allow {
			if !everything[k] {
				t.Fatalf("row %s/%q lists unknown check %q", row.principal, row.header, k)
			}
		}
		hdr := row.header
		if hdr == "" {
			hdr = "none"
		}
		for _, c := range checks {
			want := row.allow[c.name]
			label := denyLabel
			if want {
				label = allowLabel
			}
			name := fmt.Sprintf("%s/header=%s/%s=%s", row.principal, hdr, c.name, label)
			u := applyTeamHeader(makers[row.principal](), row.header)
			c := c
			t.Run(name, func(t *testing.T) {
				if got := c.fn(u); got != want {
					t.Errorf("%s: got %v, want %v (SelectedTeam=%q role=%q)", c.name, got, want, u.SelectedTeam, u.SelectedTeamRole)
				}
			})
		}
	}
}

// TestRoleMatrix_ForeignHeaderIsHeaderless pins the middleware
// behaviour the matrix relies on: a team member sending another team's
// header is evaluated exactly as with no header.
func TestRoleMatrix_ForeignHeaderIsHeaderless(t *testing.T) {
	for _, p := range matrixPrincipals[:4] {
		u := applyTeamHeader(p.make(), hdrBeta)
		if u.SelectedTeam != "" || u.SelectedTeamRole != "" {
			t.Errorf("%s with header beta: SelectedTeam=%q role=%q, want empty", p.name, u.SelectedTeam, u.SelectedTeamRole)
		}
	}
}

// TestRoleMatrix_NoSession checks the 401 path of every gate the matrix
// covers.
func TestRoleMatrix_NoSession(t *testing.T) {
	gates := map[string]func() int{
		"authorizeTeamCreate":            func() int { s, _ := authorizeTeamCreate(nil); return s },
		"authorizeTeamDelete":            func() int { s, _ := authorizeTeamDelete(nil); return s },
		"authorizeTeamUpdate":            func() int { s, _ := authorizeTeamUpdate(nil, "alpha", nil); return s },
		"authorizeTeamMembershipChange":  func() int { s, _ := authorizeTeamMembershipChange(nil, "alpha"); return s },
		"authorizeTeamEnvironmentChange": func() int { s, _ := authorizeTeamEnvironmentChange(nil, "alpha"); return s },
	}
	names := make([]string, 0, len(gates))
	for n := range gates {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if got := gates[n](); got != http.StatusUnauthorized {
			t.Errorf("%s(nil) = %d, want 401", n, got)
		}
	}
	for n, mw := range map[string]func(http.Handler) http.Handler{
		"RequirePlatformAdmin":  auth.RequirePlatformAdmin(),
		"RequireAdmin":          auth.RequireAdmin(),
		"RequirePlatformViewer": auth.RequirePlatformViewer(),
	} {
		rec := httptest.NewRecorder()
		mw(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without session = %d, want 401", n, rec.Code)
		}
	}
	if canViewImageSync(nil, "team-alpha", systemNS) || canMutateImageSync(nil, "team-alpha") {
		t.Error("image sync rules admitted a nil session")
	}
}

// TestRoleMatrix_EnvironmentHandlersDenyBeforeWrite drives the three
// environment handlers end to end for denied callers: they must answer
// 401/403 before reading the body or touching the cluster (the handler
// has no client here, so reaching it would panic).
func TestRoleMatrix_EnvironmentHandlersDenyBeforeWrite(t *testing.T) {
	h := &TeamHandler{}
	handlers := map[string]http.HandlerFunc{
		"AddEnvironment":    h.AddEnvironment,
		"UpdateEnvironment": h.UpdateEnvironment,
		"RemoveEnvironment": h.RemoveEnvironment,
	}
	cases := []struct {
		name string
		user *auth.UserSession
		team string
		want int
	}{
		{"no-session", nil, "alpha", http.StatusUnauthorized},
		{"team-viewer/own", matrixPrincipals[0].make(), "alpha", http.StatusForbidden},
		{"team-operator/own", matrixPrincipals[1].make(), "alpha", http.StatusForbidden},
		{"team-admin/foreign", matrixPrincipals[2].make(), "beta", http.StatusForbidden},
		{"platform-viewer/own", matrixPrincipals[3].make(), "alpha", http.StatusForbidden},
	}
	for hn, hf := range handlers {
		for _, tc := range cases {
			t.Run(hn+"/"+tc.name, func(t *testing.T) {
				rctx := chi.NewRouteContext()
				rctx.URLParams.Add("name", tc.team)
				rctx.URLParams.Add("env", "dev")
				req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{"name":"dev"}`))
				ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
				if tc.user != nil {
					ctx = auth.ContextWithUser(ctx, tc.user)
				}
				rec := httptest.NewRecorder()
				hf(rec, req.WithContext(ctx))
				if rec.Code != tc.want {
					t.Errorf("got %d, want %d (body %s)", rec.Code, tc.want, rec.Body.String())
				}
			})
		}
	}
}
