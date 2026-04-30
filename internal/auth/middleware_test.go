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
	"net/http"
	"net/http/httptest"
	"testing"
)

// withUser injects a UserSession into the request context for middleware tests.
func withUser(r *http.Request, user *UserSession) *http.Request {
	ctx := context.WithValue(r.Context(), userContextKey, user)
	return r.WithContext(ctx)
}

// dummyHandler is a pass-through handler used to confirm middleware did not block.
var dummyHandler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
})

func TestRequirePlatformAdmin_NoUser_401(t *testing.T) {
	mw := RequirePlatformAdmin()(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/settings", nil)
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rec.Code)
	}
}

func TestRequirePlatformAdmin_ViewerBlocked_403(t *testing.T) {
	mw := RequirePlatformAdmin()(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/settings", nil)
	req = withUser(req, &UserSession{Email: "viewer@example.com", PlatformRole: RoleViewer})
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d, want 403", rec.Code)
	}
}

func TestRequirePlatformAdmin_RegularUserBlocked_403(t *testing.T) {
	mw := RequirePlatformAdmin()(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/settings", nil)
	req = withUser(req, &UserSession{Email: "user@example.com", PlatformRole: ""})
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d, want 403", rec.Code)
	}
}

func TestRequirePlatformAdmin_AdminPasses(t *testing.T) {
	mw := RequirePlatformAdmin()(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/admin/settings", nil)
	req = withUser(req, &UserSession{Email: "admin@example.com", PlatformRole: RoleAdmin})
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
}

func TestRequirePlatformViewer_NoUser_401(t *testing.T) {
	mw := RequirePlatformViewer()(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rec.Code)
	}
}

func TestRequirePlatformViewer_RegularUserBlocked_403(t *testing.T) {
	mw := RequirePlatformViewer()(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	req = withUser(req, &UserSession{Email: "user@example.com", PlatformRole: ""})
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d, want 403", rec.Code)
	}
}

func TestRequirePlatformViewer_ViewerPasses(t *testing.T) {
	mw := RequirePlatformViewer()(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	req = withUser(req, &UserSession{Email: "viewer@example.com", PlatformRole: RoleViewer})
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
}

func TestRequirePlatformViewer_AdminPasses(t *testing.T) {
	mw := RequirePlatformViewer()(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	req = withUser(req, &UserSession{Email: "admin@example.com", PlatformRole: RoleAdmin})
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
}

// RequireTeam middleware tests with platform roles.

func TestRequireTeam_ViewerBypasses(t *testing.T) {
	mw := RequireTeam("acme")(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/teams/acme/clusters", nil)
	req = withUser(req, &UserSession{Email: "viewer@example.com", PlatformRole: RoleViewer})
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200 (platform viewer should bypass team gate)", rec.Code)
	}
}

func TestRequireTeam_AdminBypasses(t *testing.T) {
	mw := RequireTeam("acme")(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/teams/acme/clusters", nil)
	req = withUser(req, &UserSession{Email: "admin@example.com", PlatformRole: RoleAdmin})
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200 (platform admin should bypass team gate)", rec.Code)
	}
}

func TestRequireTeam_NonMemberBlocked(t *testing.T) {
	mw := RequireTeam("acme")(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/teams/acme/clusters", nil)
	req = withUser(req, &UserSession{
		Email: "user@example.com",
		Teams: []TeamMembership{{Name: "other", Role: RoleViewer}},
	})
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("got %d, want 403", rec.Code)
	}
}

func TestRequireTeam_MemberPasses(t *testing.T) {
	mw := RequireTeam("acme")(dummyHandler)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/teams/acme/clusters", nil)
	req = withUser(req, &UserSession{
		Email: "user@example.com",
		Teams: []TeamMembership{{Name: "acme", Role: RoleViewer}},
	})
	mw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("got %d, want 200", rec.Code)
	}
}
