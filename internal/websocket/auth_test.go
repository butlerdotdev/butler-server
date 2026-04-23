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

package websocket

import (
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ADR-013 gates the /ws/* upgrade on session validity plus endpoint-specific
// authorization. These tests pin the 401/403/accept shape so a future change
// that accidentally drops an auth gate fails at test time.

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRequireSession_NilResolver_401(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/clusters", nil)
	got := requireSession(rec, req, nil, newTestLogger())
	if got != nil {
		t.Fatalf("expected nil session, got %+v", got)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireSession_ResolverError_401(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/terminal/management", nil)
	resolver := func(_ *http.Request) (*SessionInfo, error) {
		return nil, errors.New("invalid token")
	}
	got := requireSession(rec, req, resolver, newTestLogger())
	if got != nil {
		t.Fatalf("expected nil session on resolver error, got %+v", got)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireSession_ResolverNilSession_401(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/terminal/management", nil)
	resolver := func(_ *http.Request) (*SessionInfo, error) {
		return nil, nil
	}
	got := requireSession(rec, req, resolver, newTestLogger())
	if got != nil {
		t.Fatalf("expected nil session when resolver returns nil, got %+v", got)
	}
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
}

func TestRequireSession_Valid_ReturnsSession(t *testing.T) {
	want := &SessionInfo{IsPlatformAdmin: true}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/clusters", nil)
	resolver := func(_ *http.Request) (*SessionInfo, error) {
		return want, nil
	}
	got := requireSession(rec, req, resolver, newTestLogger())
	if got != want {
		t.Errorf("expected passthrough of session, got %+v", got)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status should be unset on success, got %d", rec.Code)
	}
}

func TestRequirePlatformAdmin_NonAdmin_403(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/terminal/management", nil)
	ok := requirePlatformAdmin(rec, req, &SessionInfo{IsPlatformAdmin: false}, newTestLogger())
	if ok {
		t.Fatal("expected false for non-platform-admin")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestRequirePlatformAdmin_Admin_Pass(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/terminal/management", nil)
	ok := requirePlatformAdmin(rec, req, &SessionInfo{IsPlatformAdmin: true}, newTestLogger())
	if !ok {
		t.Fatal("expected true for platform admin")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status should be unset on success, got %d", rec.Code)
	}
}

func TestRequireTeamAccess_PlatformAdminBypasses(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/terminal/tenant/acme/c1", nil)
	ok := requireTeamAccess(rec, req, &SessionInfo{IsPlatformAdmin: true}, "acme", newTestLogger())
	if !ok {
		t.Fatal("platform admin should bypass team check")
	}
}

func TestRequireTeamAccess_MemberPass(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/terminal/tenant/acme/c1", nil)
	session := &SessionInfo{Teams: []TeamInfo{{Name: "acme"}, {Name: "other"}}}
	ok := requireTeamAccess(rec, req, session, "acme", newTestLogger())
	if !ok {
		t.Fatal("team member should pass")
	}
}

func TestRequireTeamAccess_NonMember_403(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/terminal/tenant/acme/c1", nil)
	session := &SessionInfo{Teams: []TeamInfo{{Name: "other"}}}
	ok := requireTeamAccess(rec, req, session, "acme", newTestLogger())
	if ok {
		t.Fatal("non-team-member should be rejected")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

func TestRequireTeamAccess_EmptyTeams_403(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/terminal/tenant/acme/c1", nil)
	session := &SessionInfo{Teams: nil}
	ok := requireTeamAccess(rec, req, session, "acme", newTestLogger())
	if ok {
		t.Fatal("session with no teams should be rejected on team endpoints")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}
