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
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ADR-013 gates the /ws/* upgrade on session validity plus endpoint-specific
// authorization. These tests pin the 401/403/accept shape so a future change
// that accidentally drops an auth gate fails at test time.

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// captureLogger returns a text-handler logger writing into buf so tests can
// assert that specific log keys (user, reason, team) appear in rejection
// records. ADR-013 commits to logging user identity on every rejection.
func captureLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
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
	want := &SessionInfo{PlatformRole: "admin", IsPlatformAdmin: true}
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
	ok := requirePlatformAdmin(rec, req, &SessionInfo{PlatformRole: "admin"}, newTestLogger())
	if !ok {
		t.Fatal("expected true for platform admin")
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status should be unset on success, got %d", rec.Code)
	}
}

func TestRequirePlatformAdmin_Viewer_403(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/terminal/management", nil)
	ok := requirePlatformAdmin(rec, req, &SessionInfo{PlatformRole: "viewer", Email: "viewer@co.com"}, newTestLogger())
	if ok {
		t.Fatal("platform viewer must NOT pass requirePlatformAdmin (management terminal)")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// resolveTerminalAccess is the tenant terminal authorization gate. It is
// allowlist-write: a permissive default on this path is a tenant cluster-admin
// shell, so every case that is not an explicit write-capable match must resolve
// to read-only or refused. The unknown/empty/nil rows below pin that.
func TestResolveTerminalAccess(t *testing.T) {
	cases := []struct {
		name       string
		session    *SessionInfo
		team       string
		wantAccess terminalAccess
		wantRole   string
	}{
		{
			name:       "platform admin writes",
			session:    &SessionInfo{PlatformRole: "admin", Email: "a@co.com"},
			team:       "acme",
			wantAccess: terminalWrite,
			wantRole:   "platform-admin",
		},
		{
			name:       "team admin writes",
			session:    &SessionInfo{Teams: []TeamInfo{{Name: "acme", Role: "admin"}}},
			team:       "acme",
			wantAccess: terminalWrite,
			wantRole:   "admin",
		},
		{
			name:       "operator writes",
			session:    &SessionInfo{Teams: []TeamInfo{{Name: "acme", Role: "operator"}}},
			team:       "acme",
			wantAccess: terminalWrite,
			wantRole:   "operator",
		},
		{
			name:       "team viewer read-only",
			session:    &SessionInfo{Teams: []TeamInfo{{Name: "acme", Role: "viewer"}}},
			team:       "acme",
			wantAccess: terminalReadOnly,
			wantRole:   "viewer",
		},
		{
			name:       "platform viewer non-member read-only",
			session:    &SessionInfo{PlatformRole: "viewer", Email: "v@co.com"},
			team:       "acme",
			wantAccess: terminalReadOnly,
			wantRole:   "platform-viewer",
		},
		{
			name:       "non-member refused",
			session:    &SessionInfo{Teams: []TeamInfo{{Name: "other", Role: "admin"}}},
			team:       "acme",
			wantAccess: terminalRefused,
			wantRole:   "",
		},
		{
			name:       "unknown role on membership is not write",
			session:    &SessionInfo{Teams: []TeamInfo{{Name: "acme", Role: "superuser"}}},
			team:       "acme",
			wantAccess: terminalReadOnly,
			wantRole:   "superuser",
		},
		{
			name:       "empty role on membership is not write",
			session:    &SessionInfo{Teams: []TeamInfo{{Name: "acme", Role: ""}}},
			team:       "acme",
			wantAccess: terminalReadOnly,
			wantRole:   "",
		},
		{
			name:       "nil session refused",
			session:    nil,
			team:       "acme",
			wantAccess: terminalRefused,
			wantRole:   "",
		},
		{
			name:       "nil teams non-platform refused",
			session:    &SessionInfo{Teams: nil},
			team:       "acme",
			wantAccess: terminalRefused,
			wantRole:   "",
		},
		{
			name:       "empty team argument refused",
			session:    &SessionInfo{Teams: []TeamInfo{{Name: "acme", Role: "admin"}}},
			team:       "",
			wantAccess: terminalRefused,
			wantRole:   "",
		},
		{
			name:       "cross-team operator refused for other team",
			session:    &SessionInfo{Teams: []TeamInfo{{Name: "team-a", Role: "operator"}}},
			team:       "team-b",
			wantAccess: terminalRefused,
			wantRole:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotAccess, gotRole := resolveTerminalAccess(tc.session, tc.team)
			if gotAccess != tc.wantAccess {
				t.Errorf("access = %d, want %d", gotAccess, tc.wantAccess)
			}
			if gotRole != tc.wantRole {
				t.Errorf("role = %q, want %q", gotRole, tc.wantRole)
			}
		})
	}
}

// F1 guard: ADR-013 commits to logging user identity on every rejection.
// Anonymous rejections log "<unauthenticated>"; authenticated-but-denied
// rejections log the session email. These tests fail if a future change
// drops either log key.

func TestRequireSession_NilResolver_LogsAnonymous(t *testing.T) {
	var buf bytes.Buffer
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/clusters", nil)
	requireSession(rec, req, nil, captureLogger(&buf))
	if !strings.Contains(buf.String(), `user=<unauthenticated>`) {
		t.Errorf("expected anonymous user marker in log, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `reason=unauthorized`) {
		t.Errorf("expected reason=unauthorized in log, got: %s", buf.String())
	}
}

func TestRequireSession_ResolverError_LogsAnonymous(t *testing.T) {
	var buf bytes.Buffer
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/terminal/management", nil)
	resolver := func(_ *http.Request) (*SessionInfo, error) { return nil, errors.New("bad token") }
	requireSession(rec, req, resolver, captureLogger(&buf))
	if !strings.Contains(buf.String(), `user=<unauthenticated>`) {
		t.Errorf("expected anonymous user marker in log, got: %s", buf.String())
	}
}

func TestRequirePlatformAdmin_NonAdmin_LogsEmail(t *testing.T) {
	var buf bytes.Buffer
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/ws/terminal/management", nil)
	session := &SessionInfo{Email: "bob@example.com", IsPlatformAdmin: false}
	requirePlatformAdmin(rec, req, session, captureLogger(&buf))
	if !strings.Contains(buf.String(), `user=bob@example.com`) {
		t.Errorf("expected user=bob@example.com in log, got: %s", buf.String())
	}
	if !strings.Contains(buf.String(), `reason=forbidden`) {
		t.Errorf("expected reason=forbidden in log, got: %s", buf.String())
	}
}
