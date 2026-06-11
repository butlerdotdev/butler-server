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
	"bytes"
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
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

// -----------------------------------------------------------------------------
// SessionMiddleware end-to-end tests covering the portal-JWT branch and the
// AllowHeaderImpersonation flag (Stage 1 of the P0 #3 fix).
//
// Load-bearing invariants:
//
//  (i)  with PortalVerifier=nil and AllowHeaderImpersonation=true (the Stage 1
//       defaults), butler-server behaves byte-identically to pre-Stage-1 for
//       every existing caller. The console-style JWT path test below proves
//       this for the console.
//
//  (ii) the portal-JWT branch is gated on iss claim. A token whose iss is
//       anything other than PortalJWTIssuer falls through to ValidateSession
//       UNCHANGED. The mutation-proof test below (an HS256 session JWT with
//       iss="butler-server") would fail if the iss gate were widened.
//
//  (iii) AllowHeaderImpersonation false skips the X-Butler-User-Email override
//       in the platform-admin branch even when the header is set. Paired with
//       the AllowHeaderImpersonation=true test, this proves the flag actually
//       controls the override (non-vacuous).
// -----------------------------------------------------------------------------

// runMiddleware constructs SessionMiddleware with the given config and a
// downstream handler that writes the in-context UserSession.Email to the
// response body, then drives a single request.
func runMiddleware(t *testing.T, cfg SessionMiddlewareConfig, req *http.Request) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	mw := SessionMiddleware(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u := UserFromContext(r.Context())
		if u == nil {
			http.Error(w, `{"error":"no-user"}`, http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(u.Email))
	}))
	mw.ServeHTTP(rec, req)
	return rec
}

func mintConsoleSessionToken(t *testing.T, secret, email string, role string) string {
	t.Helper()
	svc := NewSessionService(secret, time.Hour)
	tok, err := svc.CreateSession(&UserSession{
		Email:        email,
		Name:         "Tester",
		PlatformRole: role,
	})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	return tok
}

func TestSessionMiddleware_NoPortalVerifier_ConsoleJWTPassesThrough(t *testing.T) {
	const (
		secret = "test-jwt-secret"
		email  = "console-user@example.com"
	)
	cfg := SessionMiddlewareConfig{
		SessionService:           NewSessionService(secret, time.Hour),
		AllowHeaderImpersonation: true,
	}
	tok := mintConsoleSessionToken(t, secret, email, RoleAdmin)

	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := runMiddleware(t, cfg, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q want 200", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != email {
		t.Errorf("downstream saw email=%q want %q", got, email)
	}
}

func TestSessionMiddleware_PortalVerifier_NonPortalIssJWTFallsThrough(t *testing.T) {
	// LOAD-BEARING. Confirms the iss gate inside MaybeVerify keeps
	// console-issued JWTs (iss="butler-server") on the existing
	// ValidateSession path even when the portal verifier is configured.
	// Mutation: if the iss gate were widened to accept any iss, the
	// portal verifier would try to validate the HS256-signed console
	// JWT as EdDSA, fail, and the middleware would 401. This test
	// would then fail on the status check.
	const (
		secret = "test-jwt-secret"
		email  = "console-user@example.com"
	)
	_, pub, priv := testKeyPair(t)
	users := &fakeUserResolver{
		byEmail: map[string]*UserInfo{
			email: {Name: "u", Email: email, PlatformRole: RoleAdmin},
		},
	}
	verifier, err := NewPortalJWTVerifier(map[string]ed25519.PublicKey{"k1": pub}, users)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	_ = priv // unused; we deliberately mint a console-style token here, not a portal proof

	cfg := SessionMiddlewareConfig{
		SessionService:           NewSessionService(secret, time.Hour),
		PortalVerifier:           verifier,
		AllowHeaderImpersonation: true,
	}
	tok := mintConsoleSessionToken(t, secret, email, RoleAdmin)

	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := runMiddleware(t, cfg, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q want 200 (console JWT must fall through)", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != email {
		t.Errorf("downstream saw email=%q want %q", got, email)
	}
}

func TestSessionMiddleware_PortalProofValid_AuthsAsSub(t *testing.T) {
	const portalEmail = "portal-user@example.com"
	kid, pub, priv := testKeyPair(t)
	users := &fakeUserResolver{
		byEmail: map[string]*UserInfo{
			portalEmail: {
				Name:         "portal-user",
				Email:        portalEmail,
				DisplayName:  "Portal User",
				PlatformRole: RoleAdmin,
			},
		},
	}
	verifier, _ := NewPortalJWTVerifier(map[string]ed25519.PublicKey{kid: pub}, users)
	cfg := SessionMiddlewareConfig{
		SessionService:           NewSessionService("unused", time.Hour),
		PortalVerifier:           verifier,
		AllowHeaderImpersonation: true,
	}

	proof := signProof(t, priv, kid, func(c *jwt.RegisteredClaims, _ *jwt.Token) {
		c.Subject = portalEmail
		c.ID = "jti-portal-mw"
	})
	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	req.Header.Set("Authorization", "Bearer "+proof)
	rec := runMiddleware(t, cfg, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q want 200", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != portalEmail {
		t.Errorf("downstream saw email=%q want %q", got, portalEmail)
	}
}

func TestSessionMiddleware_PortalProofValid_LogsSuccessAtInfo(t *testing.T) {
	// Operators need a positive log signal that the proof path is winning in
	// production, especially before Stage 4 removes the legacy header-trust
	// fallback. The rejected path already logs at Warn; the success path
	// should log at Info so the trail is symmetric and visible without
	// raising the global log level.
	const portalEmail = "portal-user@example.com"
	kid, pub, priv := testKeyPair(t)
	users := &fakeUserResolver{
		byEmail: map[string]*UserInfo{
			portalEmail: {
				Name:         "portal-user",
				Email:        portalEmail,
				DisplayName:  "Portal User",
				PlatformRole: RoleAdmin,
			},
		},
	}
	verifier, _ := NewPortalJWTVerifier(map[string]ed25519.PublicKey{kid: pub}, users)

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg := SessionMiddlewareConfig{
		SessionService:           NewSessionService("unused", time.Hour),
		PortalVerifier:           verifier,
		AllowHeaderImpersonation: true,
		Logger:                   logger,
	}

	proof := signProof(t, priv, kid, func(c *jwt.RegisteredClaims, _ *jwt.Token) {
		c.Subject = portalEmail
		c.ID = "jti-portal-mw-log"
	})
	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	req.Header.Set("Authorization", "Bearer "+proof)
	rec := runMiddleware(t, cfg, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q want 200", rec.Code, rec.Body.String())
	}
	if !strings.Contains(buf.String(), `"msg":"Portal proof verified"`) {
		t.Errorf("expected Info log %q in middleware output, got: %s", "Portal proof verified", buf.String())
	}
	if !strings.Contains(buf.String(), `"sub":"`+portalEmail+`"`) {
		t.Errorf("expected sub=%q in success log, got: %s", portalEmail, buf.String())
	}
	if !strings.Contains(buf.String(), `"level":"INFO"`) {
		t.Errorf("expected level=INFO on success log, got: %s", buf.String())
	}
	if strings.Contains(buf.String(), `"msg":"Portal proof rejected"`) {
		t.Errorf("success path must not emit the rejected log, got: %s", buf.String())
	}
}

func TestSessionMiddleware_PortalProofBadSig_Rejects401(t *testing.T) {
	kid, pub, priv := testKeyPair(t)
	users := &fakeUserResolver{
		byEmail: map[string]*UserInfo{
			"portal-user@example.com": {
				Name: "u", Email: "portal-user@example.com", PlatformRole: RoleAdmin,
			},
		},
	}
	verifier, _ := NewPortalJWTVerifier(map[string]ed25519.PublicKey{kid: pub}, users)
	cfg := SessionMiddlewareConfig{
		SessionService:           NewSessionService("unused", time.Hour),
		PortalVerifier:           verifier,
		AllowHeaderImpersonation: true,
	}

	proof := signProof(t, priv, kid, func(c *jwt.RegisteredClaims, _ *jwt.Token) {
		c.Subject = "portal-user@example.com"
		c.ID = "jti-bad-sig-mw"
	})
	// Tamper the signature.
	parts := strings.Split(proof, ".")
	parts[2] = "AAAA" + parts[2][4:]
	tampered := strings.Join(parts, ".")

	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	req.Header.Set("Authorization", "Bearer "+tampered)
	rec := runMiddleware(t, cfg, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d want 401 (tampered portal proof must be rejected, not fall through)", rec.Code)
	}
}

func TestSessionMiddleware_AllowHeaderImpersonationTrue_HeaderOverrides(t *testing.T) {
	// Back-compat under Stage 1 default. The platform-admin path reads
	// X-Butler-User-Email and the override fires.
	const (
		secret    = "test-jwt-secret"
		adminMail = "admin@example.com"
		spoofMail = "victim@example.com"
	)
	cfg := SessionMiddlewareConfig{
		SessionService:           NewSessionService(secret, time.Hour),
		AllowHeaderImpersonation: true,
	}
	tok := mintConsoleSessionToken(t, secret, adminMail, RoleAdmin)

	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Butler-User-Email", spoofMail)
	rec := runMiddleware(t, cfg, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q want 200", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != spoofMail {
		t.Errorf("downstream saw email=%q want %q (override should fire with flag true)", got, spoofMail)
	}
}

func TestSessionMiddleware_AllowHeaderImpersonationFalse_HeaderIgnored(t *testing.T) {
	// Stage 4 target behavior. Same setup as the back-compat test, but
	// the flag flips to false. The override MUST NOT fire.
	const (
		secret    = "test-jwt-secret"
		adminMail = "admin@example.com"
		spoofMail = "victim@example.com"
	)
	cfg := SessionMiddlewareConfig{
		SessionService:           NewSessionService(secret, time.Hour),
		AllowHeaderImpersonation: false,
	}
	tok := mintConsoleSessionToken(t, secret, adminMail, RoleAdmin)

	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("X-Butler-User-Email", spoofMail)
	rec := runMiddleware(t, cfg, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q want 200", rec.Code, rec.Body.String())
	}
	if got := rec.Body.String(); got != adminMail {
		t.Errorf("downstream saw email=%q want %q (override must NOT fire with flag false)", got, adminMail)
	}
}

// stubVerifier returns prescribed (session, claimed, err) shapes to exercise
// SessionMiddleware's claimed-is-terminal invariant directly. It does not
// look at the token bytes; the test injects the desired return shape and
// drives the middleware with arbitrary Bearer content.
type stubVerifier struct {
	session *UserSession
	claimed bool
	err     error
}

func (s *stubVerifier) MaybeVerify(_ context.Context, _ string) (*UserSession, bool, error) {
	return s.session, s.claimed, s.err
}

func TestSessionMiddleware_ClaimedWithNilSession_RejectsTerminal(t *testing.T) {
	// Claimed-is-terminal invariant. If a verifier ever returns (nil, true,
	// nil) the middleware MUST reject rather than fall through to
	// ValidateSession. The fall-through would give a portal-claimed token a
	// second chance at HMAC auth, which is the bypass shape this guard
	// backstops. The body-string assertion is what makes this test non-
	// vacuous: both the guard path and the ValidateSession path return 401,
	// but only the guard returns "invalid portal proof".
	cfg := SessionMiddlewareConfig{
		SessionService:           NewSessionService("test-secret", time.Hour),
		PortalVerifier:           &stubVerifier{session: nil, claimed: true, err: nil},
		AllowHeaderImpersonation: true,
	}
	req := httptest.NewRequest(http.MethodGet, "/api/clusters", nil)
	req.Header.Set("Authorization", "Bearer arbitrary-token-bytes")
	rec := runMiddleware(t, cfg, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status=%d want 401 (claimed without session must be terminal)", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "invalid portal proof") {
		t.Errorf("body=%q want 'invalid portal proof' response, not the fall-through 'invalid session' from ValidateSession", body)
	}
}
