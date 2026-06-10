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
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// fakeUserResolver returns prepared UserInfo values keyed by email.
// It avoids standing up the K8s dynamic client for verifier-level tests.
type fakeUserResolver struct {
	byEmail map[string]*UserInfo
	err     error
}

func (f *fakeUserResolver) GetUserByEmail(_ context.Context, email string) (*UserInfo, error) {
	if f.err != nil {
		return nil, f.err
	}
	u, ok := f.byEmail[strings.ToLower(strings.TrimSpace(email))]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

// testKeyPair returns a fresh Ed25519 keypair and an associated kid for tests.
func testKeyPair(t *testing.T) (string, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return "test-kid", pub, priv
}

// signProof builds a portal proof with the given claims and returns the
// signed JWT string. Defaults give a valid 60-second window starting now.
func signProof(t *testing.T, priv ed25519.PrivateKey, kid string, mut func(*jwt.RegisteredClaims, *jwt.Token)) string {
	t.Helper()
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    PortalJWTIssuer,
		Audience:  jwt.ClaimStrings{PortalJWTAudience},
		Subject:   "user@example.com",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
		NotBefore: jwt.NewNumericDate(now.Add(-1 * time.Second)),
		ID:        "jti-" + t.Name(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, &claims)
	token.Header["kid"] = kid
	if mut != nil {
		mut(&claims, token)
	}
	signed, err := token.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

func newVerifierWithFakeUser(t *testing.T, pub ed25519.PublicKey, kid string, user *UserInfo) *PortalJWTVerifier {
	t.Helper()
	users := &fakeUserResolver{byEmail: map[string]*UserInfo{strings.ToLower(user.Email): user}}
	v, err := NewPortalJWTVerifier(map[string]ed25519.PublicKey{kid: pub}, users)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	return v
}

func TestPortalVerifier_ValidProof_AuthsAsSub(t *testing.T) {
	kid, pub, priv := testKeyPair(t)
	user := &UserInfo{
		Name:         "user",
		Email:        "user@example.com",
		DisplayName:  "User",
		PlatformRole: RoleAdmin,
	}
	v := newVerifierWithFakeUser(t, pub, kid, user)

	proof := signProof(t, priv, kid, nil)
	session, claimed, err := v.MaybeVerify(context.Background(), proof)
	if err != nil {
		t.Fatalf("MaybeVerify err: %v", err)
	}
	if !claimed {
		t.Fatal("expected claimed=true for portal proof")
	}
	if session == nil {
		t.Fatal("expected session, got nil")
	}
	if session.Email != "user@example.com" {
		t.Errorf("Email=%q want %q", session.Email, "user@example.com")
	}
	if session.PlatformRole != RoleAdmin {
		t.Errorf("PlatformRole=%q want %q", session.PlatformRole, RoleAdmin)
	}
	if !session.IsPlatformAdmin {
		t.Error("IsPlatformAdmin should be true for admin PlatformRole")
	}
	if session.Provider != PortalJWTIssuer {
		t.Errorf("Provider=%q want %q", session.Provider, PortalJWTIssuer)
	}
}

func TestPortalVerifier_BadSignature_Rejects(t *testing.T) {
	kid, pub, priv := testKeyPair(t)
	user := &UserInfo{Name: "u", Email: "user@example.com", PlatformRole: RoleAdmin}
	v := newVerifierWithFakeUser(t, pub, kid, user)

	proof := signProof(t, priv, kid, nil)
	// Tamper the signature by flipping the last byte of the third segment.
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected JWT shape: %d parts", len(parts))
	}
	// Mutate one base64 char in the signature.
	last := parts[2]
	if len(last) == 0 {
		t.Fatal("empty signature")
	}
	swap := byte('A')
	if last[0] == swap {
		swap = 'B'
	}
	parts[2] = string(swap) + last[1:]
	tampered := strings.Join(parts, ".")

	_, claimed, err := v.MaybeVerify(context.Background(), tampered)
	if !claimed {
		t.Fatal("expected claimed=true; tampered proof still asserts portal iss")
	}
	if err == nil {
		t.Fatal("expected verification error")
	}
}

func TestPortalVerifier_Expired_Rejects(t *testing.T) {
	kid, pub, priv := testKeyPair(t)
	user := &UserInfo{Name: "u", Email: "user@example.com", PlatformRole: RoleAdmin}
	v := newVerifierWithFakeUser(t, pub, kid, user)

	proof := signProof(t, priv, kid, func(c *jwt.RegisteredClaims, _ *jwt.Token) {
		past := time.Now().Add(-2 * time.Minute)
		c.IssuedAt = jwt.NewNumericDate(past)
		c.NotBefore = jwt.NewNumericDate(past)
		c.ExpiresAt = jwt.NewNumericDate(past.Add(30 * time.Second))
	})

	_, claimed, err := v.MaybeVerify(context.Background(), proof)
	if !claimed {
		t.Fatal("expected claimed=true")
	}
	if err == nil {
		t.Fatal("expected expired error")
	}
}

func TestPortalVerifier_TTLOverMax_Rejects(t *testing.T) {
	kid, pub, priv := testKeyPair(t)
	user := &UserInfo{Name: "u", Email: "user@example.com", PlatformRole: RoleAdmin}
	v := newVerifierWithFakeUser(t, pub, kid, user)

	proof := signProof(t, priv, kid, func(c *jwt.RegisteredClaims, _ *jwt.Token) {
		now := time.Now()
		c.IssuedAt = jwt.NewNumericDate(now)
		c.ExpiresAt = jwt.NewNumericDate(now.Add(10 * time.Minute))
	})

	_, claimed, err := v.MaybeVerify(context.Background(), proof)
	if !claimed {
		t.Fatal("expected claimed=true")
	}
	if err == nil || !strings.Contains(err.Error(), "TTL") {
		t.Fatalf("expected TTL violation, got %v", err)
	}
}

func TestPortalVerifier_WrongAudience_Rejects(t *testing.T) {
	kid, pub, priv := testKeyPair(t)
	user := &UserInfo{Name: "u", Email: "user@example.com", PlatformRole: RoleAdmin}
	v := newVerifierWithFakeUser(t, pub, kid, user)

	proof := signProof(t, priv, kid, func(c *jwt.RegisteredClaims, _ *jwt.Token) {
		c.Audience = jwt.ClaimStrings{"some-other-service"}
	})

	_, claimed, err := v.MaybeVerify(context.Background(), proof)
	if !claimed {
		t.Fatal("expected claimed=true")
	}
	if err == nil {
		t.Fatal("expected audience error")
	}
}

func TestPortalVerifier_ReplayedJTI_Rejects(t *testing.T) {
	kid, pub, priv := testKeyPair(t)
	user := &UserInfo{Name: "u", Email: "user@example.com", PlatformRole: RoleAdmin}
	v := newVerifierWithFakeUser(t, pub, kid, user)

	proof := signProof(t, priv, kid, nil)

	_, claimed, err := v.MaybeVerify(context.Background(), proof)
	if !claimed || err != nil {
		t.Fatalf("first verify must succeed: claimed=%v err=%v", claimed, err)
	}
	_, claimed, err = v.MaybeVerify(context.Background(), proof)
	if !claimed {
		t.Fatal("expected claimed=true on replay attempt")
	}
	if err == nil || !strings.Contains(err.Error(), "replayed") {
		t.Fatalf("expected replay error, got %v", err)
	}
}

func TestPortalVerifier_UnknownSub_Rejects(t *testing.T) {
	kid, pub, priv := testKeyPair(t)
	// Resolver does NOT contain the proof's sub.
	users := &fakeUserResolver{byEmail: map[string]*UserInfo{}}
	v, _ := NewPortalJWTVerifier(map[string]ed25519.PublicKey{kid: pub}, users)

	proof := signProof(t, priv, kid, nil)
	_, claimed, err := v.MaybeVerify(context.Background(), proof)
	if !claimed {
		t.Fatal("expected claimed=true")
	}
	if err == nil || !errors.Is(err, ErrUserNotFound) && !strings.Contains(err.Error(), "user not found") {
		t.Fatalf("expected user-not-found, got %v", err)
	}
}

func TestPortalVerifier_DisabledUser_Rejects(t *testing.T) {
	kid, pub, priv := testKeyPair(t)
	user := &UserInfo{
		Name:         "u",
		Email:        "user@example.com",
		PlatformRole: RoleAdmin,
		Disabled:     true,
	}
	v := newVerifierWithFakeUser(t, pub, kid, user)

	proof := signProof(t, priv, kid, nil)
	_, claimed, err := v.MaybeVerify(context.Background(), proof)
	if !claimed {
		t.Fatal("expected claimed=true")
	}
	if !errors.Is(err, ErrUserDisabled) {
		t.Fatalf("expected ErrUserDisabled, got %v", err)
	}
}

func TestPortalVerifier_NonPortalIssuer_FallsThrough(t *testing.T) {
	// Load-bearing console-safety test: a JWT with iss != PortalJWTIssuer
	// must NOT be claimed by the portal verifier. The middleware-level
	// counterpart of this test in middleware_test.go exercises the same
	// invariant against the full middleware flow.
	kid, pub, priv := testKeyPair(t)
	user := &UserInfo{Name: "u", Email: "user@example.com", PlatformRole: RoleAdmin}
	v := newVerifierWithFakeUser(t, pub, kid, user)

	// Build a JWT with iss="butler-server" (the console session shape).
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    "butler-server",
		Audience:  jwt.ClaimStrings{PortalJWTAudience},
		Subject:   "user@example.com",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
		ID:        "jti-not-portal",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodEdDSA, &claims)
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	session, claimed, err := v.MaybeVerify(context.Background(), signed)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if claimed {
		t.Fatal("portal verifier must NOT claim a non-portal iss")
	}
	if session != nil {
		t.Fatal("expected nil session on fall-through")
	}
}

func TestPortalVerifier_MalformedToken_FallsThrough(t *testing.T) {
	kid, pub, _ := testKeyPair(t)
	user := &UserInfo{Name: "u", Email: "user@example.com", PlatformRole: RoleAdmin}
	v := newVerifierWithFakeUser(t, pub, kid, user)

	// Arbitrary non-JWT bytes (e.g. an HMAC-issued cookie value from butler-
	// server's SessionService that an attacker mistakenly passes as Bearer).
	_, claimed, err := v.MaybeVerify(context.Background(), "not-a-jwt-at-all")
	if err != nil {
		t.Fatalf("unexpected err on malformed: %v", err)
	}
	if claimed {
		t.Fatal("malformed token must not be claimed")
	}
}

func TestPortalVerifier_UnknownKID_Rejects(t *testing.T) {
	kid, pub, _ := testKeyPair(t)
	user := &UserInfo{Name: "u", Email: "user@example.com", PlatformRole: RoleAdmin}
	v := newVerifierWithFakeUser(t, pub, kid, user)

	// Sign with a fresh private key whose pub the verifier doesn't know,
	// and label the kid the verifier doesn't have either.
	_, _, otherPriv := testKeyPair(t)
	proof := signProof(t, otherPriv, "unknown-kid", nil)

	_, claimed, err := v.MaybeVerify(context.Background(), proof)
	if !claimed {
		t.Fatal("expected claimed=true; portal iss is set")
	}
	if err == nil || !strings.Contains(err.Error(), "kid") {
		t.Fatalf("expected kid error, got %v", err)
	}
}

func TestPortalVerifier_HMACTokenWithPortalIss_ClaimedThenRejected(t *testing.T) {
	// A token whose iss claim is PortalJWTIssuer is claimed by the
	// portal verifier (iss-routing succeeds) even if its algorithm is
	// HMAC. Verification then fails because the verifier enforces
	// EdDSA-only and the algorithm check rejects the token. This is
	// the correct behavior: callers MUST reject the request rather
	// than fall through, since the token claimed to be a portal
	// proof and the verifier owns the failure.
	kid, pub, _ := testKeyPair(t)
	user := &UserInfo{Name: "u", Email: "user@example.com", PlatformRole: RoleAdmin}
	v := newVerifierWithFakeUser(t, pub, kid, user)

	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    PortalJWTIssuer,
		Audience:  jwt.ClaimStrings{PortalJWTAudience},
		Subject:   "user@example.com",
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
		ID:        "jti-hmac",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, &claims)
	tok.Header["kid"] = kid
	signed, _ := tok.SignedString([]byte("not-an-ed25519-key"))

	_, claimed, err := v.MaybeVerify(context.Background(), signed)
	if !claimed {
		t.Fatal("expected claimed=true; iss=PortalJWTIssuer must be routed to the portal path")
	}
	if err == nil {
		t.Fatal("expected verification error; HMAC algorithm must be rejected")
	}
}

func TestParsePortalPublicKeysPEM_SingleKey(t *testing.T) {
	_, pub, _ := testKeyPair(t)
	pkix, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:    "PUBLIC KEY",
		Headers: map[string]string{"kid": "key-1"},
		Bytes:   pkix,
	})

	keys, err := ParsePortalPublicKeysPEM(string(pemBytes))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := len(keys), 1; got != want {
		t.Fatalf("keys=%d want %d", got, want)
	}
	if _, ok := keys["key-1"]; !ok {
		t.Errorf("missing kid=key-1: %#v", keys)
	}
}

func TestParsePortalPublicKeysPEM_NoKidFingerprintFallback(t *testing.T) {
	_, pub, _ := testKeyPair(t)
	pkix, _ := x509.MarshalPKIXPublicKey(pub)
	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkix,
	})
	keys, err := ParsePortalPublicKeysPEM(string(pemBytes))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("keys=%d want 1", len(keys))
	}
	for kid := range keys {
		if len(kid) != 16 {
			t.Errorf("fingerprint kid wrong length: %q", kid)
		}
	}
}
