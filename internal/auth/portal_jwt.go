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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Portal-proof routing and validation constants. The portal-issued JWT carries
// iss=PortalJWTIssuer so SessionMiddleware can distinguish portal-mediated
// requests from console/CLI sessions and route them to PortalJWTVerifier.
// Any token with a different iss falls through to SessionService.ValidateSession
// unchanged, which is the property that keeps non-portal callers untouched.
const (
	PortalJWTIssuer   = "butler-portal"
	PortalJWTAudience = "butler-server"
	PortalJWTMaxTTL   = 60 * time.Second
)

// PortalUserResolver looks up a user by email. UserService satisfies this.
// Defined as an interface so tests can inject a fake without standing up the
// K8s dynamic client.
type PortalUserResolver interface {
	GetUserByEmail(ctx context.Context, email string) (*UserInfo, error)
}

// Compile-time assertion that *PortalJWTVerifier satisfies the
// PortalProofVerifier interface SessionMiddleware depends on.
var _ PortalProofVerifier = (*PortalJWTVerifier)(nil)

// PortalJWTVerifier verifies portal-issued Ed25519 JWTs and resolves them
// to a per-request UserSession backed by the User CRD.
//
// The verifier is scoped to the portal-proof identity path. It does not
// validate console sessions or any other token shape: MaybeVerify returns
// (nil, false, nil) for tokens whose iss claim is not PortalJWTIssuer, so
// the middleware caller can fall through to the existing SessionService
// validation unchanged.
//
// Multiple public keys are supported via the kid header to enable key
// rotation: the portal mints with one kid, the server verifies against the
// matching key in the map.
type PortalJWTVerifier struct {
	publicKeys  map[string]ed25519.PublicKey
	users       PortalUserResolver
	replayCache *jtiReplayCache
	now         func() time.Time
}

// NewPortalJWTVerifier constructs a verifier. publicKeys is keyed by kid.
// At least one key is required; users must be non-nil for sub resolution.
func NewPortalJWTVerifier(publicKeys map[string]ed25519.PublicKey, users PortalUserResolver) (*PortalJWTVerifier, error) {
	if len(publicKeys) == 0 {
		return nil, errors.New("portal verifier requires at least one public key")
	}
	if users == nil {
		return nil, errors.New("portal verifier requires a user resolver")
	}
	for kid, pk := range publicKeys {
		if kid == "" {
			return nil, errors.New("portal verifier rejects empty kid")
		}
		if len(pk) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("portal verifier key %q has wrong size", kid)
		}
	}
	return &PortalJWTVerifier{
		publicKeys:  publicKeys,
		users:       users,
		replayCache: newJTIReplayCache(10 * time.Minute),
		now:         time.Now,
	}, nil
}

// ParsePortalPublicKeysPEM parses one or more PEM blocks containing
// Ed25519 public keys in SPKI form. Each block's kid is derived from the
// (kid="...") header line if present, otherwise from a stable fingerprint
// of the key bytes. Stage 1 ships with a single key; the map shape exists
// for Stage 4+ rotation work.
func ParsePortalPublicKeysPEM(pemData string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey)
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "PUBLIC KEY" {
			continue
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse portal public key: %w", err)
		}
		pk, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("portal public key is not Ed25519")
		}
		kid := block.Headers["kid"]
		if kid == "" {
			kid = fingerprintKid(pk)
		}
		keys[kid] = pk
	}
	if len(keys) == 0 {
		return nil, errors.New("no Ed25519 public keys found in PEM input")
	}
	return keys, nil
}

// fingerprintKid derives a short stable kid from the public key bytes when
// no kid header is supplied in the PEM block. Hex-encoded first 8 bytes of
// the raw public key.
func fingerprintKid(pk ed25519.PublicKey) string {
	const hex = "0123456789abcdef"
	out := make([]byte, 16)
	for i := 0; i < 8 && i < len(pk); i++ {
		out[i*2] = hex[pk[i]>>4]
		out[i*2+1] = hex[pk[i]&0x0f]
	}
	return string(out)
}

// MaybeVerify routes a Bearer token. Returns (session, true, nil) when the
// token is a verified portal proof; (nil, false, nil) when the token is NOT
// claimed by the portal path (caller should fall through to its existing
// validator); (nil, true, err) when the token IS claimed as a portal proof
// but failed verification (caller MUST reject the request rather than
// fall through).
//
// The (claimed) bit lets the middleware distinguish "different token shape,
// not my problem" from "I claim authority over this token and rejected it."
// Falling through after a claimed-but-failed portal proof would silently
// hand the token to SessionService.ValidateSession, which would interpret
// the same bytes as an HMAC session and reject it for a different reason;
// callers MUST surface the original rejection.
func (v *PortalJWTVerifier) MaybeVerify(ctx context.Context, tokenString string) (*UserSession, bool, error) {
	if v == nil || len(v.publicKeys) == 0 {
		return nil, false, nil
	}

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"EdDSA"}))
	unverified, _, err := parser.ParseUnverified(tokenString, &jwt.RegisteredClaims{})
	if err != nil {
		// Token isn't parseable as an Ed25519 JWT (or isn't a JWT at all);
		// not a portal proof. Fall through.
		return nil, false, nil
	}
	claims, ok := unverified.Claims.(*jwt.RegisteredClaims)
	if !ok {
		return nil, false, nil
	}
	if claims.Issuer != PortalJWTIssuer {
		return nil, false, nil
	}

	session, err := v.verifyClaimed(ctx, tokenString)
	return session, true, err
}

func (v *PortalJWTVerifier) verifyClaimed(ctx context.Context, tokenString string) (*UserSession, error) {
	var claims jwt.RegisteredClaims
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"EdDSA"}),
		jwt.WithIssuer(PortalJWTIssuer),
		jwt.WithAudience(PortalJWTAudience),
	)
	token, err := parser.ParseWithClaims(tokenString, &claims, func(t *jwt.Token) (interface{}, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, errors.New("portal proof missing kid header")
		}
		pk, found := v.publicKeys[kid]
		if !found {
			return nil, fmt.Errorf("portal proof kid %q not configured", kid)
		}
		return pk, nil
	})
	if err != nil {
		return nil, fmt.Errorf("portal proof verification failed: %w", err)
	}
	if !token.Valid {
		return nil, errors.New("portal proof not valid")
	}

	if claims.IssuedAt == nil || claims.ExpiresAt == nil {
		return nil, errors.New("portal proof missing iat or exp")
	}
	iat := claims.IssuedAt.Time
	exp := claims.ExpiresAt.Time
	if ttl := exp.Sub(iat); ttl > PortalJWTMaxTTL+5*time.Second {
		return nil, fmt.Errorf("portal proof TTL %s exceeds maximum %s", ttl, PortalJWTMaxTTL)
	}

	now := v.now()
	if now.After(exp) {
		return nil, errors.New("portal proof expired")
	}
	if claims.NotBefore != nil && now.Before(claims.NotBefore.Time) {
		return nil, errors.New("portal proof not yet valid")
	}

	if claims.ID == "" {
		return nil, errors.New("portal proof missing jti")
	}
	if !v.replayCache.checkAndStore(claims.ID, exp) {
		return nil, errors.New("portal proof jti replayed")
	}

	sub := strings.TrimSpace(claims.Subject)
	if sub == "" {
		return nil, errors.New("portal proof missing sub")
	}
	sub = NormalizeEmail(sub)

	userInfo, err := v.users.GetUserByEmail(ctx, sub)
	if err != nil {
		return nil, fmt.Errorf("portal proof sub not resolvable to user: %w", err)
	}
	if userInfo.Disabled {
		return nil, ErrUserDisabled
	}

	// PlatformRole derives from the User CRD spec. IsPlatformAdmin is the
	// back-compat field SessionService.CreateSession populates from the same
	// source; mirror that here so downstream consumers (UserSession.IsAdmin()
	// helpers, JSON serialization parity if a session is ever marshalled)
	// see the same shape.
	session := &UserSession{
		Subject:         userInfo.Name,
		Email:           NormalizeEmail(userInfo.Email),
		Name:            userInfo.DisplayName,
		Provider:        PortalJWTIssuer,
		Groups:          userInfo.LastSeenGroups,
		PlatformRole:    userInfo.PlatformRole,
		IsPlatformAdmin: userInfo.IsPlatformAdmin || userInfo.PlatformRole == RoleAdmin,
	}
	return session, nil
}

// jtiReplayCache stores recently-seen jti values until their natural exp.
// Bounded by the portal proof's 60-second TTL: in steady state the cache
// holds at most one proof per concurrent request in any 60-second window.
// Lazy sweep runs at most once per sweepInterval to reclaim expired entries
// without paying the cost on every request.
//
// Restart semantics: a process restart drops the cache. A proof from before
// the restart whose exp has not yet passed (worst case, 60 seconds) can be
// replayed once after restart. This is acceptable per the staged plan
// (Stage 1 trades a 60-second post-restart replay window against the cost
// of a persistent store; persistence is reconsidered if Stage 4 measurement
// shows replay-after-restart is a real concern).
type jtiReplayCache struct {
	mu        sync.Mutex
	seen      map[string]time.Time
	sweepIv   time.Duration
	lastSweep time.Time
	now       func() time.Time
}

func newJTIReplayCache(sweepInterval time.Duration) *jtiReplayCache {
	return &jtiReplayCache{
		seen:      make(map[string]time.Time),
		sweepIv:   sweepInterval,
		lastSweep: time.Now(),
		now:       time.Now,
	}
}

// checkAndStore records a new jti. Returns false if the jti was already
// recorded AND its prior recorded exp has not yet passed (a replay attempt);
// returns true if the jti is new or its prior recording had expired naturally.
func (c *jtiReplayCache) checkAndStore(jti string, exp time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if priorExp, ok := c.seen[jti]; ok && now.Before(priorExp) {
		return false
	}
	c.seen[jti] = exp
	if now.Sub(c.lastSweep) >= c.sweepIv {
		for k, e := range c.seen {
			if now.After(e) {
				delete(c.seen, k)
			}
		}
		c.lastSweep = now
	}
	return true
}
