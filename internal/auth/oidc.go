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
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

var (
	ErrOIDCNotConfigured = errors.New("OIDC is not configured")
	ErrInvalidState      = errors.New("invalid OAuth state")
	ErrTokenExchange     = errors.New("failed to exchange token")
	ErrIDTokenMissing    = errors.New("ID token missing from response")
	ErrClaimsExtraction  = errors.New("failed to extract claims from token")
)

// OIDCConfig holds OIDC provider configuration.
type OIDCConfig struct {
	// IssuerURL is the OIDC provider's issuer URL (e.g., https://accounts.google.com)
	IssuerURL string

	// ClientID is the OAuth2 client ID
	ClientID string

	// ClientSecret is the OAuth2 client secret
	ClientSecret string

	// RedirectURL is the callback URL (e.g., https://butler.example.com/api/auth/callback)
	RedirectURL string

	// Scopes are the OAuth2 scopes to request (defaults to openid, email, profile)
	Scopes []string

	// HostedDomain restricts authentication to a specific domain (Google Workspace only)
	HostedDomain string

	// GroupsClaim is the JWT claim containing group memberships (default: "groups")
	GroupsClaim string

	// EmailClaim is the JWT claim containing the user's email (default: "email")
	EmailClaim string

	// DisplayName is the display name for this provider (e.g., "Google", "Okta")
	DisplayName string

	// GoogleWorkspace holds optional Google Admin SDK config for fetching groups.
	// Required for Google Workspace because OIDC tokens don't include groups.
	GoogleWorkspace *GoogleGroupsConfig
}

// OIDCProvider handles OIDC authentication flows.
type OIDCProvider struct {
	config        *OIDCConfig
	provider      *oidc.Provider
	oauth2Config  *oauth2.Config
	verifier      *oidc.IDTokenVerifier
	groupsFetcher *GoogleGroupsFetcher
	logger        *slog.Logger
}

// OIDCClaims represents the claims extracted from an OIDC ID token.
type OIDCClaims struct {
	Subject       string   `json:"sub"`
	Email         string   `json:"email"`
	EmailVerified bool     `json:"email_verified"`
	Name          string   `json:"name"`
	Picture       string   `json:"picture"`
	Groups        []string `json:"groups"`
	HostedDomain  string   `json:"hd"` // Google-specific
}

// NewOIDCProvider creates a new OIDC provider from configuration.
// This performs OIDC Discovery to automatically configure endpoints.
func NewOIDCProvider(ctx context.Context, cfg *OIDCConfig, logger *slog.Logger) (*OIDCProvider, error) {
	if cfg == nil || cfg.IssuerURL == "" {
		return nil, ErrOIDCNotConfigured
	}

	if logger == nil {
		logger = slog.Default()
	}

	// Perform OIDC Discovery
	provider, err := oidc.NewProvider(ctx, cfg.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to discover OIDC provider: %w", err)
	}

	// Set default scopes if not specified
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}

	// Build OAuth2 config from discovered endpoints
	oauth2Config := &oauth2.Config{
		ClientID:     cfg.ClientID,
		ClientSecret: cfg.ClientSecret,
		RedirectURL:  cfg.RedirectURL,
		Endpoint:     provider.Endpoint(),
		Scopes:       scopes,
	}

	// Create ID token verifier
	verifier := provider.Verifier(&oidc.Config{
		ClientID: cfg.ClientID,
	})

	p := &OIDCProvider{
		config:       cfg,
		provider:     provider,
		oauth2Config: oauth2Config,
		verifier:     verifier,
		logger:       logger,
	}

	// Initialize Google Groups fetcher if configured
	if cfg.GoogleWorkspace != nil {
		fetcher, err := NewGoogleGroupsFetcher(ctx, cfg.GoogleWorkspace, logger)
		if err != nil {
			logger.Warn("Failed to initialize Google Groups fetcher - group sync disabled",
				"error", err,
			)
		} else {
			p.groupsFetcher = fetcher
			logger.Info("Google Workspace group sync enabled",
				"adminEmail", cfg.GoogleWorkspace.AdminEmail,
				"domain", cfg.GoogleWorkspace.Domain,
			)
		}
	}

	return p, nil
}

// AuthCodeURL generates the URL to redirect users to for authentication.
// Returns the URL and a state token that must be validated on callback.
func (p *OIDCProvider) AuthCodeURL() (string, string, error) {
	state, err := generateState()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate state: %w", err)
	}

	opts := []oauth2.AuthCodeOption{
		oauth2.AccessTypeOffline,
		// Always show account picker so user can choose correct account
		oauth2.SetAuthURLParam("prompt", "select_account"),
	}

	// Add Google-specific hosted domain restriction
	if p.config.HostedDomain != "" {
		opts = append(opts, oauth2.SetAuthURLParam("hd", p.config.HostedDomain))
	}

	url := p.oauth2Config.AuthCodeURL(state, opts...)
	return url, state, nil
}

// Exchange exchanges an authorization code for tokens and validates the ID token.
func (p *OIDCProvider) Exchange(ctx context.Context, code string) (*OIDCClaims, error) {
	// Exchange code for tokens
	token, err := p.oauth2Config.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchange, err)
	}

	// Extract ID token from response
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, ErrIDTokenMissing
	}

	// Verify and parse the ID token
	idToken, err := p.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify ID token: %w", err)
	}

	// Extract claims
	claims, err := p.extractClaims(idToken)
	if err != nil {
		return nil, err
	}

	// Validate hosted domain if configured (Google Workspace)
	if p.config.HostedDomain != "" && claims.HostedDomain != p.config.HostedDomain {
		return nil, fmt.Errorf("user domain %q does not match required domain %q",
			claims.HostedDomain, p.config.HostedDomain)
	}

	// Fetch Google Workspace groups if configured and groups are empty
	// This is the key integration point for Google Workspace group sync
	if len(claims.Groups) == 0 && p.groupsFetcher != nil {
		groups, err := p.groupsFetcher.FetchUserGroups(ctx, claims.Email)
		if err != nil {
			p.logger.Warn("Failed to fetch Google Workspace groups",
				"email", claims.Email,
				"error", err,
			)
		} else {
			claims.Groups = groups
			p.logger.Info("Populated groups from Google Workspace Admin SDK",
				"email", claims.Email,
				"groupCount", len(groups),
				"groups", groups,
			)
		}
	}

	return claims, nil
}

// extractClaims extracts claims from an ID token.
func (p *OIDCProvider) extractClaims(idToken *oidc.IDToken) (*OIDCClaims, error) {
	// First, extract standard claims
	var claims OIDCClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrClaimsExtraction, err)
	}

	claims.Subject = idToken.Subject

	// If a custom groups claim is specified, try to extract it
	if p.config.GroupsClaim != "" && p.config.GroupsClaim != "groups" {
		var customClaims map[string]interface{}
		if err := idToken.Claims(&customClaims); err == nil {
			if groups, ok := customClaims[p.config.GroupsClaim].([]interface{}); ok {
				for _, g := range groups {
					if gs, ok := g.(string); ok {
						claims.Groups = append(claims.Groups, gs)
					}
				}
			}
		}
	}

	// If a custom email claim is specified, try to extract it
	if p.config.EmailClaim != "" && p.config.EmailClaim != "email" {
		var customClaims map[string]interface{}
		if err := idToken.Claims(&customClaims); err == nil {
			if email, ok := customClaims[p.config.EmailClaim].(string); ok {
				claims.Email = email
			}
		}
	}

	return &claims, nil
}

// GetIssuer returns the OIDC issuer URL.
func (p *OIDCProvider) GetIssuer() string {
	return p.config.IssuerURL
}

// GetDisplayName returns a display name for this provider.
func (p *OIDCProvider) GetDisplayName() string {
	if p.config.DisplayName != "" {
		return p.config.DisplayName
	}
	switch {
	case contains(p.config.IssuerURL, "accounts.google.com"):
		return "Google"
	case contains(p.config.IssuerURL, "login.microsoftonline.com"):
		return "Microsoft"
	case contains(p.config.IssuerURL, "okta.com"):
		return "Okta"
	case contains(p.config.IssuerURL, "auth0.com"):
		return "Auth0"
	default:
		return "SSO"
	}
}

// HasGroupSync returns true if Google Workspace group sync is configured.
func (p *OIDCProvider) HasGroupSync() bool {
	return p.groupsFetcher != nil
}

// generateState generates a cryptographically random state token.
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

// contains checks if s contains substr.
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// StateStore provides state token storage and validation.
// In production, this should be backed by Redis or similar for horizontal scaling.
type StateStore struct {
	states map[string]time.Time
	expiry time.Duration
}

// NewStateStore creates a new state store with the given expiry duration.
func NewStateStore(expiry time.Duration) *StateStore {
	return &StateStore{
		states: make(map[string]time.Time),
		expiry: expiry,
	}
}

// Store stores a state token.
func (s *StateStore) Store(state string) {
	s.states[state] = time.Now().Add(s.expiry)
	// Clean up expired states (simple inline cleanup)
	s.cleanup()
}

// Validate validates and consumes a state token.
func (s *StateStore) Validate(state string) bool {
	expiry, ok := s.states[state]
	if !ok {
		return false
	}
	delete(s.states, state)
	return time.Now().Before(expiry)
}

// cleanup removes expired states.
func (s *StateStore) cleanup() {
	now := time.Now()
	for state, expiry := range s.states {
		if now.After(expiry) {
			delete(s.states, state)
		}
	}
}
