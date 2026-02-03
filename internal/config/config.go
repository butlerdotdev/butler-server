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

package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds the server configuration.
type Config struct {
	Server          ServerConfig
	Auth            AuthConfig
	OIDC            OIDCConfig
	TenantNamespace string
	SystemNamespace string
	FrontendURL     string // For dev mode when frontend runs separately
}

// ServerConfig holds general server configuration.
type ServerConfig struct {
	// BaseURL is the public URL of the Butler Console
	// Used for generating invite links, OAuth redirects, etc.
	// Example: https://butler.example.com
	BaseURL string
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	// JWTSecret is used to sign session tokens
	JWTSecret string

	// SessionExpiry is how long sessions last
	SessionExpiry time.Duration

	// SecureCookies forces Secure flag on cookies (should be true in production)
	SecureCookies bool

	// Legacy basic auth (deprecated, will be removed)
	AdminUsername string
	AdminPassword string
}

// OIDCConfig holds OIDC provider configuration.
// Can be set via environment variables or loaded from IdentityProvider CRD.
type OIDCConfig struct {
	// Enabled indicates if OIDC is configured
	Enabled bool

	// IssuerURL is the OIDC provider's issuer URL
	// Example: https://accounts.google.com
	IssuerURL string

	// ClientID is the OAuth2 client ID
	ClientID string

	// ClientSecret is the OAuth2 client secret
	ClientSecret string

	// RedirectURL is the OAuth2 callback URL
	// Example: https://butler.example.com/api/auth/callback
	RedirectURL string

	// Scopes are the OAuth2 scopes to request
	// Defaults to: openid, email, profile
	Scopes []string

	// HostedDomain restricts authentication to a specific domain (Google only)
	HostedDomain string

	// GroupsClaim is the JWT claim for group memberships
	// Default: "groups"
	GroupsClaim string

	// EmailClaim is the JWT claim for email
	// Default: "email"
	EmailClaim string

	// GoogleWorkspace for Admin SDK group fetching
	GoogleServiceAccountJSON string `env:"GOOGLE_SERVICE_ACCOUNT_JSON"`
	GoogleAdminEmail         string `env:"GOOGLE_ADMIN_EMAIL"`
}

// Load loads configuration from environment variables.
func Load() *Config {
	cfg := &Config{
		Server: ServerConfig{
			BaseURL: getEnv("BUTLER_BASE_URL", "http://localhost:8080"),
		},
		Auth: AuthConfig{
			JWTSecret:     getEnv("BUTLER_JWT_SECRET", "butler-dev-secret-change-me-in-production"),
			SessionExpiry: getDurationEnv("BUTLER_SESSION_EXPIRY", 24*time.Hour),
			SecureCookies: getBoolEnv("BUTLER_SECURE_COOKIES", false),
			// Legacy - deprecated
			AdminUsername: getEnv("BUTLER_ADMIN_USERNAME", "admin"),
			AdminPassword: getEnv("BUTLER_ADMIN_PASSWORD", ""),
		},
		OIDC: OIDCConfig{
			Enabled:                  getBoolEnv("BUTLER_OIDC_ENABLED", false),
			IssuerURL:                getEnv("BUTLER_OIDC_ISSUER_URL", ""),
			ClientID:                 getEnv("BUTLER_OIDC_CLIENT_ID", ""),
			ClientSecret:             getEnv("BUTLER_OIDC_CLIENT_SECRET", ""),
			RedirectURL:              getEnv("BUTLER_OIDC_REDIRECT_URL", ""),
			HostedDomain:             getEnv("BUTLER_OIDC_HOSTED_DOMAIN", ""),
			GroupsClaim:              getEnv("BUTLER_OIDC_GROUPS_CLAIM", "groups"),
			EmailClaim:               getEnv("BUTLER_OIDC_EMAIL_CLAIM", "email"),
			GoogleServiceAccountJSON: getEnv("GOOGLE_SERVICE_ACCOUNT_JSON", ""),
			GoogleAdminEmail:         getEnv("GOOGLE_ADMIN_EMAIL", ""),
		},
		TenantNamespace: getEnv("BUTLER_TENANT_NAMESPACE", "butler-tenants"),
		SystemNamespace: getEnv("BUTLER_SYSTEM_NAMESPACE", "butler-system"),
		FrontendURL:     getEnv("BUTLER_FRONTEND_URL", ""), // e.g., http://localhost:3000 for dev
	}

	// Auto-enable OIDC if issuer URL is set
	if cfg.OIDC.IssuerURL != "" && cfg.OIDC.ClientID != "" {
		cfg.OIDC.Enabled = true
	}

	// Parse scopes if provided
	if scopesStr := getEnv("BUTLER_OIDC_SCOPES", ""); scopesStr != "" {
		cfg.OIDC.Scopes = parseScopes(scopesStr)
	}

	return cfg
}

// IsOIDCConfigured returns true if OIDC is properly configured.
func (c *Config) IsOIDCConfigured() bool {
	return c.OIDC.Enabled &&
		c.OIDC.IssuerURL != "" &&
		c.OIDC.ClientID != "" &&
		c.OIDC.ClientSecret != "" &&
		c.OIDC.RedirectURL != ""
}

// IsLegacyAuthEnabled returns true if legacy username/password auth is enabled.
// This is a fallback for development when OIDC is not configured.
func (c *Config) IsLegacyAuthEnabled() bool {
	return !c.IsOIDCConfigured() && c.Auth.AdminPassword != ""
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if b, err := strconv.ParseBool(value); err == nil {
			return b
		}
	}
	return defaultValue
}

func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
	}
	return defaultValue
}

func parseScopes(s string) []string {
	var scopes []string
	current := ""
	for _, c := range s {
		if c == ',' || c == ' ' {
			if current != "" {
				scopes = append(scopes, current)
				current = ""
			}
		} else {
			current += string(c)
		}
	}
	if current != "" {
		scopes = append(scopes, current)
	}
	return scopes
}

// GoogleWorkspaceConfig returns OIDC config preset for Google Workspace.
func GoogleWorkspaceConfig(clientID, clientSecret, redirectURL, hostedDomain string) OIDCConfig {
	return OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://accounts.google.com",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		HostedDomain: hostedDomain,
		Scopes:       []string{"openid", "email", "profile"},
		GroupsClaim:  "", // Google doesn't include groups by default
		EmailClaim:   "email",
	}
}

// MicrosoftEntraConfig returns OIDC config preset for Microsoft Entra ID.
func MicrosoftEntraConfig(tenantID, clientID, clientSecret, redirectURL string) OIDCConfig {
	return OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://login.microsoftonline.com/" + tenantID + "/v2.0",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "email", "profile"},
		GroupsClaim:  "groups",
		EmailClaim:   "email",
	}
}

// OktaConfig returns OIDC config preset for Okta.
func OktaConfig(domain, clientID, clientSecret, redirectURL string) OIDCConfig {
	return OIDCConfig{
		Enabled:      true,
		IssuerURL:    "https://" + domain + ".okta.com",
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "email", "profile", "groups"},
		GroupsClaim:  "groups",
		EmailClaim:   "email",
	}
}
