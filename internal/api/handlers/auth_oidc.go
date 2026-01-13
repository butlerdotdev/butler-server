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
	"log/slog"
	"net/http"
	"time"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/config"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	oidcProvider   *auth.OIDCProvider
	sessionService *auth.SessionService
	teamResolver   *auth.TeamResolver
	stateStore     *auth.StateStore
	config         *config.Config
	logger         *slog.Logger
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(
	oidcProvider *auth.OIDCProvider,
	sessionService *auth.SessionService,
	teamResolver *auth.TeamResolver,
	cfg *config.Config,
	logger *slog.Logger,
) *AuthHandler {
	return &AuthHandler{
		oidcProvider:   oidcProvider,
		sessionService: sessionService,
		teamResolver:   teamResolver,
		stateStore:     auth.NewStateStore(10 * time.Minute),
		config:         cfg,
		logger:         logger,
	}
}

// LoginResponse is returned after successful login.
type LoginResponse struct {
	User UserResponse `json:"user"`
}

// UserResponse represents the user data returned to the client.
type UserResponse struct {
	Email   string                `json:"email"`
	Name    string                `json:"name"`
	Picture string                `json:"picture,omitempty"`
	Teams   []auth.TeamMembership `json:"teams"`
}

// Login initiates the OIDC login flow.
// GET /api/auth/login -> Redirect to IdP
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if h.oidcProvider == nil {
		h.logger.Error("OIDC provider not configured")
		writeError(w, http.StatusServiceUnavailable, "SSO is not configured")
		return
	}

	// Generate authorization URL with state
	authURL, state, err := h.oidcProvider.AuthCodeURL()
	if err != nil {
		h.logger.Error("Failed to generate auth URL", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to initiate login")
		return
	}

	// Store state for validation
	h.stateStore.Store(state)

	// Redirect to IdP
	http.Redirect(w, r, authURL, http.StatusFound)
}

// Callback handles the OIDC callback after user authenticates.
// GET /api/auth/callback?code=xxx&state=xxx -> Set session, redirect to app
func (h *AuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	if h.oidcProvider == nil {
		writeError(w, http.StatusServiceUnavailable, "SSO is not configured")
		return
	}

	// Validate state
	state := r.URL.Query().Get("state")
	if !h.stateStore.Validate(state) {
		h.logger.Warn("Invalid OAuth state", "state", state)
		writeError(w, http.StatusBadRequest, "Invalid OAuth state")
		return
	}

	// Check for error from IdP
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		h.logger.Warn("OAuth error from IdP", "error", errParam, "description", errDesc)
		// Redirect to login page with error
		http.Redirect(w, r, "/?error="+errParam, http.StatusFound)
		return
	}

	// Exchange code for tokens
	code := r.URL.Query().Get("code")
	if code == "" {
		writeError(w, http.StatusBadRequest, "Missing authorization code")
		return
	}

	claims, err := h.oidcProvider.Exchange(r.Context(), code)
	if err != nil {
		h.logger.Error("Failed to exchange code", "error", err)
		http.Redirect(w, r, "/?error=token_exchange_failed", http.StatusFound)
		return
	}

	// Resolve team memberships
	teams, err := h.teamResolver.ResolveTeams(r.Context(), claims.Email, claims.Groups)
	if err != nil {
		h.logger.Warn("Failed to resolve teams", "email", claims.Email, "error", err)
		// Continue with empty teams - user can still log in
		teams = []auth.TeamMembership{}
	}

	// Create user session
	user := &auth.UserSession{
		Subject:  claims.Subject,
		Email:    claims.Email,
		Name:     claims.Name,
		Picture:  claims.Picture,
		Provider: h.oidcProvider.GetDisplayName(),
		Groups:   claims.Groups,
		Teams:    teams,
	}

	// Generate session token
	token, err := h.sessionService.CreateSession(user)
	if err != nil {
		h.logger.Error("Failed to create session", "error", err)
		http.Redirect(w, r, "/?error=session_creation_failed", http.StatusFound)
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "butler_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || h.config.Auth.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.config.Auth.SessionExpiry.Seconds()),
	})

	h.logger.Info("User logged in",
		"email", claims.Email,
		"teams", len(teams),
	)

	// Redirect to app
	redirectURL := "/"
	if returnTo := r.URL.Query().Get("return_to"); returnTo != "" {
		// Validate return_to is a relative path (security)
		if len(returnTo) > 0 && returnTo[0] == '/' && (len(returnTo) == 1 || returnTo[1] != '/') {
			redirectURL = returnTo
		}
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// Logout clears the session and logs the user out.
// POST /api/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "butler_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || h.config.Auth.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// Me returns the current user's information.
// GET /api/auth/me
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	response := UserResponse{
		Email:   user.Email,
		Name:    user.Name,
		Picture: user.Picture,
		Teams:   user.Teams,
	}

	writeJSON(w, http.StatusOK, response)
}

// Refresh refreshes the session token.
// POST /api/auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	// Get current session from cookie
	cookie, err := r.Cookie("butler_session")
	if err != nil {
		writeError(w, http.StatusUnauthorized, "No session")
		return
	}

	// Refresh the session
	newToken, err := h.sessionService.RefreshSession(cookie.Value)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Session expired")
		return
	}

	// Set new cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "butler_session",
		Value:    newToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || h.config.Auth.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.config.Auth.SessionExpiry.Seconds()),
	})

	// Return user info
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	response := LoginResponse{
		User: UserResponse{
			Email:   user.Email,
			Name:    user.Name,
			Picture: user.Picture,
			Teams:   user.Teams,
		},
	}

	writeJSON(w, http.StatusOK, response)
}

// GetProviders returns available identity providers.
// GET /api/auth/providers
func (h *AuthHandler) GetProviders(w http.ResponseWriter, r *http.Request) {
	providers := []ProviderInfo{}

	if h.oidcProvider != nil {
		providers = append(providers, ProviderInfo{
			Name:        h.oidcProvider.GetDisplayName(),
			Type:        "oidc",
			LoginURL:    "/api/auth/login",
			IconURL:     getProviderIcon(h.oidcProvider.GetDisplayName()),
			ButtonLabel: "Sign in with " + h.oidcProvider.GetDisplayName(),
		})
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"providers": providers,
	})
}

// ProviderInfo describes an available identity provider.
type ProviderInfo struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	LoginURL    string `json:"loginUrl"`
	IconURL     string `json:"iconUrl,omitempty"`
	ButtonLabel string `json:"buttonLabel"`
}

// getProviderIcon returns an icon URL for known providers.
func getProviderIcon(providerName string) string {
	switch providerName {
	case "Google":
		return "/icons/google.svg"
	case "Microsoft":
		return "/icons/microsoft.svg"
	case "Okta":
		return "/icons/okta.svg"
	default:
		return ""
	}
}

// Teams returns the teams for the current user.
// GET /api/auth/teams
func (h *AuthHandler) Teams(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	// Get detailed team info
	teams, err := h.teamResolver.ListTeamsForUser(r.Context(), user.Email, user.Groups)
	if err != nil {
		h.logger.Error("Failed to list teams", "error", err)
		// Fall back to basic team info from session
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"teams": user.Teams,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"teams": teams,
	})
}
