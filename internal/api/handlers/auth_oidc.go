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
	"encoding/json"
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
	userService    *auth.UserService
	stateStore     *auth.StateStore
	config         *config.Config
	logger         *slog.Logger
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(
	oidcProvider *auth.OIDCProvider,
	sessionService *auth.SessionService,
	teamResolver *auth.TeamResolver,
	userService *auth.UserService,
	cfg *config.Config,
	logger *slog.Logger,
) *AuthHandler {
	return &AuthHandler{
		oidcProvider:   oidcProvider,
		sessionService: sessionService,
		teamResolver:   teamResolver,
		userService:    userService,
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
	Email           string                `json:"email"`
	Name            string                `json:"name"`
	Picture         string                `json:"picture,omitempty"`
	Teams           []auth.TeamMembership `json:"teams"`
	IsPlatformAdmin bool                  `json:"isPlatformAdmin,omitempty"`
}

// Login initiates the OIDC login flow.
// GET /api/auth/login/sso -> Redirect to IdP
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	if h.oidcProvider == nil {
		h.logger.Error("OIDC provider not configured")
		writeError(w, http.StatusServiceUnavailable, "SSO is not configured")
		return
	}

	authURL, state, err := h.oidcProvider.AuthCodeURL()
	if err != nil {
		h.logger.Error("Failed to generate auth URL", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to initiate login")
		return
	}

	h.stateStore.Store(state)
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
		errorURL := "/?error=" + errParam
		if h.config.FrontendURL != "" {
			errorURL = h.config.FrontendURL + "/?error=" + errParam
		}
		http.Redirect(w, r, errorURL, http.StatusFound)
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
		errorURL := "/?error=token_exchange_failed"
		if h.config.FrontendURL != "" {
			errorURL = h.config.FrontendURL + errorURL
		}
		http.Redirect(w, r, errorURL, http.StatusFound)
		return
	}

	// IMPORTANT: Ensure User CRD exists for this SSO user
	// This is called on EVERY SSO login to create/update the user record
	var isPlatformAdmin bool
	user, err := h.userService.EnsureSSOUser(r.Context(), auth.EnsureSSOUserRequest{
		Email:       claims.Email,
		DisplayName: claims.Name,
		Picture:     claims.Picture,
		Provider:    h.oidcProvider.GetDisplayName(),
		Subject:     claims.Subject,
	})
	if err != nil {
		h.logger.Error("Failed to ensure SSO user", "email", claims.Email, "error", err)
		// Don't fail login - user can still authenticate, just won't have User CRD
		// This is a graceful degradation
	} else {
		h.logger.Info("SSO user ensured", "username", user.Name, "email", user.Email)

		// SECURITY: Check if user is disabled BEFORE creating session
		if user.Disabled {
			h.logger.Warn("Disabled user attempted SSO login", "email", claims.Email)
			errorURL := "/?error=account_disabled"
			if h.config.FrontendURL != "" {
				errorURL = h.config.FrontendURL + errorURL
			}
			http.Redirect(w, r, errorURL, http.StatusFound)
			return
		}

		// Check if user has platform admin privileges from User CRD
		isPlatformAdmin = user.IsPlatformAdmin
	}

	// Resolve team memberships
	teams, err := h.teamResolver.ResolveTeams(r.Context(), claims.Email, claims.Groups)
	if err != nil {
		h.logger.Warn("Failed to resolve teams", "email", claims.Email, "error", err)
		teams = []auth.TeamMembership{}
	}

	// Create user session
	session := &auth.UserSession{
		Subject:         claims.Subject,
		Email:           claims.Email,
		Name:            claims.Name,
		Picture:         claims.Picture,
		Provider:        h.oidcProvider.GetDisplayName(),
		Groups:          claims.Groups,
		Teams:           teams,
		IsPlatformAdmin: isPlatformAdmin,
	}

	// Generate session token
	token, err := h.sessionService.CreateSession(session)
	if err != nil {
		h.logger.Error("Failed to create session", "error", err)
		errorURL := "/?error=session_creation_failed"
		if h.config.FrontendURL != "" {
			errorURL = h.config.FrontendURL + errorURL
		}
		http.Redirect(w, r, errorURL, http.StatusFound)
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

	h.logger.Info("User logged in via SSO",
		"email", claims.Email,
		"teams", len(teams),
		"isPlatformAdmin", isPlatformAdmin,
	)

	// Redirect to app
	redirectURL := "/"
	if h.config.FrontendURL != "" {
		redirectURL = h.config.FrontendURL
	}
	if returnTo := r.URL.Query().Get("return_to"); returnTo != "" {
		if len(returnTo) > 0 && returnTo[0] == '/' && (len(returnTo) == 1 || returnTo[1] != '/') {
			if h.config.FrontendURL != "" {
				redirectURL = h.config.FrontendURL + returnTo
			} else {
				redirectURL = returnTo
			}
		}
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// InternalUserLogin handles username/password login for internal users.
// POST /api/auth/login
func (h *AuthHandler) InternalUserLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"` // Can be email or username
		Email    string `json:"email"`    // Alternative field
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Accept either username or email field
	identifier := req.Username
	if identifier == "" {
		identifier = req.Email
	}

	if identifier == "" || req.Password == "" {
		writeError(w, http.StatusBadRequest, "Email/username and password are required")
		return
	}

	// Try internal user auth first
	user, err := h.userService.AuthenticateInternal(r.Context(), identifier, req.Password)
	if err != nil {
		// If internal auth fails, try legacy admin auth
		if h.config.Auth.AdminUsername != "" && h.config.Auth.AdminPassword != "" {
			if identifier == h.config.Auth.AdminUsername && req.Password == h.config.Auth.AdminPassword {
				h.createLegacyAdminSession(w, r)
				return
			}
		}

		switch err {
		case auth.ErrInvalidCredentials, auth.ErrUserNotFound:
			writeError(w, http.StatusUnauthorized, "Invalid email or password")
		case auth.ErrUserDisabled:
			writeError(w, http.StatusForbidden, "Account is disabled")
		case auth.ErrUserLocked:
			writeError(w, http.StatusForbidden, "Account is temporarily locked due to too many failed attempts")
		case auth.ErrUserPending:
			writeError(w, http.StatusForbidden, "Please complete registration using your invite link")
		default:
			h.logger.Error("Login failed", "error", err)
			writeError(w, http.StatusInternalServerError, "Login failed")
		}
		return
	}

	// Resolve team memberships
	teams, err := h.teamResolver.ResolveTeams(r.Context(), user.Email, nil)
	if err != nil {
		h.logger.Warn("Failed to resolve teams", "email", user.Email, "error", err)
		teams = []auth.TeamMembership{}
	}

	// Create session
	session := &auth.UserSession{
		Subject:         "internal:" + user.Name,
		Email:           user.Email,
		Name:            user.DisplayName,
		Picture:         user.Avatar,
		Provider:        "internal",
		Teams:           teams,
		IsPlatformAdmin: user.IsPlatformAdmin, // Propagate from User CRD
	}

	if session.Name == "" {
		session.Name = user.Name
	}

	token, err := h.sessionService.CreateSession(session)
	if err != nil {
		h.logger.Error("Failed to create session", "error", err)
		writeError(w, http.StatusInternalServerError, "Login failed")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "butler_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || h.config.Auth.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.config.Auth.SessionExpiry.Seconds()),
	})

	h.logger.Info("User logged in via password",
		"email", user.Email,
		"teams", len(teams),
		"isPlatformAdmin", user.IsPlatformAdmin,
	)

	writeJSON(w, http.StatusOK, LoginResponse{
		User: UserResponse{
			Email:           user.Email,
			Name:            session.Name,
			Picture:         user.Avatar,
			Teams:           teams,
			IsPlatformAdmin: user.IsPlatformAdmin,
		},
	})
}

// LegacyLogin handles the legacy admin login (for backwards compatibility).
// POST /api/auth/login/legacy
func (h *AuthHandler) LegacyLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Check legacy admin credentials
	if req.Username != h.config.Auth.AdminUsername || req.Password != h.config.Auth.AdminPassword {
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	h.createLegacyAdminSession(w, r)
}

// Logout handles user logout.
// POST /api/auth/logout
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Clear session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "butler_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		MaxAge:   -1,
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// Refresh refreshes the session token.
// POST /api/auth/refresh
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	// Create new session token with fresh data
	token, err := h.sessionService.CreateSession(user)
	if err != nil {
		h.logger.Error("Failed to refresh session", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to refresh session")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "butler_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || h.config.Auth.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.config.Auth.SessionExpiry.Seconds()),
	})

	writeJSON(w, http.StatusOK, map[string]string{"status": "refreshed"})
}

// Me returns the current user's information.
// GET /api/auth/me
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	writeJSON(w, http.StatusOK, UserResponse{
		Email:           user.Email,
		Name:            user.Name,
		Picture:         user.Picture,
		Teams:           user.Teams,
		IsPlatformAdmin: user.IsPlatformAdmin,
	})
}

// Teams returns the current user's team memberships.
// GET /api/auth/teams
func (h *AuthHandler) Teams(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"teams":           user.Teams,
		"isPlatformAdmin": user.IsPlatformAdmin,
	})
}

// GetProviders returns available authentication providers.
// GET /api/auth/providers
func (h *AuthHandler) GetProviders(w http.ResponseWriter, r *http.Request) {
	// SSO providers only - these have login URLs for redirect
	providers := []map[string]interface{}{}

	// Add OIDC if configured
	if h.oidcProvider != nil {
		providers = append(providers, map[string]interface{}{
			"name":        h.oidcProvider.GetDisplayName(),
			"type":        "oidc",
			"loginUrl":    "/api/auth/login/sso",
			"buttonLabel": "Sign in with " + h.oidcProvider.GetDisplayName(),
		})
	}

	// Internal users and legacy auth are separate flags, not providers
	// The frontend shows a password form when these are true
	hasInternalUsers := true // Always allow internal user login
	hasLegacyAuth := h.config.Auth.AdminUsername != "" && h.config.Auth.AdminPassword != ""

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"providers":        providers,
		"internalUsers":    hasInternalUsers,
		"legacyAuth":       hasLegacyAuth,
		"passwordLoginUrl": "/api/auth/login",
	})
}

// createLegacyAdminSession creates a session for the legacy admin user (bootstrap/dev mode).
// The legacy admin is a PLATFORM ADMIN with full access to everything.
func (h *AuthHandler) createLegacyAdminSession(w http.ResponseWriter, r *http.Request) {
	// Create session for the admin user with PLATFORM ADMIN privileges
	// Platform admins bypass team checks entirely
	session := &auth.UserSession{
		Subject:         "legacy:admin",
		Email:           "admin@butler.local",
		Name:            "Platform Administrator",
		Provider:        "legacy",
		IsPlatformAdmin: true,                    // THIS IS THE KEY FIX
		Teams:           []auth.TeamMembership{}, // No teams needed for platform admin
	}

	token, err := h.sessionService.CreateSession(session)
	if err != nil {
		h.logger.Error("Failed to create session", "error", err)
		writeError(w, http.StatusInternalServerError, "Login failed")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "butler_session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || h.config.Auth.SecureCookies,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(h.config.Auth.SessionExpiry.Seconds()),
	})

	h.logger.Info("Platform admin logged in via legacy auth")

	writeJSON(w, http.StatusOK, LoginResponse{
		User: UserResponse{
			Email:           session.Email,
			Name:            session.Name,
			Teams:           session.Teams,
			IsPlatformAdmin: true,
		},
	})
}
