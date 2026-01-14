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
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/go-chi/chi/v5"
)

// UserHandler handles user management endpoints.
type UserHandler struct {
	userService    *auth.UserService
	sessionService *auth.SessionService
	teamResolver   *auth.TeamResolver
	config         *config.Config
	logger         *slog.Logger
}

// NewUserHandler creates a new user handler.
func NewUserHandler(
	userService *auth.UserService,
	sessionService *auth.SessionService,
	teamResolver *auth.TeamResolver,
	cfg *config.Config,
	logger *slog.Logger,
) *UserHandler {
	return &UserHandler{
		userService:    userService,
		sessionService: sessionService,
		teamResolver:   teamResolver,
		config:         cfg,
		logger:         logger,
	}
}

// ---- Request/Response Types ----

// CreateUserRequest is the request body for creating a new internal user.
type CreateUserRequest struct {
	Username    string `json:"username,omitempty"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName,omitempty"`
}

// UserListResponse represents a user in the list API response.
type UserListResponse struct {
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	DisplayName string   `json:"displayName,omitempty"`
	Avatar      string   `json:"avatar,omitempty"`
	Phase       string   `json:"phase"`
	Disabled    bool     `json:"disabled"`
	AuthType    string   `json:"authType"` // "internal" or "sso"
	SSOProvider string   `json:"ssoProvider,omitempty"`
	Teams       []string `json:"teams,omitempty"`
}

// CreateUserResponseBody is the response for user creation.
type CreateUserResponseBody struct {
	User      UserListResponse `json:"user"`
	InviteURL string           `json:"inviteUrl"`
}

// ValidateInviteResponse is returned when validating an invite token.
type ValidateInviteResponse struct {
	Valid       bool   `json:"valid"`
	Email       string `json:"email,omitempty"`
	DisplayName string `json:"displayName,omitempty"`
}

// SetPasswordRequest is the request body for setting a password.
type SetPasswordRequest struct {
	Token    string `json:"token"`
	Password string `json:"password"`
}

// ---- User List Endpoint (any authenticated user) ----

// ListUsers returns all users from User CRDs.
// GET /api/users (accessible to any authenticated user)
func (h *UserHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	// Get all users from User CRDs
	users, err := h.userService.ListUsers(r.Context())
	if err != nil {
		h.logger.Error("Failed to list users", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to list users")
		return
	}

	// Build response with team membership info
	response := make([]UserListResponse, 0, len(users))

	// Get team membership for all users (batch lookup)
	teamMemberships := h.teamResolver.ListAllMembers(r.Context())

	for _, u := range users {
		userResp := UserListResponse{
			Username:    u.Name,
			Email:       u.Email,
			DisplayName: u.DisplayName,
			Avatar:      u.Avatar,
			Phase:       u.Phase,
			Disabled:    u.Disabled,
			AuthType:    u.AuthType,
			SSOProvider: u.SSOProvider,
		}

		// Add team membership info
		emailLower := strings.ToLower(u.Email)
		if membership, ok := teamMemberships[emailLower]; ok {
			userResp.Teams = membership.Teams
		}

		response = append(response, userResp)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"users": response,
	})
}

// ---- Admin Endpoints (require admin role) ----

// CreateUser creates a new internal user and returns an invite URL.
// POST /api/admin/users
func (h *UserHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	var req CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Email == "" {
		writeError(w, http.StatusBadRequest, "Email is required")
		return
	}

	result, err := h.userService.CreateUser(r.Context(), auth.CreateUserRequest{
		Username:    req.Username,
		Email:       req.Email,
		DisplayName: req.DisplayName,
	})

	if err != nil {
		if errors.Is(err, auth.ErrUserExists) {
			writeError(w, http.StatusConflict, "User already exists")
			return
		}
		h.logger.Error("Failed to create user", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to create user")
		return
	}

	h.logger.Info("Internal user created",
		"username", result.User.Name,
		"email", result.User.Email,
	)

	writeJSON(w, http.StatusCreated, CreateUserResponseBody{
		User: UserListResponse{
			Username:    result.User.Name,
			Email:       result.User.Email,
			DisplayName: result.User.DisplayName,
			Phase:       result.User.Phase,
			Disabled:    result.User.Disabled,
			AuthType:    result.User.AuthType,
		},
		InviteURL: result.InviteURL,
	})
}

// GetUser returns a specific user.
// GET /api/admin/users/{username}
func (h *UserHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	user, err := h.userService.GetUser(r.Context(), username)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "User not found")
			return
		}
		h.logger.Error("Failed to get user", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to get user")
		return
	}

	// Get team membership
	var teams []string
	if membership := h.teamResolver.ListAllMembers(r.Context()); membership != nil {
		if m, ok := membership[strings.ToLower(user.Email)]; ok {
			teams = m.Teams
		}
	}

	writeJSON(w, http.StatusOK, UserListResponse{
		Username:    user.Name,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Avatar:      user.Avatar,
		Phase:       user.Phase,
		Disabled:    user.Disabled,
		AuthType:    user.AuthType,
		SSOProvider: user.SSOProvider,
		Teams:       teams,
	})
}

// DeleteUser deletes a user.
// DELETE /api/admin/users/{username}
func (h *UserHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	err := h.userService.DeleteUser(r.Context(), username)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "User not found")
			return
		}
		h.logger.Error("Failed to delete user", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to delete user")
		return
	}

	h.logger.Info("User deleted", "username", username)
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "deleted",
	})
}

// DisableUser disables a user account.
// POST /api/admin/users/{username}/disable
func (h *UserHandler) DisableUser(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	err := h.userService.DisableUser(r.Context(), username)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "User not found")
			return
		}
		h.logger.Error("Failed to disable user", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to disable user")
		return
	}

	h.logger.Info("User disabled", "username", username)
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "disabled",
	})
}

// EnableUser enables a disabled user account.
// POST /api/admin/users/{username}/enable
func (h *UserHandler) EnableUser(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	err := h.userService.EnableUser(r.Context(), username)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "User not found")
			return
		}
		h.logger.Error("Failed to enable user", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to enable user")
		return
	}

	h.logger.Info("User enabled", "username", username)
	writeJSON(w, http.StatusOK, map[string]string{
		"status": "enabled",
	})
}

// RegenerateInvite creates a new invite token for an internal user.
// POST /api/admin/users/{username}/invite
func (h *UserHandler) RegenerateInvite(w http.ResponseWriter, r *http.Request) {
	username := chi.URLParam(r, "username")

	inviteURL, err := h.userService.RegenerateInvite(r.Context(), username)
	if err != nil {
		if errors.Is(err, auth.ErrUserNotFound) {
			writeError(w, http.StatusNotFound, "User not found")
			return
		}
		h.logger.Error("Failed to regenerate invite", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to regenerate invite")
		return
	}

	h.logger.Info("Invite regenerated", "username", username)
	writeJSON(w, http.StatusOK, map[string]string{
		"inviteUrl": inviteURL,
	})
}

// ---- Public Endpoints (no auth required) ----

// ValidateInvite checks if an invite token is valid.
// GET /api/auth/invite/{token}
func (h *UserHandler) ValidateInvite(w http.ResponseWriter, r *http.Request) {
	token := chi.URLParam(r, "token")

	user, err := h.userService.ValidateInviteToken(r.Context(), token)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidInviteToken) {
			writeJSON(w, http.StatusOK, ValidateInviteResponse{
				Valid: false,
			})
			return
		}
		h.logger.Error("Failed to validate invite", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to validate invite")
		return
	}

	writeJSON(w, http.StatusOK, ValidateInviteResponse{
		Valid:       true,
		Email:       user.Email,
		DisplayName: user.DisplayName,
	})
}

// SetPassword sets the password for an internal user using their invite token.
// POST /api/auth/set-password
func (h *UserHandler) SetPassword(w http.ResponseWriter, r *http.Request) {
	var req SetPasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.Token == "" {
		writeError(w, http.StatusBadRequest, "Token is required")
		return
	}

	if req.Password == "" {
		writeError(w, http.StatusBadRequest, "Password is required")
		return
	}

	user, err := h.userService.SetPassword(r.Context(), req.Token, req.Password)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidInviteToken) {
			writeError(w, http.StatusBadRequest, "Invalid or expired invite token")
			return
		}
		if errors.Is(err, auth.ErrPasswordTooWeak) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		h.logger.Error("Failed to set password", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to set password")
		return
	}

	h.logger.Info("User completed registration", "username", user.Name)

	// Automatically log the user in after setting password
	teams, err := h.teamResolver.ResolveTeams(r.Context(), user.Email, nil)
	if err != nil {
		h.logger.Warn("Failed to resolve teams", "email", user.Email, "error", err)
		teams = []auth.TeamMembership{}
	}

	session := &auth.UserSession{
		Subject:  "internal:" + user.Name,
		Email:    user.Email,
		Name:     user.DisplayName,
		Picture:  user.Avatar,
		Provider: "internal",
		Teams:    teams,
	}

	if session.Name == "" {
		session.Name = user.Name
	}

	token, err := h.sessionService.CreateSession(session)
	if err != nil {
		h.logger.Error("Failed to create session", "error", err)
		// User is registered but we couldn't log them in
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "password_set",
			"message": "Password set successfully. Please log in.",
		})
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

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status": "success",
		"user": UserListResponse{
			Username:    user.Name,
			Email:       user.Email,
			DisplayName: user.DisplayName,
			Phase:       user.Phase,
			AuthType:    user.AuthType,
		},
	})
}
