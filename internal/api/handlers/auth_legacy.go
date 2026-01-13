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
	"net/http"

	"github.com/butlerdotdev/butler-server/internal/auth"
)

// LegacyLoginRequest is the request body for legacy username/password login.
type LegacyLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LegacyLogin handles legacy username/password authentication.
// This is only enabled when OIDC is not configured (development mode).
// POST /api/auth/login/legacy
func (h *AuthHandler) LegacyLogin(w http.ResponseWriter, r *http.Request) {
	var req LegacyLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate credentials against config
	if req.Username != h.config.Auth.AdminUsername || req.Password != h.config.Auth.AdminPassword {
		writeError(w, http.StatusUnauthorized, "Invalid credentials")
		return
	}

	// Create session for the admin user
	user := &auth.UserSession{
		Subject:  "local:" + req.Username,
		Email:    req.Username + "@localhost",
		Name:     req.Username,
		Provider: "local",
		Teams: []auth.TeamMembership{
			{
				Name: "default",
				Role: auth.RoleAdmin,
			},
		},
	}

	// Generate session token
	token, err := h.sessionService.CreateSession(user)
	if err != nil {
		h.logger.Error("Failed to create session", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to create session")
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

	h.logger.Info("Legacy login successful", "username", req.Username)

	response := LoginResponse{
		User: UserResponse{
			Email:   user.Email,
			Name:    user.Name,
			Picture: "",
			Teams:   user.Teams,
		},
	}

	writeJSON(w, http.StatusOK, response)
}
