/*
Copyright 2025 The Butler Authors.

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
	"time"

	"github.com/butlerdotdev/butler-server/internal/api/middleware"
	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/config"
)

// AuthHandler handles authentication endpoints.
type AuthHandler struct {
	tokenService *auth.TokenService
	config       *config.Config
}

// NewAuthHandler creates a new auth handler.
func NewAuthHandler(tokenService *auth.TokenService, cfg *config.Config) *AuthHandler {
	return &AuthHandler{
		tokenService: tokenService,
		config:       cfg,
	}
}

// LoginRequest represents a login request body.
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents a login response.
type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

// User represents user information.
type User struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

// Login handles user login.
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Username != h.config.Auth.AdminUsername || req.Password != h.config.Auth.AdminPassword {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	token, err := h.tokenService.GenerateToken(req.Username, "admin")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate token")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "butler_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.config.Auth.JWTExpiry.Seconds()),
	})

	writeJSON(w, http.StatusOK, LoginResponse{
		Token: token,
		User: User{
			Username: req.Username,
			Role:     "admin",
		},
	})
}

// Logout handles user logout.
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     "butler_token",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})

	writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
}

// Me returns the current user information.
func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetUser(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	writeJSON(w, http.StatusOK, User{
		Username: claims.Username,
		Role:     claims.Role,
	})
}

// Refresh refreshes the auth token.
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	claims := middleware.GetUser(r.Context())
	if claims == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	token, err := h.tokenService.GenerateToken(claims.Username, claims.Role)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to refresh token")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "butler_token",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(h.config.Auth.JWTExpiry.Seconds()),
	})

	writeJSON(w, http.StatusOK, LoginResponse{
		Token: token,
		User: User{
			Username: claims.Username,
			Role:     claims.Role,
		},
	})
}
