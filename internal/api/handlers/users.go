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
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/go-chi/chi/v5"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// UserHandler handles user management endpoints.
type UserHandler struct {
	userService    *auth.UserService
	sessionService *auth.SessionService
	teamResolver   *auth.TeamResolver
	k8sClient      *k8s.Client
	config         *config.Config
	logger         *slog.Logger
}

// NewUserHandler creates a new user handler.
func NewUserHandler(
	userService *auth.UserService,
	sessionService *auth.SessionService,
	teamResolver *auth.TeamResolver,
	k8sClient *k8s.Client,
	cfg *config.Config,
	logger *slog.Logger,
) *UserHandler {
	return &UserHandler{
		userService:    userService,
		sessionService: sessionService,
		teamResolver:   teamResolver,
		k8sClient:      k8sClient,
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
	Username        string   `json:"username"`
	Email           string   `json:"email"`
	DisplayName     string   `json:"displayName,omitempty"`
	Avatar          string   `json:"avatar,omitempty"`
	Phase           string   `json:"phase"`
	Disabled        bool     `json:"disabled"`
	AuthType        string   `json:"authType"` // "internal" or "sso"
	SSOProvider     string   `json:"ssoProvider,omitempty"`
	Teams           []string `json:"teams,omitempty"`
	IsPlatformAdmin bool     `json:"isPlatformAdmin,omitempty"`
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
			Username:        u.Name,
			Email:           u.Email,
			DisplayName:     u.DisplayName,
			Avatar:          u.Avatar,
			Phase:           u.Phase,
			Disabled:        u.Disabled,
			AuthType:        u.AuthType,
			SSOProvider:     u.SSOProvider,
			IsPlatformAdmin: u.IsPlatformAdmin,
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
			Username:        result.User.Name,
			Email:           result.User.Email,
			DisplayName:     result.User.DisplayName,
			Phase:           result.User.Phase,
			Disabled:        result.User.Disabled,
			AuthType:        result.User.AuthType,
			IsPlatformAdmin: result.User.IsPlatformAdmin,
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
		Username:        user.Name,
		Email:           user.Email,
		DisplayName:     user.DisplayName,
		Avatar:          user.Avatar,
		Phase:           user.Phase,
		Disabled:        user.Disabled,
		AuthType:        user.AuthType,
		SSOProvider:     user.SSOProvider,
		Teams:           teams,
		IsPlatformAdmin: user.IsPlatformAdmin,
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
		Subject:         "internal:" + user.Name,
		Email:           user.Email,
		Name:            user.DisplayName,
		Picture:         user.Avatar,
		Provider:        "internal",
		Teams:           teams,
		IsPlatformAdmin: user.IsPlatformAdmin,
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
			Username:        user.Name,
			Email:           user.Email,
			DisplayName:     user.DisplayName,
			Phase:           user.Phase,
			AuthType:        user.AuthType,
			IsPlatformAdmin: user.IsPlatformAdmin,
		},
	})
}

// ---- SSH Key Management (self-service) ----

var userGVR = schema.GroupVersionResource{
	Group:    "butler.butlerlabs.dev",
	Version:  "v1alpha1",
	Resource: "users",
}

// AddSSHKeyRequest is the request body for adding an SSH key.
type AddSSHKeyRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

// SSHKeyResponse represents an SSH key in the API response.
type SSHKeyResponse struct {
	Name        string `json:"name"`
	Fingerprint string `json:"fingerprint"`
	AddedAt     string `json:"addedAt"`
	// First 30 chars of the key for display
	Preview string `json:"preview"`
}

// ListSSHKeys returns the current user's SSH keys.
// GET /api/auth/ssh-keys
func (h *UserHandler) ListSSHKeys(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	userCRD, err := h.findUserCRDByEmail(r.Context(), user.Email)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	sshKeys, _, _ := unstructured.NestedSlice(userCRD.Object, "spec", "sshKeys")

	var keys []SSHKeyResponse
	for _, k := range sshKeys {
		keyMap, ok := k.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := keyMap["name"].(string)
		fingerprint, _ := keyMap["fingerprint"].(string)
		addedAt, _ := keyMap["addedAt"].(string)
		publicKey, _ := keyMap["publicKey"].(string)

		preview := publicKey
		if len(preview) > 30 {
			preview = preview[:30] + "..."
		}

		keys = append(keys, SSHKeyResponse{
			Name:        name,
			Fingerprint: fingerprint,
			AddedAt:     addedAt,
			Preview:     preview,
		})
	}

	if keys == nil {
		keys = []SSHKeyResponse{}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{"sshKeys": keys})
}

// AddSSHKey adds an SSH public key to the current user's profile.
// POST /api/auth/ssh-keys
func (h *UserHandler) AddSSHKey(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	var req AddSSHKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if req.PublicKey == "" {
		writeError(w, http.StatusBadRequest, "publicKey is required")
		return
	}

	// Validate SSH public key format
	parts := strings.Fields(req.PublicKey)
	if len(parts) < 2 {
		writeError(w, http.StatusBadRequest, "invalid SSH public key format")
		return
	}

	keyType := parts[0]
	validTypes := map[string]bool{
		"ssh-rsa":             true,
		"ssh-ed25519":         true,
		"ecdsa-sha2-nistp256": true,
		"ecdsa-sha2-nistp384": true,
		"ecdsa-sha2-nistp521": true,
	}
	if !validTypes[keyType] {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("unsupported SSH key type: %s", keyType))
		return
	}

	// Validate base64 encoding of key data
	_, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid SSH key data (bad base64)")
		return
	}

	// Compute SHA256 fingerprint
	keyBytes, _ := base64.StdEncoding.DecodeString(parts[1])
	hash := sha256.Sum256(keyBytes)
	fingerprint := "SHA256:" + base64.StdEncoding.EncodeToString(hash[:])
	// Remove trailing padding
	fingerprint = strings.TrimRight(fingerprint, "=")

	userCRD, err := h.findUserCRDByEmail(r.Context(), user.Email)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	// Get existing SSH keys
	sshKeys, _, _ := unstructured.NestedSlice(userCRD.Object, "spec", "sshKeys")

	// Check for duplicate fingerprint
	for _, k := range sshKeys {
		if keyMap, ok := k.(map[string]interface{}); ok {
			if fp, _ := keyMap["fingerprint"].(string); fp == fingerprint {
				writeError(w, http.StatusConflict, "SSH key already exists")
				return
			}
		}
	}

	newKey := map[string]interface{}{
		"name":        req.Name,
		"publicKey":   req.PublicKey,
		"fingerprint": fingerprint,
		"addedAt":     time.Now().UTC().Format(time.RFC3339),
	}

	sshKeys = append(sshKeys, newKey)

	if err := unstructured.SetNestedSlice(userCRD.Object, sshKeys, "spec", "sshKeys"); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update SSH keys")
		return
	}

	_, err = h.k8sClient.Dynamic().Resource(userGVR).Update(r.Context(), userCRD, metav1.UpdateOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save SSH key: %v", err))
		return
	}

	h.logger.Info("SSH key added", "user", user.Email, "keyName", req.Name)

	writeJSON(w, http.StatusCreated, SSHKeyResponse{
		Name:        req.Name,
		Fingerprint: fingerprint,
		AddedAt:     newKey["addedAt"].(string),
		Preview:     truncate(req.PublicKey, 30),
	})
}

// RemoveSSHKey removes an SSH key by fingerprint.
// DELETE /api/auth/ssh-keys/{fingerprint}
func (h *UserHandler) RemoveSSHKey(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return
	}

	fingerprint := chi.URLParam(r, "fingerprint")

	userCRD, err := h.findUserCRDByEmail(r.Context(), user.Email)
	if err != nil {
		writeError(w, http.StatusNotFound, "user not found")
		return
	}

	sshKeys, _, _ := unstructured.NestedSlice(userCRD.Object, "spec", "sshKeys")

	var updated []interface{}
	found := false
	for _, k := range sshKeys {
		if keyMap, ok := k.(map[string]interface{}); ok {
			if fp, _ := keyMap["fingerprint"].(string); fp == fingerprint {
				found = true
				continue
			}
		}
		updated = append(updated, k)
	}

	if !found {
		writeError(w, http.StatusNotFound, "SSH key not found")
		return
	}

	if err := unstructured.SetNestedSlice(userCRD.Object, updated, "spec", "sshKeys"); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to update SSH keys")
		return
	}

	_, err = h.k8sClient.Dynamic().Resource(userGVR).Update(r.Context(), userCRD, metav1.UpdateOptions{})
	if err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to remove SSH key: %v", err))
		return
	}

	h.logger.Info("SSH key removed", "user", user.Email, "fingerprint", fingerprint)

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// findUserCRDByEmail looks up a User CRD by email address.
func (h *UserHandler) findUserCRDByEmail(ctx context.Context, email string) (*unstructured.Unstructured, error) {
	users, err := h.k8sClient.Dynamic().Resource(userGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	for _, u := range users.Items {
		userEmail, _, _ := unstructured.NestedString(u.Object, "spec", "email")
		if strings.EqualFold(userEmail, email) {
			return &u, nil
		}
	}

	return nil, fmt.Errorf("user not found: %s", email)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
