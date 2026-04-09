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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/butlerdotdev/butler-server/internal/audit"
	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/config"
)

// DeviceFlowHandler handles the OAuth 2.0 Device Authorization Grant endpoints
// used by the Butler CLI.
type DeviceFlowHandler struct {
	deviceStore    *auth.DeviceStore
	saManager      *auth.CLIServiceAccountManager
	teamResolver   *auth.TeamResolver
	userService    *auth.UserService
	sessionService *auth.SessionService
	config         *config.Config
	logger         *slog.Logger
	auditEmitter   *audit.Emitter
}

// NewDeviceFlowHandler creates a new device flow handler.
func NewDeviceFlowHandler(
	deviceStore *auth.DeviceStore,
	saManager *auth.CLIServiceAccountManager,
	teamResolver *auth.TeamResolver,
	userService *auth.UserService,
	sessionService *auth.SessionService,
	cfg *config.Config,
	logger *slog.Logger,
	auditEmitter *audit.Emitter,
) *DeviceFlowHandler {
	return &DeviceFlowHandler{
		deviceStore:    deviceStore,
		saManager:      saManager,
		teamResolver:   teamResolver,
		userService:    userService,
		sessionService: sessionService,
		config:         cfg,
		logger:         logger,
		auditEmitter:   auditEmitter,
	}
}

// DeviceAuthorize initiates a device authorization flow.
// POST /api/auth/cli/device
func (h *DeviceFlowHandler) DeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	dc, err := h.deviceStore.Create(h.config.CLIAuth.DeviceCodeExpiry)
	if err != nil {
		h.logger.Error("Failed to create device code", "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to create device code")
		return
	}

	verificationURI := h.config.FrontendURL
	if verificationURI == "" {
		verificationURI = h.config.Server.BaseURL
	}
	verificationURI = verificationURI + "/auth/device"

	h.logger.Info("Device authorization initiated",
		"userCode", dc.UserCode,
		"expiresIn", int(time.Until(dc.ExpiresAt).Seconds()),
	)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"device_code":      dc.DeviceCode,
		"user_code":        dc.UserCode,
		"verification_uri": verificationURI,
		"expires_in":       int(time.Until(dc.ExpiresAt).Seconds()),
		"interval":         dc.Interval,
	})
}

// DeviceToken handles CLI polling for an approved device code.
// POST /api/auth/cli/token
func (h *DeviceFlowHandler) DeviceToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DeviceCode string `json:"device_code"`
		ClientID   string `json:"client_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.DeviceCode == "" {
		writeError(w, http.StatusBadRequest, "device_code is required")
		return
	}

	dc, ok := h.deviceStore.Get(req.DeviceCode)
	if !ok {
		// Could be expired or never existed
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "expired_token"})
		return
	}

	if dc.Denied {
		h.deviceStore.Delete(req.DeviceCode)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "access_denied"})
		return
	}

	if !dc.Approved {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "authorization_pending"})
		return
	}

	// Approved -- provision SA, token, and kubeconfig
	session := dc.UserSession
	h.deviceStore.Delete(req.DeviceCode)

	result, err := h.provisionCLIAccess(r, session)
	if err != nil {
		h.logger.Error("Failed to provision CLI access", "email", session.Email, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to provision CLI access")
		return
	}

	audit.RecordLogin(h.auditEmitter, session.Email, "cli-device", r.RemoteAddr)

	h.logger.Info("CLI device flow completed",
		"email", session.Email,
		"teams", len(session.Teams),
		"isPlatformAdmin", session.IsPlatformAdmin,
	)

	writeJSON(w, http.StatusOK, result)
}

// DeviceVerify validates a user code entered in the console.
// POST /api/auth/cli/verify
func (h *DeviceFlowHandler) DeviceVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserCode string `json:"user_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.UserCode == "" {
		writeError(w, http.StatusBadRequest, "user_code is required")
		return
	}

	dc, ok := h.deviceStore.GetByUserCode(req.UserCode)
	if !ok {
		writeError(w, http.StatusNotFound, "Invalid or expired user code")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"device_code": dc.DeviceCode,
		"expires_in":  int(time.Until(dc.ExpiresAt).Seconds()),
	})
}

// DeviceApprove is called by an authenticated console user to approve a device code.
// POST /api/auth/cli/approve
func (h *DeviceFlowHandler) DeviceApprove(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		writeError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	var req struct {
		DeviceCode string `json:"device_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.DeviceCode == "" {
		writeError(w, http.StatusBadRequest, "device_code is required")
		return
	}

	dc, ok := h.deviceStore.Get(req.DeviceCode)
	if !ok {
		writeError(w, http.StatusNotFound, "Invalid or expired device code")
		return
	}

	if dc.Approved || dc.Denied {
		writeError(w, http.StatusConflict, "Device code already resolved")
		return
	}

	// Re-resolve teams to get the freshest membership data
	teams, err := h.teamResolver.ResolveTeams(r.Context(), user.Email, user.Groups)
	if err != nil {
		h.logger.Warn("Failed to resolve teams during device approval", "email", user.Email, "error", err)
		teams = user.Teams // fall back to session data
	}

	session := &auth.UserSession{
		Subject:         user.Subject,
		Email:           user.Email,
		Name:            user.Name,
		Picture:         user.Picture,
		Provider:        user.Provider,
		Groups:          user.Groups,
		Teams:           teams,
		IsPlatformAdmin: user.IsPlatformAdmin,
	}

	h.deviceStore.Approve(req.DeviceCode, session)

	h.logger.Info("Device code approved",
		"email", user.Email,
		"deviceCode", dc.DeviceCode[:8]+"...",
	)

	writeJSON(w, http.StatusOK, map[string]string{"status": "approved"})
}

// DeviceRefresh exchanges a refresh token for a new SA token and kubeconfig.
// POST /api/auth/cli/refresh
func (h *DeviceFlowHandler) DeviceRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.RefreshToken == "" {
		writeError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}

	email, ok := h.deviceStore.ValidateRefreshToken(req.RefreshToken)
	if !ok {
		writeError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}

	// Check if user is disabled
	userCRD, err := h.userService.GetUserByEmail(r.Context(), email)
	if err != nil {
		h.logger.Warn("Failed to look up user during CLI refresh", "email", email, "error", err)
		writeError(w, http.StatusUnauthorized, "User not found")
		return
	}
	if userCRD.Disabled {
		h.logger.Warn("Disabled user attempted CLI refresh", "email", email)
		writeError(w, http.StatusForbidden, "Account is disabled")
		return
	}

	// Re-resolve teams
	teams, err := h.teamResolver.ResolveTeams(r.Context(), email, nil)
	if err != nil {
		h.logger.Warn("Failed to resolve teams during CLI refresh", "email", email, "error", err)
		teams = []auth.TeamMembership{}
	}

	session := &auth.UserSession{
		Email:           email,
		Name:            userCRD.DisplayName,
		Teams:           teams,
		IsPlatformAdmin: userCRD.IsPlatformAdmin,
	}

	result, err := h.provisionCLIAccess(r, session)
	if err != nil {
		h.logger.Error("Failed to provision CLI access on refresh", "email", email, "error", err)
		writeError(w, http.StatusInternalServerError, "Failed to refresh CLI access")
		return
	}

	h.logger.Info("CLI refresh completed", "email", email)
	writeJSON(w, http.StatusOK, result)
}

// cliTokenResponse is the shape returned by both the token and refresh endpoints.
type cliTokenResponse struct {
	User              cliUserResponse `json:"user"`
	Kubeconfig        string          `json:"kubeconfig"`
	ExpiresAt         string          `json:"expires_at"`
	RefreshToken      string          `json:"refresh_token"`
	RefreshExpiresAt  string          `json:"refresh_expires_at"`
}

type cliUserResponse struct {
	Email           string                `json:"email"`
	Name            string                `json:"name"`
	Teams           []auth.TeamMembership `json:"teams"`
	IsPlatformAdmin bool                  `json:"isPlatformAdmin,omitempty"`
}

// provisionCLIAccess creates (or updates) the SA, RoleBindings, token, and
// kubeconfig for a CLI user. It returns the response payload.
func (h *DeviceFlowHandler) provisionCLIAccess(r *http.Request, session *auth.UserSession) (*cliTokenResponse, error) {
	ctx := r.Context()

	// Ensure ServiceAccount
	sa, err := h.saManager.EnsureServiceAccount(ctx, session.Email)
	if err != nil {
		return nil, fmt.Errorf("ensure service account: %w", err)
	}

	// Ensure RoleBindings
	if err := h.saManager.EnsureRoleBindings(ctx, sa.Name, session.Email, session.Teams, session.IsPlatformAdmin); err != nil {
		return nil, fmt.Errorf("ensure role bindings: %w", err)
	}

	// Create short-lived SA token
	token, expiresAt, err := h.saManager.CreateToken(ctx, sa.Name)
	if err != nil {
		return nil, fmt.Errorf("create token: %w", err)
	}

	// Build kubeconfig
	kubeconfigBytes, err := h.saManager.BuildKubeconfig(token, sa.Name)
	if err != nil {
		return nil, fmt.Errorf("build kubeconfig: %w", err)
	}

	// Generate refresh token
	refreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("generate refresh token: %w", err)
	}

	refreshExpiresAt := time.Now().Add(h.config.CLIAuth.RefreshExpiry)
	h.deviceStore.StoreRefreshToken(refreshToken, session.Email, h.config.CLIAuth.RefreshExpiry)

	return &cliTokenResponse{
		User: cliUserResponse{
			Email:           session.Email,
			Name:            session.Name,
			Teams:           session.Teams,
			IsPlatformAdmin: session.IsPlatformAdmin,
		},
		Kubeconfig:       base64.StdEncoding.EncodeToString(kubeconfigBytes),
		ExpiresAt:        expiresAt.Format(time.RFC3339),
		RefreshToken:     refreshToken,
		RefreshExpiresAt: refreshExpiresAt.Format(time.RFC3339),
	}, nil
}
