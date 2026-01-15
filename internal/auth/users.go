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
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var (
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrUserDisabled       = errors.New("user is disabled")
	ErrUserLocked         = errors.New("user is locked")
	ErrUserPending        = errors.New("user registration pending")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidInviteToken = errors.New("invalid or expired invite token")
	ErrPasswordTooWeak    = errors.New("password does not meet requirements")

	// UserGVR is the GroupVersionResource for User CRDs
	UserGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "users",
	}
)

// UserInfo represents user information returned from the service.
// This is the internal representation used by handlers.
type UserInfo struct {
	Name            string
	Email           string
	DisplayName     string
	Avatar          string
	Phase           string
	Disabled        bool
	AuthType        string
	SSOProvider     string
	IsPlatformAdmin bool // NEW: Platform admin flag from User CRD
}

// UserService handles user management operations using User CRDs.
type UserService struct {
	dynamicClient dynamic.Interface
	clientset     kubernetes.Interface
	baseURL       string
	logger        *slog.Logger
}

// NewUserService creates a new user service.
func NewUserService(dynamicClient dynamic.Interface, clientset kubernetes.Interface, baseURL string, logger *slog.Logger) *UserService {
	return &UserService{
		dynamicClient: dynamicClient,
		clientset:     clientset,
		baseURL:       baseURL,
		logger:        logger,
	}
}

// CreateUserRequest is the request to create a new internal user.
type CreateUserRequest struct {
	Username    string
	Email       string
	DisplayName string
}

// CreateUserResult is the result of creating a new internal user.
type CreateUserResult struct {
	User      *UserInfo
	InviteURL string
}

// EnsureSSOUserRequest is the request to ensure an SSO user exists.
type EnsureSSOUserRequest struct {
	Email       string
	DisplayName string
	Picture     string
	Provider    string
	Subject     string
}

// CreateUser creates a new internal user and returns an invite URL.
func (s *UserService) CreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResult, error) {
	// Generate username from email if not provided
	username := req.Username
	if username == "" {
		username = strings.Split(req.Email, "@")[0]
		username = strings.ToLower(strings.ReplaceAll(username, ".", "-"))
	}

	// Check if user already exists
	_, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
	if err == nil {
		return nil, ErrUserExists
	}
	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to check user existence: %w", err)
	}

	// Also check by email
	existingUser, err := s.GetUserByEmail(ctx, req.Email)
	if err == nil && existingUser != nil {
		return nil, ErrUserExists
	}

	// Generate invite token
	inviteToken, err := generateSecureToken(32)
	if err != nil {
		return nil, fmt.Errorf("failed to generate invite token: %w", err)
	}
	inviteTokenHash := hashToken(inviteToken)

	// Create User CRD
	now := metav1.Now()
	expiresAt := metav1.NewTime(time.Now().Add(7 * 24 * time.Hour)) // 7 days

	user := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "User",
			"metadata": map[string]interface{}{
				"name": username,
			},
			"spec": map[string]interface{}{
				"email":           req.Email,
				"displayName":     req.DisplayName,
				"disabled":        false,
				"authType":        "internal",
				"isPlatformAdmin": false,
			},
			"status": map[string]interface{}{
				"phase":           "Pending",
				"inviteTokenHash": inviteTokenHash,
				"inviteExpiresAt": expiresAt.Format(time.RFC3339),
				"inviteSentAt":    now.Format(time.RFC3339),
			},
		},
	}

	created, err := s.dynamicClient.Resource(UserGVR).Create(ctx, user, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Update status (subresource)
	created.Object["status"] = user.Object["status"]
	_, err = s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, created, metav1.UpdateOptions{})
	if err != nil {
		s.logger.Warn("Failed to update user status", "error", err)
	}

	inviteURL := fmt.Sprintf("%s/invite/%s", s.baseURL, inviteToken)

	return &CreateUserResult{
		User: &UserInfo{
			Name:        username,
			Email:       req.Email,
			DisplayName: req.DisplayName,
			Phase:       "Pending",
			Disabled:    false,
			AuthType:    "internal",
		},
		InviteURL: inviteURL,
	}, nil
}

// EnsureSSOUser creates or updates a User CRD for an SSO user.
func (s *UserService) EnsureSSOUser(ctx context.Context, req EnsureSSOUserRequest) (*UserInfo, error) {
	// Generate username from email
	username := strings.Split(req.Email, "@")[0]
	username = strings.ToLower(strings.ReplaceAll(username, ".", "-"))

	// Try to get existing user by username first
	existing, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
	if err == nil {
		// User exists - update if needed
		spec, _, _ := unstructured.NestedMap(existing.Object, "spec")

		// Auto-fix authType if incorrect
		currentAuthType, _, _ := unstructured.NestedString(spec, "authType")
		if currentAuthType != "sso" {
			spec["authType"] = "sso"
			spec["ssoProvider"] = req.Provider
			spec["ssoSubject"] = req.Subject
			if err := unstructured.SetNestedMap(existing.Object, spec, "spec"); err == nil {
				_, updateErr := s.dynamicClient.Resource(UserGVR).Update(ctx, existing, metav1.UpdateOptions{})
				if updateErr != nil {
					s.logger.Warn("Failed to update SSO user authType", "error", updateErr)
				}
			}
		}

		return s.userFromUnstructured(existing), nil
	}

	if !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Also check by email in case username differs
	existingByEmail, err := s.GetUserByEmail(ctx, req.Email)
	if err == nil && existingByEmail != nil {
		return existingByEmail, nil
	}

	// Create new SSO user
	user := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "User",
			"metadata": map[string]interface{}{
				"name": username,
			},
			"spec": map[string]interface{}{
				"email":           req.Email,
				"displayName":     req.DisplayName,
				"avatar":          req.Picture,
				"disabled":        false,
				"authType":        "sso",
				"ssoProvider":     req.Provider,
				"ssoSubject":      req.Subject,
				"isPlatformAdmin": false,
			},
			"status": map[string]interface{}{
				"phase": "Active",
			},
		},
	}

	created, err := s.dynamicClient.Resource(UserGVR).Create(ctx, user, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			// Race condition - fetch and return
			existing, getErr := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
			if getErr != nil {
				return nil, fmt.Errorf("failed to get existing user: %w", getErr)
			}
			return s.userFromUnstructured(existing), nil
		}
		return nil, fmt.Errorf("failed to create SSO user: %w", err)
	}

	// Update status
	created.Object["status"] = user.Object["status"]
	_, err = s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, created, metav1.UpdateOptions{})
	if err != nil {
		s.logger.Warn("Failed to update SSO user status", "error", err)
	}

	return s.userFromUnstructured(created), nil
}

// GetUser gets a user by username.
func (s *UserService) GetUser(ctx context.Context, username string) (*UserInfo, error) {
	user, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	return s.userFromUnstructured(user), nil
}

// GetUserByEmail gets a user by email address.
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*UserInfo, error) {
	users, err := s.dynamicClient.Resource(UserGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	emailLower := strings.ToLower(email)
	for _, u := range users.Items {
		userEmail, _, _ := unstructured.NestedString(u.Object, "spec", "email")
		if strings.ToLower(userEmail) == emailLower {
			return s.userFromUnstructured(&u), nil
		}
	}

	return nil, ErrUserNotFound
}

// ListUsers lists all users.
func (s *UserService) ListUsers(ctx context.Context) ([]*UserInfo, error) {
	users, err := s.dynamicClient.Resource(UserGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	result := make([]*UserInfo, 0, len(users.Items))
	for _, u := range users.Items {
		result = append(result, s.userFromUnstructured(&u))
	}
	return result, nil
}

// DeleteUser deletes a user.
func (s *UserService) DeleteUser(ctx context.Context, username string) error {
	err := s.dynamicClient.Resource(UserGVR).Delete(ctx, username, metav1.DeleteOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}

// DisableUser disables a user.
func (s *UserService) DisableUser(ctx context.Context, username string) error {
	user, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	if err := unstructured.SetNestedField(user.Object, true, "spec", "disabled"); err != nil {
		return fmt.Errorf("failed to set disabled: %w", err)
	}

	_, err = s.dynamicClient.Resource(UserGVR).Update(ctx, user, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// EnableUser enables a disabled user.
func (s *UserService) EnableUser(ctx context.Context, username string) error {
	user, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	if err := unstructured.SetNestedField(user.Object, false, "spec", "disabled"); err != nil {
		return fmt.Errorf("failed to set disabled: %w", err)
	}

	_, err = s.dynamicClient.Resource(UserGVR).Update(ctx, user, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// ValidateInviteToken validates an invite token and returns the user.
func (s *UserService) ValidateInviteToken(ctx context.Context, token string) (*UserInfo, error) {
	tokenHash := hashToken(token)

	users, err := s.dynamicClient.Resource(UserGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	for _, u := range users.Items {
		storedHash, _, _ := unstructured.NestedString(u.Object, "status", "inviteTokenHash")
		if storedHash != tokenHash {
			continue
		}

		// Check expiry
		expiresAtStr, _, _ := unstructured.NestedString(u.Object, "status", "inviteExpiresAt")
		if expiresAtStr != "" {
			expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
			if err == nil && time.Now().After(expiresAt) {
				return nil, ErrInvalidInviteToken
			}
		}

		return s.userFromUnstructured(&u), nil
	}

	return nil, ErrInvalidInviteToken
}

// SetPassword sets the password for an internal user.
func (s *UserService) SetPassword(ctx context.Context, token, password string) (*UserInfo, error) {
	// Validate token first
	tokenHash := hashToken(token)

	users, err := s.dynamicClient.Resource(UserGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	var targetUser *unstructured.Unstructured
	for _, u := range users.Items {
		storedHash, _, _ := unstructured.NestedString(u.Object, "status", "inviteTokenHash")
		if storedHash == tokenHash {
			// Check expiry
			expiresAtStr, _, _ := unstructured.NestedString(u.Object, "status", "inviteExpiresAt")
			if expiresAtStr != "" {
				expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
				if err == nil && time.Now().After(expiresAt) {
					return nil, ErrInvalidInviteToken
				}
			}
			targetUser = &u
			break
		}
	}

	if targetUser == nil {
		return nil, ErrInvalidInviteToken
	}

	// Validate password strength
	if len(password) < 8 {
		return nil, fmt.Errorf("%w: password must be at least 8 characters", ErrPasswordTooWeak)
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	username := targetUser.GetName()

	// Store password in a Secret
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("butler-user-%s-password", username),
			Namespace: "butler-system",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			"password": hashedPassword,
		},
	}

	_, err = s.clientset.CoreV1().Secrets("butler-system").Create(ctx, secret, metav1.CreateOptions{})
	if err != nil {
		if apierrors.IsAlreadyExists(err) {
			_, err = s.clientset.CoreV1().Secrets("butler-system").Update(ctx, secret, metav1.UpdateOptions{})
		}
		if err != nil {
			return nil, fmt.Errorf("failed to store password: %w", err)
		}
	}

	// Update user status
	now := metav1.Now()
	status := map[string]interface{}{
		"phase": "Active",
		"passwordSecretRef": map[string]interface{}{
			"name":      secret.Name,
			"namespace": secret.Namespace,
			"key":       "password",
		},
		"passwordChangedAt": now.Format(time.RFC3339),
		// Clear invite token
		"inviteTokenHash": "",
		"inviteExpiresAt": "",
	}

	if err := unstructured.SetNestedMap(targetUser.Object, status, "status"); err != nil {
		return nil, fmt.Errorf("failed to set status: %w", err)
	}

	_, err = s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, targetUser, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to update user status: %w", err)
	}

	return s.userFromUnstructured(targetUser), nil
}

// RegenerateInvite regenerates the invite token for an internal user.
func (s *UserService) RegenerateInvite(ctx context.Context, username string) (string, error) {
	user, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", ErrUserNotFound
		}
		return "", fmt.Errorf("failed to get user: %w", err)
	}

	// Generate new invite token
	inviteToken, err := generateSecureToken(32)
	if err != nil {
		return "", fmt.Errorf("failed to generate invite token: %w", err)
	}
	inviteTokenHash := hashToken(inviteToken)

	// Update status
	now := metav1.Now()
	expiresAt := metav1.NewTime(time.Now().Add(7 * 24 * time.Hour))

	status, _, _ := unstructured.NestedMap(user.Object, "status")
	if status == nil {
		status = make(map[string]interface{})
	}
	status["inviteTokenHash"] = inviteTokenHash
	status["inviteExpiresAt"] = expiresAt.Format(time.RFC3339)
	status["inviteSentAt"] = now.Format(time.RFC3339)
	status["phase"] = "Pending"

	if err := unstructured.SetNestedMap(user.Object, status, "status"); err != nil {
		return "", fmt.Errorf("failed to set status: %w", err)
	}

	_, err = s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, user, metav1.UpdateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to update user status: %w", err)
	}

	return fmt.Sprintf("%s/invite/%s", s.baseURL, inviteToken), nil
}

// AuthenticateInternal authenticates an internal user with email/username and password.
func (s *UserService) AuthenticateInternal(ctx context.Context, identifier, password string) (*UserInfo, error) {
	// Find user by email or username
	var user *unstructured.Unstructured

	// Try by username first
	u, err := s.dynamicClient.Resource(UserGVR).Get(ctx, identifier, metav1.GetOptions{})
	if err == nil {
		user = u
	} else {
		// Try by email
		users, err := s.dynamicClient.Resource(UserGVR).List(ctx, metav1.ListOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to list users: %w", err)
		}

		identifierLower := strings.ToLower(identifier)
		for _, u := range users.Items {
			email, _, _ := unstructured.NestedString(u.Object, "spec", "email")
			if strings.ToLower(email) == identifierLower {
				user = &u
				break
			}
		}
	}

	if user == nil {
		return nil, ErrUserNotFound
	}

	// Check if disabled
	disabled, _, _ := unstructured.NestedBool(user.Object, "spec", "disabled")
	if disabled {
		return nil, ErrUserDisabled
	}

	// Check phase
	phase, _, _ := unstructured.NestedString(user.Object, "status", "phase")
	if phase == "Pending" {
		return nil, ErrUserPending
	}
	if phase == "Locked" {
		return nil, ErrUserLocked
	}

	// Get password from secret
	secretRef, _, _ := unstructured.NestedStringMap(user.Object, "status", "passwordSecretRef")
	if secretRef == nil || secretRef["name"] == "" {
		return nil, ErrInvalidCredentials
	}

	namespace := secretRef["namespace"]
	if namespace == "" {
		namespace = "butler-system"
	}

	secret, err := s.clientset.CoreV1().Secrets(namespace).Get(ctx, secretRef["name"], metav1.GetOptions{})
	if err != nil {
		s.logger.Error("Failed to get password secret", "error", err)
		return nil, ErrInvalidCredentials
	}

	key := secretRef["key"]
	if key == "" {
		key = "password"
	}

	storedHash := secret.Data[key]
	if err := bcrypt.CompareHashAndPassword(storedHash, []byte(password)); err != nil {
		// TODO: Increment failed login counter
		return nil, ErrInvalidCredentials
	}

	// Update last login time
	status, _, _ := unstructured.NestedMap(user.Object, "status")
	if status == nil {
		status = make(map[string]interface{})
	}
	status["lastLoginTime"] = metav1.Now().Format(time.RFC3339)
	loginCount, _, _ := unstructured.NestedInt64(user.Object, "status", "loginCount")
	status["loginCount"] = loginCount + 1
	status["failedLoginAttempts"] = int64(0)

	if err := unstructured.SetNestedMap(user.Object, status, "status"); err == nil {
		s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, user, metav1.UpdateOptions{})
	}

	return s.userFromUnstructured(user), nil
}

// userFromUnstructured converts an unstructured User to UserInfo.
func (s *UserService) userFromUnstructured(u *unstructured.Unstructured) *UserInfo {
	email, _, _ := unstructured.NestedString(u.Object, "spec", "email")
	displayName, _, _ := unstructured.NestedString(u.Object, "spec", "displayName")
	avatar, _, _ := unstructured.NestedString(u.Object, "spec", "avatar")
	disabled, _, _ := unstructured.NestedBool(u.Object, "spec", "disabled")
	authType, _, _ := unstructured.NestedString(u.Object, "spec", "authType")
	ssoProvider, _, _ := unstructured.NestedString(u.Object, "spec", "ssoProvider")
	isPlatformAdmin, _, _ := unstructured.NestedBool(u.Object, "spec", "isPlatformAdmin")
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")

	if authType == "" {
		authType = "internal"
	}
	if phase == "" {
		phase = "Active"
	}

	return &UserInfo{
		Name:            u.GetName(),
		Email:           email,
		DisplayName:     displayName,
		Avatar:          avatar,
		Phase:           phase,
		Disabled:        disabled,
		AuthType:        authType,
		SSOProvider:     ssoProvider,
		IsPlatformAdmin: isPlatformAdmin,
	}
}

// generateSecureToken generates a cryptographically secure random token.
func generateSecureToken(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashToken creates a SHA256 hash of a token.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
