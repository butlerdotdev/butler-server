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
	"encoding/base64"
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
	// UserGVR is the GroupVersionResource for User CRDs
	UserGVR = schema.GroupVersionResource{
		Group:    "butler.butlerlabs.dev",
		Version:  "v1alpha1",
		Resource: "users",
	}

	// Errors
	ErrUserNotFound       = errors.New("user not found")
	ErrUserDisabled       = errors.New("user is disabled")
	ErrUserLocked         = errors.New("user is temporarily locked")
	ErrUserPending        = errors.New("user has not completed registration")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidInviteToken = errors.New("invalid or expired invite token")
	ErrUserExists         = errors.New("user already exists")
	ErrPasswordTooWeak    = errors.New("password does not meet requirements")
)

const (
	// InviteTokenLength is the number of random bytes in an invite token
	InviteTokenLength = 32

	// DefaultInviteExpiry is how long invite tokens are valid
	DefaultInviteExpiry = 48 * time.Hour

	// MaxFailedAttempts before locking account
	MaxFailedAttempts = 5

	// LockDuration is how long accounts are locked after max failures
	LockDuration = 15 * time.Minute

	// MinPasswordLength is the minimum password length
	MinPasswordLength = 12

	// DefaultSecretNamespace for password secrets
	DefaultSecretNamespace = "butler-system"

	// PasswordHashKey is the key in the password secret
	PasswordHashKey = "password-hash"

	// AuthType constants
	AuthTypeSSO      = "sso"
	AuthTypeInternal = "internal"
)

// UserService handles all user operations.
type UserService struct {
	dynamicClient dynamic.Interface
	clientset     kubernetes.Interface
	logger        *slog.Logger
	baseURL       string
}

// NewUserService creates a new user service.
func NewUserService(dynamicClient dynamic.Interface, clientset kubernetes.Interface, baseURL string, logger *slog.Logger) *UserService {
	return &UserService{
		dynamicClient: dynamicClient,
		clientset:     clientset,
		baseURL:       strings.TrimSuffix(baseURL, "/"),
		logger:        logger,
	}
}

// User represents a user from the User CRD.
// This is the canonical user representation used throughout the system.
type User struct {
	Name        string `json:"name"`
	Email       string `json:"email"`
	DisplayName string `json:"displayName,omitempty"`
	Avatar      string `json:"avatar,omitempty"`
	Disabled    bool   `json:"disabled"`
	Phase       string `json:"phase"`
	AuthType    string `json:"authType"` // "sso" or "internal"
	SSOProvider string `json:"ssoProvider,omitempty"`
	SSOSubject  string `json:"ssoSubject,omitempty"`
}

// CreateUserRequest contains the data needed to create a new internal user.
type CreateUserRequest struct {
	Username    string
	Email       string
	DisplayName string
}

// CreateUserResponse contains the result of user creation.
type CreateUserResponse struct {
	User      User
	InviteURL string
}

// EnsureSSOUserRequest contains the data from an SSO login.
type EnsureSSOUserRequest struct {
	Email       string
	DisplayName string
	Picture     string
	Provider    string
	Subject     string
}

// EnsureSSOUser creates or updates a User CRD for an SSO user.
// This is called on every SSO login to ensure we have a user record.
// If the user exists, it updates their last login time.
// If the user doesn't exist, it creates a new User CRD.
func (s *UserService) EnsureSSOUser(ctx context.Context, req EnsureSSOUserRequest) (*User, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, errors.New("email is required")
	}

	// Try to find existing user by email
	existing, err := s.findUserByEmail(ctx, email)
	if err != nil && !errors.Is(err, ErrUserNotFound) {
		return nil, fmt.Errorf("failed to check existing user: %w", err)
	}

	now := metav1.Now()

	if existing != nil {
		// User exists - update last login and potentially update profile info
		s.logger.Debug("SSO user exists, updating last login",
			"email", email,
			"username", existing.Name,
		)

		user, err := s.dynamicClient.Resource(UserGVR).Get(ctx, existing.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get user for update: %w", err)
		}

		needsUpdate := false
		authType, _, _ := unstructured.NestedString(user.Object, "spec", "authType")

		if authType != AuthTypeSSO {
			s.logger.Info("Updating user to SSO auth type",
				"username", existing.Name,
				"previousAuthType", authType,
			)
			unstructured.SetNestedField(user.Object, AuthTypeSSO, "spec", "authType")
			unstructured.SetNestedField(user.Object, req.Provider, "spec", "ssoProvider")
			unstructured.SetNestedField(user.Object, req.Subject, "spec", "ssoSubject")
			needsUpdate = true

			// Update label too
			labels := user.GetLabels()
			if labels == nil {
				labels = make(map[string]string)
			}
			labels["butler.butlerlabs.dev/auth-type"] = AuthTypeSSO
			user.SetLabels(labels)
		}

		// Update profile info from IdP (SSO is source of truth for display name/avatar)
		currentDisplay, _, _ := unstructured.NestedString(user.Object, "spec", "displayName")
		if req.DisplayName != "" && req.DisplayName != currentDisplay {
			unstructured.SetNestedField(user.Object, req.DisplayName, "spec", "displayName")
			needsUpdate = true
		}

		currentAvatar, _, _ := unstructured.NestedString(user.Object, "spec", "avatar")
		if req.Picture != "" && req.Picture != currentAvatar {
			unstructured.SetNestedField(user.Object, req.Picture, "spec", "avatar")
			needsUpdate = true
		}

		// Update ssoProvider/ssoSubject if they've changed (handles provider migrations)
		if authType == AuthTypeSSO {
			currentProvider, _, _ := unstructured.NestedString(user.Object, "spec", "ssoProvider")
			if req.Provider != "" && req.Provider != currentProvider {
				unstructured.SetNestedField(user.Object, req.Provider, "spec", "ssoProvider")
				needsUpdate = true
			}

			currentSubject, _, _ := unstructured.NestedString(user.Object, "spec", "ssoSubject")
			if req.Subject != "" && req.Subject != currentSubject {
				unstructured.SetNestedField(user.Object, req.Subject, "spec", "ssoSubject")
				needsUpdate = true
			}
		}

		if needsUpdate {
			_, err = s.dynamicClient.Resource(UserGVR).Update(ctx, user, metav1.UpdateOptions{})
			if err != nil {
				s.logger.Warn("Failed to update SSO user profile", "error", err)
			}
		}

		// Update status with last login
		loginCount, _, _ := unstructured.NestedInt64(user.Object, "status", "loginCount")
		unstructured.SetNestedField(user.Object, now.Format(time.RFC3339), "status", "lastLoginTime")
		unstructured.SetNestedField(user.Object, loginCount+1, "status", "loginCount")

		_, err = s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, user, metav1.UpdateOptions{})
		if err != nil {
			s.logger.Warn("Failed to update SSO user last login", "error", err)
			// Don't fail login just because status update failed
		}

		// Return updated user info (not the stale 'existing' variable)
		return &User{
			Name:        existing.Name,
			Email:       email,
			DisplayName: req.DisplayName,
			Avatar:      req.Picture,
			Disabled:    existing.Disabled,
			Phase:       "Active",
			AuthType:    AuthTypeSSO,
			SSOProvider: req.Provider,
			SSOSubject:  req.Subject,
		}, nil
	}

	// Create new SSO user
	s.logger.Info("Creating User CRD for SSO user",
		"email", email,
		"provider", req.Provider,
	)

	// Generate username from email
	username := sanitizeUsername(email)

	// Ensure username is unique
	username, err = s.ensureUniqueUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	// Create the User CRD
	user := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "User",
			"metadata": map[string]interface{}{
				"name": username,
				"labels": map[string]interface{}{
					"butler.butlerlabs.dev/auth-type": AuthTypeSSO,
				},
			},
			"spec": map[string]interface{}{
				"email":       email,
				"displayName": req.DisplayName,
				"authType":    AuthTypeSSO,
				"disabled":    false,
				"avatar":      req.Picture,
				"ssoProvider": req.Provider,
				"ssoSubject":  req.Subject,
			},
		},
	}

	created, err := s.dynamicClient.Resource(UserGVR).Create(ctx, user, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create SSO user: %w", err)
	}

	// Set initial status
	unstructured.SetNestedField(created.Object, "Active", "status", "phase")
	unstructured.SetNestedField(created.Object, now.Format(time.RFC3339), "status", "lastLoginTime")
	unstructured.SetNestedField(created.Object, int64(1), "status", "loginCount")

	_, err = s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, created, metav1.UpdateOptions{})
	if err != nil {
		s.logger.Warn("Failed to set initial status for SSO user", "error", err)
	}

	s.logger.Info("Created SSO user",
		"username", username,
		"email", email,
		"provider", req.Provider,
	)

	return &User{
		Name:        username,
		Email:       email,
		DisplayName: req.DisplayName,
		Avatar:      req.Picture,
		Disabled:    false,
		Phase:       "Active",
		AuthType:    AuthTypeSSO,
		SSOProvider: req.Provider,
		SSOSubject:  req.Subject,
	}, nil
}

// CreateUser creates a new internal user and generates an invite token.
// Returns the invite URL that should be shared with the user.
func (s *UserService) CreateUser(ctx context.Context, req CreateUserRequest) (*CreateUserResponse, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	if email == "" {
		return nil, errors.New("email is required")
	}

	// Check if email is already in use
	if existing, _ := s.findUserByEmail(ctx, email); existing != nil {
		return nil, ErrUserExists
	}

	// Generate username
	username := req.Username
	if username == "" {
		username = sanitizeUsername(email)
	} else {
		username = strings.ToLower(strings.TrimSpace(username))
	}

	// Ensure username is unique
	username, err := s.ensureUniqueUsername(ctx, username)
	if err != nil {
		return nil, err
	}

	// Generate invite token
	rawToken, tokenHash, err := generateInviteToken()
	if err != nil {
		return nil, fmt.Errorf("failed to generate invite token: %w", err)
	}

	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(DefaultInviteExpiry))

	// Create the User CRD
	user := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "butler.butlerlabs.dev/v1alpha1",
			"kind":       "User",
			"metadata": map[string]interface{}{
				"name": username,
				"labels": map[string]interface{}{
					"butler.butlerlabs.dev/auth-type": AuthTypeInternal,
				},
			},
			"spec": map[string]interface{}{
				"email":       email,
				"displayName": req.DisplayName,
				"authType":    AuthTypeInternal,
				"disabled":    false,
			},
		},
	}

	created, err := s.dynamicClient.Resource(UserGVR).Create(ctx, user, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	// Update status with invite token
	status := map[string]interface{}{
		"phase":           "Pending",
		"inviteTokenHash": tokenHash,
		"inviteExpiresAt": expiresAt.Format(time.RFC3339),
		"inviteSentAt":    now.Format(time.RFC3339),
	}
	unstructured.SetNestedMap(created.Object, status, "status")

	_, err = s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, created, metav1.UpdateOptions{})
	if err != nil {
		// Clean up the created user
		s.dynamicClient.Resource(UserGVR).Delete(ctx, username, metav1.DeleteOptions{})
		return nil, fmt.Errorf("failed to set user status: %w", err)
	}

	inviteURL := fmt.Sprintf("%s/invite/%s", s.baseURL, rawToken)

	s.logger.Info("Internal user created with invite",
		"username", username,
		"email", email,
		"expiresAt", expiresAt.Format(time.RFC3339),
	)

	return &CreateUserResponse{
		User: User{
			Name:        username,
			Email:       email,
			DisplayName: req.DisplayName,
			Phase:       "Pending",
			AuthType:    AuthTypeInternal,
		},
		InviteURL: inviteURL,
	}, nil
}

// ListUsers returns all users from User CRDs.
func (s *UserService) ListUsers(ctx context.Context) ([]User, error) {
	list, err := s.dynamicClient.Resource(UserGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return []User{}, nil
		}
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	users := make([]User, 0, len(list.Items))
	for _, item := range list.Items {
		user, err := s.parseUser(&item)
		if err != nil {
			s.logger.Warn("Failed to parse user", "name", item.GetName(), "error", err)
			continue
		}
		users = append(users, *user)
	}

	return users, nil
}

// GetUser returns a user by username.
func (s *UserService) GetUser(ctx context.Context, username string) (*User, error) {
	user, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return s.parseUser(user)
}

// GetUserByEmail returns a user by email address.
func (s *UserService) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	return s.findUserByEmail(ctx, strings.ToLower(strings.TrimSpace(email)))
}

// DeleteUser deletes a user and their associated secrets.
func (s *UserService) DeleteUser(ctx context.Context, username string) error {
	// Get user first to check if they exist
	user, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	// Delete password secret if it exists (internal users only)
	authType, _, _ := unstructured.NestedString(user.Object, "spec", "authType")
	if authType == AuthTypeInternal {
		secretName := fmt.Sprintf("user-%s-password", username)
		err = s.clientset.CoreV1().Secrets(DefaultSecretNamespace).Delete(ctx, secretName, metav1.DeleteOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			s.logger.Warn("Failed to delete password secret", "secret", secretName, "error", err)
		}
	}

	// Delete the user CRD
	err = s.dynamicClient.Resource(UserGVR).Delete(ctx, username, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	s.logger.Info("User deleted", "username", username)
	return nil
}

// DisableUser disables a user account.
func (s *UserService) DisableUser(ctx context.Context, username string) error {
	user, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	unstructured.SetNestedField(user.Object, true, "spec", "disabled")
	_, err = s.dynamicClient.Resource(UserGVR).Update(ctx, user, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to disable user: %w", err)
	}

	// Update status
	unstructured.SetNestedField(user.Object, "Disabled", "status", "phase")
	s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, user, metav1.UpdateOptions{})

	s.logger.Info("User disabled", "username", username)
	return nil
}

// EnableUser enables a disabled user account.
func (s *UserService) EnableUser(ctx context.Context, username string) error {
	user, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	unstructured.SetNestedField(user.Object, false, "spec", "disabled")
	_, err = s.dynamicClient.Resource(UserGVR).Update(ctx, user, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to enable user: %w", err)
	}

	// Update status - set to Active or Pending based on whether they've set password
	authType, _, _ := unstructured.NestedString(user.Object, "spec", "authType")
	phase := "Active"
	if authType == AuthTypeInternal {
		// Check if password is set
		secretRef, _, _ := unstructured.NestedStringMap(user.Object, "status", "passwordSecretRef")
		if secretRef == nil || secretRef["name"] == "" {
			phase = "Pending"
		}
	}
	unstructured.SetNestedField(user.Object, phase, "status", "phase")
	s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, user, metav1.UpdateOptions{})

	s.logger.Info("User enabled", "username", username)
	return nil
}

// ValidateInviteToken checks if an invite token is valid and returns the user.
func (s *UserService) ValidateInviteToken(ctx context.Context, token string) (*User, error) {
	tokenHash := hashToken(token)

	users, err := s.dynamicClient.Resource(UserGVR).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("butler.butlerlabs.dev/auth-type=%s", AuthTypeInternal),
	})
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

		// Check phase
		phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
		if phase != "Pending" {
			return nil, ErrInvalidInviteToken
		}

		return s.parseUser(&u)
	}

	return nil, ErrInvalidInviteToken
}

// SetPassword sets the password for an internal user using their invite token.
func (s *UserService) SetPassword(ctx context.Context, token string, password string) (*User, error) {
	// Validate password strength
	if len(password) < MinPasswordLength {
		return nil, fmt.Errorf("%w: password must be at least %d characters", ErrPasswordTooWeak, MinPasswordLength)
	}

	// Find user by token
	tokenHash := hashToken(token)
	var targetUser *unstructured.Unstructured

	users, err := s.dynamicClient.Resource(UserGVR).List(ctx, metav1.ListOptions{
		LabelSelector: fmt.Sprintf("butler.butlerlabs.dev/auth-type=%s", AuthTypeInternal),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	for i := range users.Items {
		u := &users.Items[i]
		storedHash, _, _ := unstructured.NestedString(u.Object, "status", "inviteTokenHash")
		if storedHash != tokenHash {
			continue
		}

		expiresAtStr, _, _ := unstructured.NestedString(u.Object, "status", "inviteExpiresAt")
		if expiresAtStr != "" {
			expiresAt, err := time.Parse(time.RFC3339, expiresAtStr)
			if err == nil && time.Now().After(expiresAt) {
				return nil, ErrInvalidInviteToken
			}
		}

		phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")
		if phase != "Pending" {
			return nil, ErrInvalidInviteToken
		}

		targetUser = u
		break
	}

	if targetUser == nil {
		return nil, ErrInvalidInviteToken
	}

	username := targetUser.GetName()

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	// Create the password secret
	secretName := fmt.Sprintf("user-%s-password", username)
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: DefaultSecretNamespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "butler",
				"butler.butlerlabs.dev/user":   username,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			PasswordHashKey: hashedPassword,
		},
	}

	_, err = s.clientset.CoreV1().Secrets(DefaultSecretNamespace).Create(ctx, secret, metav1.CreateOptions{})
	if err != nil && !apierrors.IsAlreadyExists(err) {
		return nil, fmt.Errorf("failed to create password secret: %w", err)
	}
	if apierrors.IsAlreadyExists(err) {
		secret.Data[PasswordHashKey] = hashedPassword
		_, err = s.clientset.CoreV1().Secrets(DefaultSecretNamespace).Update(ctx, secret, metav1.UpdateOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to update password secret: %w", err)
		}
	}

	// Update user status
	now := time.Now().Format(time.RFC3339)
	unstructured.SetNestedField(targetUser.Object, "Active", "status", "phase")
	unstructured.SetNestedField(targetUser.Object, "", "status", "inviteTokenHash")
	unstructured.SetNestedField(targetUser.Object, now, "status", "passwordChangedAt")
	unstructured.SetNestedMap(targetUser.Object, map[string]interface{}{
		"name":      secretName,
		"namespace": DefaultSecretNamespace,
		"key":       PasswordHashKey,
	}, "status", "passwordSecretRef")

	_, err = s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, targetUser, metav1.UpdateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to update user status: %w", err)
	}

	s.logger.Info("User completed registration", "username", username)

	return s.parseUser(targetUser)
}

// RegenerateInvite creates a new invite token for an internal user.
func (s *UserService) RegenerateInvite(ctx context.Context, username string) (string, error) {
	user, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			return "", ErrUserNotFound
		}
		return "", fmt.Errorf("failed to get user: %w", err)
	}

	// Only allow for internal users
	authType, _, _ := unstructured.NestedString(user.Object, "spec", "authType")
	if authType != AuthTypeInternal {
		return "", errors.New("cannot regenerate invite for SSO user")
	}

	// Generate new invite token
	rawToken, tokenHash, err := generateInviteToken()
	if err != nil {
		return "", fmt.Errorf("failed to generate invite token: %w", err)
	}

	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(DefaultInviteExpiry))

	// Update status
	unstructured.SetNestedField(user.Object, "Pending", "status", "phase")
	unstructured.SetNestedField(user.Object, tokenHash, "status", "inviteTokenHash")
	unstructured.SetNestedField(user.Object, expiresAt.Format(time.RFC3339), "status", "inviteExpiresAt")
	unstructured.SetNestedField(user.Object, now.Format(time.RFC3339), "status", "inviteSentAt")

	_, err = s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, user, metav1.UpdateOptions{})
	if err != nil {
		return "", fmt.Errorf("failed to update user status: %w", err)
	}

	// Delete password secret if it exists
	secretName := fmt.Sprintf("user-%s-password", username)
	s.clientset.CoreV1().Secrets(DefaultSecretNamespace).Delete(ctx, secretName, metav1.DeleteOptions{})

	inviteURL := fmt.Sprintf("%s/invite/%s", s.baseURL, rawToken)

	s.logger.Info("Invite regenerated",
		"username", username,
		"expiresAt", expiresAt.Format(time.RFC3339),
	)

	return inviteURL, nil
}

// AuthenticateInternal authenticates an internal user with email and password.
func (s *UserService) AuthenticateInternal(ctx context.Context, email, password string) (*User, error) {
	email = strings.ToLower(strings.TrimSpace(email))

	user, err := s.findUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	// Must be internal user
	if user.AuthType != AuthTypeInternal {
		return nil, ErrInvalidCredentials
	}

	// Get the raw user object for status updates
	rawUser, err := s.dynamicClient.Resource(UserGVR).Get(ctx, user.Name, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Check if disabled
	if user.Disabled {
		return nil, ErrUserDisabled
	}

	// Check if locked
	lockedUntilStr, _, _ := unstructured.NestedString(rawUser.Object, "status", "lockedUntil")
	if lockedUntilStr != "" {
		lockedUntil, err := time.Parse(time.RFC3339, lockedUntilStr)
		if err == nil && time.Now().Before(lockedUntil) {
			return nil, ErrUserLocked
		}
	}

	// Check if pending
	if user.Phase == "Pending" {
		return nil, ErrUserPending
	}

	// Get password secret reference
	secretRef, _, _ := unstructured.NestedStringMap(rawUser.Object, "status", "passwordSecretRef")
	if secretRef == nil || secretRef["name"] == "" {
		return nil, ErrUserPending
	}

	// Get password hash from secret
	secret, err := s.clientset.CoreV1().Secrets(secretRef["namespace"]).Get(ctx, secretRef["name"], metav1.GetOptions{})
	if err != nil {
		s.logger.Error("Failed to get password secret", "error", err)
		return nil, ErrInvalidCredentials
	}

	hashedPassword := secret.Data[secretRef["key"]]
	if len(hashedPassword) == 0 {
		return nil, ErrInvalidCredentials
	}

	// Verify password
	err = bcrypt.CompareHashAndPassword(hashedPassword, []byte(password))
	if err != nil {
		s.recordFailedAttempt(ctx, rawUser)
		return nil, ErrInvalidCredentials
	}

	// Record successful login
	s.recordSuccessfulLogin(ctx, rawUser)

	return user, nil
}

// Helper functions

func (s *UserService) findUserByEmail(ctx context.Context, email string) (*User, error) {
	users, err := s.dynamicClient.Resource(UserGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}

	for _, u := range users.Items {
		userEmail, _, _ := unstructured.NestedString(u.Object, "spec", "email")
		if strings.EqualFold(userEmail, email) {
			return s.parseUser(&u)
		}
	}

	return nil, ErrUserNotFound
}

func (s *UserService) ensureUniqueUsername(ctx context.Context, baseUsername string) (string, error) {
	username := baseUsername
	for i := 1; i <= 100; i++ {
		_, err := s.dynamicClient.Resource(UserGVR).Get(ctx, username, metav1.GetOptions{})
		if apierrors.IsNotFound(err) {
			return username, nil
		}
		if err != nil {
			return "", fmt.Errorf("failed to check username availability: %w", err)
		}
		username = fmt.Sprintf("%s-%d", baseUsername, i)
	}
	return "", errors.New("could not generate unique username")
}

func (s *UserService) parseUser(u *unstructured.Unstructured) (*User, error) {
	email, _, _ := unstructured.NestedString(u.Object, "spec", "email")
	displayName, _, _ := unstructured.NestedString(u.Object, "spec", "displayName")
	avatar, _, _ := unstructured.NestedString(u.Object, "spec", "avatar")
	disabled, _, _ := unstructured.NestedBool(u.Object, "spec", "disabled")
	authType, _, _ := unstructured.NestedString(u.Object, "spec", "authType")
	ssoProvider, _, _ := unstructured.NestedString(u.Object, "spec", "ssoProvider")
	ssoSubject, _, _ := unstructured.NestedString(u.Object, "spec", "ssoSubject")
	phase, _, _ := unstructured.NestedString(u.Object, "status", "phase")

	// Default authType for backwards compatibility
	if authType == "" {
		authType = AuthTypeInternal
	}

	return &User{
		Name:        u.GetName(),
		Email:       email,
		DisplayName: displayName,
		Avatar:      avatar,
		Disabled:    disabled,
		Phase:       phase,
		AuthType:    authType,
		SSOProvider: ssoProvider,
		SSOSubject:  ssoSubject,
	}, nil
}

func (s *UserService) recordFailedAttempt(ctx context.Context, user *unstructured.Unstructured) {
	failedAttempts, _, _ := unstructured.NestedInt64(user.Object, "status", "failedLoginAttempts")
	failedAttempts++

	unstructured.SetNestedField(user.Object, failedAttempts, "status", "failedLoginAttempts")

	if failedAttempts >= MaxFailedAttempts {
		unstructured.SetNestedField(user.Object, time.Now().Add(LockDuration).Format(time.RFC3339), "status", "lockedUntil")
		unstructured.SetNestedField(user.Object, "Locked", "status", "phase")
		s.logger.Warn("User account locked", "user", user.GetName(), "attempts", failedAttempts)
	}

	s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, user, metav1.UpdateOptions{})
}

func (s *UserService) recordSuccessfulLogin(ctx context.Context, user *unstructured.Unstructured) {
	loginCount, _, _ := unstructured.NestedInt64(user.Object, "status", "loginCount")

	unstructured.SetNestedField(user.Object, time.Now().Format(time.RFC3339), "status", "lastLoginTime")
	unstructured.SetNestedField(user.Object, loginCount+1, "status", "loginCount")
	unstructured.SetNestedField(user.Object, int64(0), "status", "failedLoginAttempts")
	unstructured.SetNestedField(user.Object, "", "status", "lockedUntil")

	phase, _, _ := unstructured.NestedString(user.Object, "status", "phase")
	if phase == "Locked" {
		unstructured.SetNestedField(user.Object, "Active", "status", "phase")
	}

	s.dynamicClient.Resource(UserGVR).UpdateStatus(ctx, user, metav1.UpdateOptions{})
}

func sanitizeUsername(email string) string {
	username := strings.Split(email, "@")[0]
	username = strings.ToLower(username)
	username = strings.ReplaceAll(username, ".", "-")
	username = strings.ReplaceAll(username, "+", "-")
	username = strings.ReplaceAll(username, "_", "-")
	return username
}

func generateInviteToken() (rawToken string, hash string, err error) {
	tokenBytes := make([]byte, InviteTokenLength)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", "", err
	}
	rawToken = base64.URLEncoding.EncodeToString(tokenBytes)
	hash = hashToken(rawToken)
	return rawToken, hash, nil
}

func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
