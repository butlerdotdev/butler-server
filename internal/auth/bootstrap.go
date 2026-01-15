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
	"fmt"

	"golang.org/x/crypto/bcrypt"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BootstrapAdminConfig holds configuration for the bootstrap admin sync.
type BootstrapAdminConfig struct {
	// Username is the admin username
	Username string
	// Password is the admin password (from BUTLER_ADMIN_PASSWORD env var)
	Password string
	// SecretName is the name of the Secret to update with the hash
	// Default: "butler-console-admin"
	SecretName string
	// SecretNamespace is the namespace of the Secret
	// Default: "butler-system"
	SecretNamespace string
	// HashKey is the key in the Secret to store the hash
	// Default: "password-hash"
	HashKey string
}

// SyncBootstrapAdminPassword ensures the admin password hash is stored in the Secret.
// This should be called on server startup.
//
// The Secret is created by the butler-console Helm chart with:
//   - admin-password: the plaintext password (for env var injection)
//   - password-hash: empty (to be populated by this function)
//
// The butler-addons User CRD references this Secret's password-hash key
// for authentication.
func (s *UserService) SyncBootstrapAdminPassword(ctx context.Context, cfg BootstrapAdminConfig) error {
	if cfg.Password == "" {
		s.logger.Debug("No bootstrap admin password configured, skipping sync")
		return nil
	}

	// Apply defaults
	if cfg.SecretName == "" {
		cfg.SecretName = "butler-console-admin"
	}
	if cfg.SecretNamespace == "" {
		cfg.SecretNamespace = "butler-system"
	}
	if cfg.HashKey == "" {
		cfg.HashKey = "password-hash"
	}

	s.logger.Info("Syncing bootstrap admin password hash",
		"secret", cfg.SecretName,
		"namespace", cfg.SecretNamespace,
	)

	// Get the existing Secret
	secret, err := s.clientset.CoreV1().Secrets(cfg.SecretNamespace).Get(ctx, cfg.SecretName, metav1.GetOptions{})
	if err != nil {
		if apierrors.IsNotFound(err) {
			s.logger.Warn("Admin secret not found - butler-console chart may not be installed yet",
				"secret", cfg.SecretName,
				"namespace", cfg.SecretNamespace,
			)
			return nil // Not an error - chart ordering issue, will sync on next restart
		}
		return fmt.Errorf("failed to get admin secret: %w", err)
	}

	// Check if hash already exists and is non-empty
	existingHash := secret.Data[cfg.HashKey]
	if len(existingHash) > 0 {
		// Verify the existing hash matches the current password
		if err := bcrypt.CompareHashAndPassword(existingHash, []byte(cfg.Password)); err == nil {
			s.logger.Debug("Password hash already synced and matches current password")
			return nil
		}
		// Hash exists but doesn't match - password was changed, update it
		s.logger.Info("Password changed, updating hash")
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(cfg.Password), bcrypt.DefaultCost)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	// Update the Secret with the hash
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[cfg.HashKey] = hashedPassword

	_, err = s.clientset.CoreV1().Secrets(cfg.SecretNamespace).Update(ctx, secret, metav1.UpdateOptions{})
	if err != nil {
		return fmt.Errorf("failed to update admin secret with hash: %w", err)
	}

	s.logger.Info("Bootstrap admin password hash synced successfully")
	return nil
}
