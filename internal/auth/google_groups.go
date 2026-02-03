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
	"encoding/json"
	"fmt"
	"log/slog"

	"golang.org/x/oauth2/google"
	admin "google.golang.org/api/admin/directory/v1"
	"google.golang.org/api/option"
)

// GoogleGroupsFetcher fetches user groups from Google Workspace Admin SDK.
// This is required because Google OIDC tokens don't include group memberships.
type GoogleGroupsFetcher struct {
	service *admin.Service
	domain  string
	logger  *slog.Logger
}

// GoogleGroupsConfig holds configuration for Google Admin SDK group fetching.
type GoogleGroupsConfig struct {
	// ServiceAccountJSON is the JSON key for the service account with
	// domain-wide delegation enabled.
	ServiceAccountJSON string

	// AdminEmail is the email of a Google Workspace admin to impersonate.
	// Required for domain-wide delegation.
	AdminEmail string

	// Domain is the Google Workspace domain (e.g., "butlerlabs.dev").
	// Used to filter groups.
	Domain string
}

// NewGoogleGroupsFetcher creates a new Google groups fetcher.
// Requirements:
//   - Service account with domain-wide delegation enabled
//   - Scope: https://www.googleapis.com/auth/admin.directory.group.readonly
//   - AdminEmail must be a Google Workspace super admin
func NewGoogleGroupsFetcher(ctx context.Context, cfg *GoogleGroupsConfig, logger *slog.Logger) (*GoogleGroupsFetcher, error) {
	if cfg == nil || cfg.ServiceAccountJSON == "" {
		return nil, fmt.Errorf("service account JSON is required")
	}
	if cfg.AdminEmail == "" {
		return nil, fmt.Errorf("admin email is required for domain-wide delegation")
	}

	// Create JWT config for domain-wide delegation
	jwtConfig, err := google.JWTConfigFromJSON(
		[]byte(cfg.ServiceAccountJSON),
		admin.AdminDirectoryGroupReadonlyScope,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT config: %w", err)
	}

	// Set the subject (admin to impersonate)
	jwtConfig.Subject = cfg.AdminEmail

	// Create the Admin SDK client with impersonation
	client := jwtConfig.Client(ctx)
	service, err := admin.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create Admin SDK service: %w", err)
	}

	return &GoogleGroupsFetcher{
		service: service,
		domain:  cfg.Domain,
		logger:  logger,
	}, nil
}

// FetchUserGroups retrieves all groups a user belongs to.
// Returns group email addresses (e.g., ["engineers@example.com", "admins@example.com"]).
func (f *GoogleGroupsFetcher) FetchUserGroups(ctx context.Context, userEmail string) ([]string, error) {
	var groups []string
	var pageToken string

	for {
		call := f.service.Groups.List().UserKey(userEmail).MaxResults(200)
		if pageToken != "" {
			call = call.PageToken(pageToken)
		}

		resp, err := call.Context(ctx).Do()
		if err != nil {
			// Log the error but don't fail - user might not be in any groups
			f.logger.Warn("Failed to fetch groups from Google Admin SDK",
				"email", userEmail,
				"error", err,
			)
			return groups, nil
		}

		for _, group := range resp.Groups {
			groups = append(groups, group.Email)
			f.logger.Debug("Found group membership",
				"user", userEmail,
				"group", group.Email,
				"groupName", group.Name,
			)
		}

		pageToken = resp.NextPageToken
		if pageToken == "" {
			break
		}
	}

	f.logger.Info("Fetched Google Workspace groups",
		"email", userEmail,
		"groupCount", len(groups),
	)

	return groups, nil
}

// ValidateGoogleGroupsConfig checks if the Google groups configuration is valid.
func ValidateGoogleGroupsConfig(cfg *GoogleGroupsConfig) error {
	if cfg == nil {
		return fmt.Errorf("config is nil")
	}
	if cfg.ServiceAccountJSON == "" {
		return fmt.Errorf("serviceAccountJSON is required")
	}
	if cfg.AdminEmail == "" {
		return fmt.Errorf("adminEmail is required")
	}

	// Verify the JSON is valid
	var sa struct {
		Type        string `json:"type"`
		ClientEmail string `json:"client_email"`
		ClientID    string `json:"client_id"`
	}
	if err := json.Unmarshal([]byte(cfg.ServiceAccountJSON), &sa); err != nil {
		return fmt.Errorf("invalid service account JSON: %w", err)
	}
	if sa.Type != "service_account" {
		return fmt.Errorf("credential type must be 'service_account', got %q", sa.Type)
	}
	if sa.ClientEmail == "" {
		return fmt.Errorf("service account JSON missing client_email")
	}

	return nil
}
