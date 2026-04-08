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

package audit

import (
	"fmt"

	ws "github.com/butlerdotdev/butler-server/internal/websocket"
)

// shouldNotify determines if an audit event should generate a real-time notification.
// Returns nil for events that don't warrant notifications.
func shouldNotify(event Event) *ws.NotificationPayload {
	// Cluster mutations (create, delete, scale)
	if event.ResourceType == "TenantCluster" && event.Success {
		return clusterMutationNotification(event)
	}

	// Team membership mutations
	if event.ResourceType == "Team" && event.Path != "" {
		if containsSubpath(event.Path, "/members") {
			return teamMemberNotification(event)
		}
		if containsSubpath(event.Path, "/groups") {
			return teamGroupNotification(event)
		}
	}

	// Failed login attempts
	if event.Action == "login_failed" {
		return &ws.NotificationPayload{
			Title:    "Failed login attempt",
			Message:  fmt.Sprintf("From %s (%s)", event.User, event.SourceIP),
			Severity: "warning",
			Category: "security",
		}
	}

	// User permission changes
	if event.ResourceType == "User" && (event.Action == "update" || event.Action == "create" || event.Action == "delete") {
		return &ws.NotificationPayload{
			Title:    fmt.Sprintf("User %s %sd", event.ResourceName, event.Action),
			Message:  fmt.Sprintf("By %s", event.User),
			Severity: "info",
			Category: "security",
			ResourceRef: &ws.ResourceRef{
				Kind: "User",
				Name: event.ResourceName,
			},
		}
	}

	// Provider failures
	if event.ResourceType == "ProviderConfig" && !event.Success {
		return &ws.NotificationPayload{
			Title:    fmt.Sprintf("Provider %s operation failed", event.ResourceName),
			Message:  event.ErrorMessage,
			Severity: "error",
			Category: "infra",
			ResourceRef: &ws.ResourceRef{
				Kind:      "ProviderConfig",
				Name:      event.ResourceName,
				Namespace: event.ResourceNamespace,
			},
		}
	}

	// Image sync failures
	if event.ResourceType == "ImageSync" && !event.Success {
		return &ws.NotificationPayload{
			Title:   "Image sync operation failed",
			Message: event.ErrorMessage,
			Severity: "error",
			Category: "infra",
			ResourceRef: &ws.ResourceRef{
				Kind: "ImageSync",
				Name: event.ResourceName,
			},
		}
	}

	return nil
}

func teamMemberNotification(event Event) *ws.NotificationPayload {
	team := event.TeamRef
	if team == "" {
		team = event.ResourceName
	}

	switch event.Action {
	case "create":
		return &ws.NotificationPayload{
			Title:    fmt.Sprintf("Member added to %s", team),
			Message:  fmt.Sprintf("Added by %s", event.User),
			Severity: "info",
			Category: "team",
			ResourceRef: &ws.ResourceRef{
				Kind: "Team",
				Name: team,
				Team: team,
			},
		}
	case "delete":
		return &ws.NotificationPayload{
			Title:    fmt.Sprintf("Member removed from %s", team),
			Message:  fmt.Sprintf("Removed by %s", event.User),
			Severity: "warning",
			Category: "team",
			ResourceRef: &ws.ResourceRef{
				Kind: "Team",
				Name: team,
				Team: team,
			},
		}
	case "update":
		return &ws.NotificationPayload{
			Title:    fmt.Sprintf("Role changed in %s", team),
			Message:  fmt.Sprintf("Changed by %s", event.User),
			Severity: "info",
			Category: "team",
			ResourceRef: &ws.ResourceRef{
				Kind: "Team",
				Name: team,
				Team: team,
			},
		}
	}
	return nil
}

func teamGroupNotification(event Event) *ws.NotificationPayload {
	team := event.TeamRef
	if team == "" {
		team = event.ResourceName
	}

	switch event.Action {
	case "create":
		return &ws.NotificationPayload{
			Title:    fmt.Sprintf("Group sync added to %s", team),
			Message:  fmt.Sprintf("Added by %s", event.User),
			Severity: "info",
			Category: "team",
			ResourceRef: &ws.ResourceRef{
				Kind: "Team",
				Name: team,
				Team: team,
			},
		}
	case "delete":
		return &ws.NotificationPayload{
			Title:    fmt.Sprintf("Group sync removed from %s", team),
			Message:  fmt.Sprintf("Removed by %s", event.User),
			Severity: "warning",
			Category: "team",
			ResourceRef: &ws.ResourceRef{
				Kind: "Team",
				Name: team,
				Team: team,
			},
		}
	}
	return nil
}

func clusterMutationNotification(event Event) *ws.NotificationPayload {
	ref := &ws.ResourceRef{
		Kind:      "TenantCluster",
		Name:      event.ResourceName,
		Namespace: event.ResourceNamespace,
		Team:      event.TeamRef,
	}

	switch event.Action {
	case "create":
		return &ws.NotificationPayload{
			Title:       fmt.Sprintf("Cluster %s created", event.ResourceName),
			Message:     fmt.Sprintf("Created by %s", event.User),
			Severity:    "info",
			Category:    "cluster",
			ResourceRef: ref,
		}
	case "delete":
		return &ws.NotificationPayload{
			Title:       fmt.Sprintf("Cluster %s deletion initiated", event.ResourceName),
			Message:     fmt.Sprintf("Deleted by %s", event.User),
			Severity:    "warning",
			Category:    "cluster",
			ResourceRef: ref,
		}
	case "scale":
		return &ws.NotificationPayload{
			Title:       fmt.Sprintf("Cluster %s scaled", event.ResourceName),
			Message:     fmt.Sprintf("Scaled by %s", event.User),
			Severity:    "info",
			Category:    "cluster",
			ResourceRef: ref,
		}
	case "update":
		return &ws.NotificationPayload{
			Title:       fmt.Sprintf("Cluster %s updated", event.ResourceName),
			Message:     fmt.Sprintf("Updated by %s", event.User),
			Severity:    "info",
			Category:    "cluster",
			ResourceRef: ref,
		}
	}
	return nil
}

func containsSubpath(path, subpath string) bool {
	return len(path) > 0 && len(subpath) > 0 && contains(path, subpath)
}

func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
