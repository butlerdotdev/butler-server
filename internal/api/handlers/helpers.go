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
	"log/slog"
	"net/http"
)

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		slog.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes a JSON error response.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

// MapAddonStatus maps internal addon status to display status.
// Used by both cluster and addon handlers for consistent status display.
func MapAddonStatus(status string) string {
	switch status {
	case "Installed", "Healthy":
		return "Installed"
	case "Installing", "Progressing":
		return "Installing"
	case "Upgrading":
		return "Upgrading"
	case "Failed", "Unhealthy":
		return "Failed"
	case "Degraded":
		return "Degraded"
	case "Pending":
		return "Pending"
	case "Deleting":
		return "Deleting"
	default:
		return "Unknown"
	}
}
