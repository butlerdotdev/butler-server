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
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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

// webhookDenialReason is the structured 403 reason butler-console keys
// on to render the denial inline on edit forms instead of as a toast.
// See ADR-010 Decision: "Error passthrough".
const webhookDenialReason = "webhook-denied"

// writeWebhookError detects Kubernetes webhook denials embedded in the
// apiserver's Forbidden response and surfaces them as a structured 403
// so butler-console can inline-render the denial. Non-webhook errors
// and non-Forbidden errors fall through to writeError. The extracted
// message preserves the webhook's field path when the apiserver
// includes a Cause with FieldValueForbidden or similar; otherwise the
// raw message string is returned. Returns true when the error was
// recognized as a webhook denial, false when it was not and the
// caller should continue with its default error handler.
func writeWebhookError(w http.ResponseWriter, err error) bool {
	if err == nil || !apierrors.IsForbidden(err) {
		return false
	}
	statusErr, ok := err.(*apierrors.StatusError)
	if !ok {
		return false
	}
	msg := statusErr.ErrStatus.Message
	if !strings.Contains(msg, "admission webhook") && !strings.Contains(msg, "denied the request") {
		return false
	}
	field := ""
	if statusErr.ErrStatus.Details != nil {
		for _, cause := range statusErr.ErrStatus.Details.Causes {
			switch cause.Type {
			case metav1.CauseTypeForbidden,
				metav1.CauseTypeFieldValueInvalid,
				metav1.CauseTypeFieldValueRequired,
				metav1.CauseTypeFieldValueNotSupported:
				field = cause.Field
			}
			if field != "" {
				break
			}
		}
	}
	writeJSON(w, http.StatusForbidden, map[string]string{
		"error":   "webhook denied",
		"reason":  webhookDenialReason,
		"message": msg,
		"field":   field,
	})
	return true
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
