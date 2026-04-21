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
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// Middleware returns a chi middleware that records audit events for mutation requests.
// Must be wired AFTER SessionMiddleware so user identity is available.
func Middleware(emitter *Emitter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			method := r.Method

			// Only audit mutations
			if method != http.MethodPost && method != http.MethodPut &&
				method != http.MethodPatch && method != http.MethodDelete {
				next.ServeHTTP(w, r)
				return
			}

			// Skip auth endpoints handled explicitly
			if isAuthPath(r.URL.Path) {
				next.ServeHTTP(w, r)
				return
			}

			// Capture request body and restore for downstream handlers.
			// Read the full body so downstream gets everything, but only
			// log a truncated summary for audit purposes.
			var bodySummary string
			if r.Body != nil && method != http.MethodDelete {
				bodyBytes, _ := io.ReadAll(r.Body)
				r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				summary := bodyBytes
				if len(summary) > 2048 {
					summary = summary[:2048]
				}
				bodySummary = ScrubRequestBody(summary)
			}

			// Wrap response writer to capture status code
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)

			start := time.Now()
			next.ServeHTTP(ww, r)

			// Build audit event after handler completes
			statusCode := ww.Status()
			if statusCode == 0 {
				statusCode = http.StatusOK
			}

			user := auth.UserFromContext(r.Context())
			email := "anonymous"
			teamRef := ""
			if user != nil {
				email = user.Email
				teamRef = user.SelectedTeam
			}

			event := Event{
				Timestamp:         start.UTC(),
				User:              email,
				Action:            resolveAction(method, r.URL.Path),
				ResourceType:      resolveResourceType(r.URL.Path),
				ResourceName:      chi.URLParam(r, "name"),
				ResourceNamespace: chi.URLParam(r, "namespace"),
				TeamRef:           teamRef,
				HTTPMethod:        method,
				Path:              r.URL.Path,
				StatusCode:        statusCode,
				Success:           statusCode >= 200 && statusCode < 400,
				RequestSummary:    bodySummary,
				SourceIP:          r.RemoteAddr,
			}

			// Capture error from response if failure
			if !event.Success {
				event.ErrorMessage = http.StatusText(statusCode)
			}

			emitter.Emit(event)
		})
	}
}

func isAuthPath(path string) bool {
	return strings.HasPrefix(path, "/api/auth/login") ||
		strings.HasPrefix(path, "/api/auth/logout") ||
		strings.HasPrefix(path, "/api/auth/callback") ||
		strings.HasPrefix(path, "/api/auth/set-password")
}

// resolveAction maps HTTP method + path to a semantic action.
func resolveAction(method, path string) string {
	switch method {
	case http.MethodPost:
		return "create"
	case http.MethodPut:
		return "update"
	case http.MethodDelete:
		return "delete"
	case http.MethodPatch:
		if strings.Contains(path, "/scale") {
			return "scale"
		}
		return "update"
	default:
		return strings.ToLower(method)
	}
}

// resolveResourceType extracts the resource type from the API path.
func resolveResourceType(path string) string {
	pathMap := []struct {
		prefix       string
		resourceType string
	}{
		{"/api/clusters/", "TenantCluster"},
		{"/api/teams/", "Team"},
		{"/api/admin/users/", "User"},
		{"/api/providers/", "ProviderConfig"},
		{"/api/admin/identity-providers/", "IdentityProvider"},
		{"/api/admin/networks/", "NetworkPool"},
		{"/api/management/addons/", "ManagementAddon"},
		{"/api/image-syncs/", "ImageSync"},
		{"/api/admin/config", "ButlerConfig"},
		{"/api/admin/observability/", "Observability"},
		{"/api/gitops/", "GitOps"},
		{"/api/admin/addons/catalog", "AddonDefinition"},
		{"/api/admin/ipallocations/", "IPAllocation"},
	}

	for _, entry := range pathMap {
		if strings.HasPrefix(path, entry.prefix) {
			// Check for sub-resources
			suffix := path[len(entry.prefix):]
			if strings.Contains(suffix, "/addons") {
				return "TenantAddon"
			}
			if strings.Contains(suffix, "/workspaces") {
				return "Workspace"
			}
			if strings.Contains(suffix, "/gitops") {
				return "GitOps"
			}
			if strings.Contains(suffix, "/certificates") {
				return "Certificate"
			}
			return entry.resourceType
		}
	}

	return "Unknown"
}
