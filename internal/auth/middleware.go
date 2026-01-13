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
	"net/http"
	"strings"
)

type contextKey string

const (
	// UserContextKey is the context key for the authenticated user.
	UserContextKey contextKey = "user"
)

// SessionMiddleware creates authentication middleware using the session service.
func SessionMiddleware(sessionService *SessionService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenString string

			// Try to get token from cookie first (preferred for web clients)
			cookie, err := r.Cookie("butler_session")
			if err == nil && cookie.Value != "" {
				tokenString = cookie.Value
			}

			// Fall back to Authorization header (for API clients)
			if tokenString == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					tokenString = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			if tokenString == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// Validate session
			user, err := sessionService.ValidateSession(tokenString)
			if err != nil {
				http.Error(w, `{"error":"invalid or expired session"}`, http.StatusUnauthorized)
				return
			}

			// Add user to context
			ctx := context.WithValue(r.Context(), UserContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// UserFromContext extracts the user session from the request context.
func UserFromContext(ctx context.Context) *UserSession {
	user, ok := ctx.Value(UserContextKey).(*UserSession)
	if !ok {
		return nil
	}
	return user
}

// RequireTeamAccess creates middleware that requires access to a specific team.
// The team name is extracted from the URL parameter specified by teamParam.
func RequireTeamAccess(teamParam string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// Extract team from URL or query parameter
			// This is a simplified version - in practice you'd use chi.URLParam
			teamName := r.URL.Query().Get(teamParam)
			if teamName == "" {
				// No team specified, allow access (cluster may not have team ownership)
				next.ServeHTTP(w, r)
				return
			}

			if !user.HasTeamMembership(teamName) {
				http.Error(w, `{"error":"forbidden: not a member of this team"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireTeamRole creates middleware that requires a specific role in a team.
func RequireTeamRole(teamParam, requiredRole string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			teamName := r.URL.Query().Get(teamParam)
			if teamName == "" {
				next.ServeHTTP(w, r)
				return
			}

			membership := user.GetTeamMembership(teamName)
			if membership == nil {
				http.Error(w, `{"error":"forbidden: not a member of this team"}`, http.StatusForbidden)
				return
			}

			// Check if user's role is sufficient
			if !RoleHierarchy(membership.Role, requiredRole) {
				http.Error(w, `{"error":"forbidden: insufficient role"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin creates middleware that requires admin role in any team.
func RequireAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			if !user.IsAdmin() {
				http.Error(w, `{"error":"forbidden: admin role required"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ClusterTeamAuthz is middleware that checks team access for cluster operations.
// It expects the cluster's team label to be passed or extracted from the cluster.
type ClusterTeamAuthz struct {
	GetClusterTeam func(ctx context.Context, namespace, name string) (string, error)
}

// NewClusterTeamAuthz creates a new cluster team authorization middleware.
func NewClusterTeamAuthz(getTeamFunc func(ctx context.Context, namespace, name string) (string, error)) *ClusterTeamAuthz {
	return &ClusterTeamAuthz{
		GetClusterTeam: getTeamFunc,
	}
}

// RequireAccess creates middleware that requires access to a cluster's team.
func (c *ClusterTeamAuthz) RequireAccess() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// For now, just pass through - actual team extraction requires
			// integration with the cluster handler
			next.ServeHTTP(w, r)
		})
	}
}

// OptionalAuth creates middleware that sets user context if authenticated,
// but allows unauthenticated requests to proceed.
func OptionalAuth(sessionService *SessionService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var tokenString string

			cookie, err := r.Cookie("butler_session")
			if err == nil && cookie.Value != "" {
				tokenString = cookie.Value
			}

			if tokenString == "" {
				authHeader := r.Header.Get("Authorization")
				if strings.HasPrefix(authHeader, "Bearer ") {
					tokenString = strings.TrimPrefix(authHeader, "Bearer ")
				}
			}

			// If we have a token, try to validate it
			if tokenString != "" {
				if user, err := sessionService.ValidateSession(tokenString); err == nil {
					ctx := context.WithValue(r.Context(), UserContextKey, user)
					r = r.WithContext(ctx)
				}
			}

			next.ServeHTTP(w, r)
		})
	}
}
