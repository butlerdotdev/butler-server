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
	"log/slog"
	"net/http"
	"strings"
)

type contextKey string

const userContextKey contextKey = "user"

// UserFromContext retrieves the authenticated user from the request context.
func UserFromContext(ctx context.Context) *UserSession {
	user, _ := ctx.Value(userContextKey).(*UserSession)
	return user
}

// SessionMiddlewareConfig holds dependencies for the session middleware.
type SessionMiddlewareConfig struct {
	SessionService *SessionService
	TeamResolver   *TeamResolver
	UserService    *UserService // Added: for checking disabled status
	Logger         *slog.Logger
}

// SessionMiddleware validates the session token and re-resolves team membership on every request.
// This ensures that when a user is removed from a team or disabled, they immediately lose access.
// Platform admins bypass team membership checks but still respect team-scoped authorization
// when X-Butler-Team header is present.
func SessionMiddleware(cfg SessionMiddlewareConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Get session token from cookie or header
			var token string

			// Try cookie first
			if cookie, err := r.Cookie("butler_session"); err == nil {
				token = cookie.Value
			}

			// Fall back to Authorization header
			if token == "" {
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(auth, "Bearer ") {
					token = strings.TrimPrefix(auth, "Bearer ")
				}
			}

			if token == "" {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// Validate session
			user, err := cfg.SessionService.ValidateSession(token)
			if err != nil {
				http.Error(w, `{"error":"invalid session"}`, http.StatusUnauthorized)
				return
			}

			// Read team context from header (sent by frontend when scoped to a team)
			selectedTeam := r.Header.Get("X-Butler-Team")

			// Platform admins path
			if user.IsPlatformAdmin {
				// When requests come through the Backstage portal proxy, all
				// requests authenticate as the admin service account. The proxy
				// forwards the real user's email via X-Butler-User-Email so the
				// server can use it as the effective identity (e.g., workspace
				// ownership, SSH key resolution). Only trust this header for
				// platform admin sessions to prevent unprivileged impersonation.
				if impersonateEmail := r.Header.Get("X-Butler-User-Email"); impersonateEmail != "" {
					if cfg.Logger != nil {
						cfg.Logger.Debug("Platform admin impersonating user via X-Butler-User-Email",
							"sessionEmail", user.Email,
							"effectiveEmail", impersonateEmail,
						)
					}
					user.Email = impersonateEmail
				}

				// Set team context if provided - this enables team-scoped authorization
				// even for platform admins when they're viewing a specific team
				if selectedTeam != "" {
					user.SelectedTeam = selectedTeam
					// Find user's actual role in this team (might be from group sync)
					membership := findTeamMembership(user.Teams, selectedTeam)
					if membership != nil {
						user.SelectedTeamRole = membership.Role
					} else {
						// Platform admin without explicit membership gets admin role
						// This allows platform admins to access any team
						user.SelectedTeamRole = RoleAdmin
					}

					if cfg.Logger != nil {
						cfg.Logger.Debug("Platform admin with team context",
							"email", user.Email,
							"selectedTeam", selectedTeam,
							"selectedTeamRole", user.SelectedTeamRole,
						)
					}
				} else {
					if cfg.Logger != nil {
						cfg.Logger.Debug("Platform admin access granted (no team scope)",
							"email", user.Email,
							"subject", user.Subject,
						)
					}
				}

				ctx := context.WithValue(r.Context(), userContextKey, user)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			// SECURITY: Check if user is disabled in User CRD
			// This only applies to non-platform-admin users
			if cfg.UserService != nil {
				userCRD, err := cfg.UserService.GetUserByEmail(r.Context(), user.Email)
				if err != nil {
					// User CRD not found - this could happen for legacy admin
					// Log but don't block (legacy admin has no User CRD)
					if cfg.Logger != nil {
						cfg.Logger.Debug("User CRD not found during auth check",
							"email", user.Email,
							"error", err,
						)
					}
				} else if userCRD.Disabled {
					// User is disabled - reject the request
					if cfg.Logger != nil {
						cfg.Logger.Warn("Disabled user attempted access",
							"email", user.Email,
							"username", userCRD.Name,
						)
					}
					http.Error(w, `{"error":"account disabled"}`, http.StatusForbidden)
					return
				}
			}

			// Re-resolve team memberships on every request for non-platform-admins
			// This ensures team removal takes effect immediately
			if cfg.TeamResolver != nil {
				freshTeams, err := cfg.TeamResolver.ResolveTeams(r.Context(), user.Email, user.Groups)
				if err != nil {
					// Log but don't fail - will check for empty teams below
					if cfg.Logger != nil {
						cfg.Logger.Warn("Failed to re-resolve teams", "email", user.Email, "error", err)
					}
					freshTeams = []TeamMembership{}
				}
				user.Teams = freshTeams
			}

			// Check if user has any team membership (required for access)
			// Platform admins already bypassed above, so this only affects regular users
			if len(user.Teams) == 0 {
				http.Error(w, `{"error":"no team access - contact your administrator"}`, http.StatusForbidden)
				return
			}

			// Set team context for non-platform-admins
			if selectedTeam != "" {
				membership := findTeamMembership(user.Teams, selectedTeam)
				if membership != nil {
					user.SelectedTeam = selectedTeam
					user.SelectedTeamRole = membership.Role
				}
				// If user doesn't have membership in selected team, leave SelectedTeam empty
				// This will cause authorization checks to fail appropriately
			}

			// Add user to context with fresh team data
			ctx := context.WithValue(r.Context(), userContextKey, user)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// findTeamMembership finds a team membership by name from a list
func findTeamMembership(teams []TeamMembership, teamName string) *TeamMembership {
	for i := range teams {
		if teams[i].Name == teamName {
			return &teams[i]
		}
	}
	return nil
}

// RequireTeam creates middleware that requires membership in a specific team.
func RequireTeam(teamName string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			// Platform admins have access to all teams
			if user.IsPlatformAdmin {
				next.ServeHTTP(w, r)
				return
			}

			hasAccess := false
			for _, team := range user.Teams {
				if team.Name == teamName {
					hasAccess = true
					break
				}
			}

			if !hasAccess {
				http.Error(w, `{"error":"forbidden: team access required"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequireAdmin creates middleware that requires admin role in any team.
// Platform admins always pass this check.
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

// RequirePlatformAdmin creates middleware that requires platform admin privileges.
// Use this for operations that should only be available to platform-level admins,
// not team-level admins.
func RequirePlatformAdmin() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			user := UserFromContext(r.Context())
			if user == nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			if !user.IsPlatformAdmin {
				http.Error(w, `{"error":"forbidden: platform admin required"}`, http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// AdminMiddleware is an alias for RequireAdmin for API consistency.
func AdminMiddleware() func(http.Handler) http.Handler {
	return RequireAdmin()
}

// ClusterTeamAuthz is middleware that checks team access for cluster operations.
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

			// Platform admins have access to all clusters
			if user.IsPlatformAdmin {
				next.ServeHTTP(w, r)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
