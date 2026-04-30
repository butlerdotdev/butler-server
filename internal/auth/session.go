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
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// NormalizeEmail returns the canonical form of an email address for
// Butler identity comparisons: trimmed of surrounding whitespace and
// lowercased. Per ADR-010 this is applied at session creation so all
// downstream consumers (middleware, impersonation headers, application
// audit logs) read a single canonical form.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// TeamMembership represents a user's membership in a team.
type TeamMembership struct {
	// Name is the team name (metadata.name from Team CRD)
	Name string `json:"name"`

	// Role is the user's role in the team (admin, operator, viewer)
	Role string `json:"role"`
}

// UserSession represents an authenticated user's session.
type UserSession struct {
	// Subject is the OIDC subject identifier (unique per provider).
	// Uses "subject" tag to avoid collision with jwt.RegisteredClaims "sub" in SessionClaims.
	Subject string `json:"subject,omitempty"`

	// Email is the user's email address
	Email string `json:"email"`

	// Name is the user's display name
	Name string `json:"name"`

	// Picture is the URL to the user's profile picture
	Picture string `json:"picture,omitempty"`

	// Provider is the identity provider name (e.g., "google-workspace")
	Provider string `json:"provider,omitempty"`

	// Groups are the IdP groups the user belongs to
	Groups []string `json:"groups,omitempty"`

	// Teams are the resolved team memberships
	Teams []TeamMembership `json:"teams"`

	// PlatformRole is the effective platform-wide role for this session.
	// "admin" grants full platform access (manage all teams, clusters,
	// users, settings). "viewer" grants read-only access across all
	// teams and clusters. Empty string means no platform role; the user
	// has only their team-scoped permissions.
	//
	// Computed at session creation from: max(User.spec.platformRole,
	// User.spec.isPlatformAdmin, IdP group match). See ADR-014.
	PlatformRole string `json:"platformRole,omitempty"`

	// IsPlatformAdmin is kept for JSON serialization backwards
	// compatibility with existing JWTs and API responses. Computed
	// from PlatformRole == "admin". New code should check PlatformRole.
	//
	// Deprecated: use PlatformRole instead. Removal targeted for v1.0.0.
	// Tracked in butler-console#56, butler-cli#37, butler-server#56.
	IsPlatformAdmin bool `json:"isPlatformAdmin,omitempty"`

	// SelectedTeam is the team context from X-Butler-Team header.
	// When set, even platform admins are scoped to this team's permissions
	// for tenant resource operations (clusters, providers).
	// This is NOT persisted in JWT - it's set per-request by middleware.
	SelectedTeam string `json:"-"`

	// SelectedTeamRole is the user's role in the selected team.
	// Empty if no team is selected or user doesn't have membership.
	// For platform admins without explicit membership, this defaults
	// to "admin". For platform viewers, it defaults to "viewer".
	// This is NOT persisted in JWT - it's set per-request by middleware.
	SelectedTeamRole string `json:"-"`

	// SelectedEnvironment is the env context from X-Butler-Environment
	// header. Used with SelectedTeam to scope authorization to a specific
	// Team.spec.environments[] entry. Empty when the header is absent.
	// Not persisted in JWT; set per-request by middleware.
	SelectedEnvironment string `json:"-"`

	// SelectedEnvironmentRole is the user's effective role in the selected
	// environment. Computed as the additive max of SelectedTeamRole and
	// the role resolved from Team.spec.environments[].access for this user.
	// Env access can only elevate a team role, never reduce it
	// (ADR-009 additive-only inheritance).
	SelectedEnvironmentRole string `json:"-"`
}

// SessionClaims are the JWT claims for a user session.
type SessionClaims struct {
	UserSession
	jwt.RegisteredClaims
}

// SessionService handles session token operations.
type SessionService struct {
	secret []byte
	expiry time.Duration
}

// NewSessionService creates a new session service.
func NewSessionService(secret string, expiry time.Duration) *SessionService {
	return &SessionService{
		secret: []byte(secret),
		expiry: expiry,
	}
}

// CreateSession creates a new session token for a user.
func (s *SessionService) CreateSession(user *UserSession) (string, error) {
	now := time.Now()
	// Canonicalize email at the single funnel for session issuance.
	// Every call path (OIDC callback, internal login, device flow,
	// refresh, admin impersonation) passes through here.
	user.Email = NormalizeEmail(user.Email)
	// Keep IsPlatformAdmin in sync with PlatformRole for backwards
	// compat. Existing consumers (butler-console, butler-cli) read
	// this field from JWT claims and API responses.
	user.IsPlatformAdmin = user.PlatformRole == RoleAdmin
	claims := &SessionClaims{
		UserSession: *user,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(s.expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    "butler-server",
			Subject:   user.Subject,
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.secret)
}

// ValidateSession validates a session token and returns the user session.
func (s *SessionService) ValidateSession(tokenString string) (*UserSession, error) {
	token, err := jwt.ParseWithClaims(tokenString, &SessionClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return s.secret, nil
	})

	if err != nil {
		if err == jwt.ErrTokenExpired {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*SessionClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	// Canonicalize email on every session read so downstream consumers
	// (impersonation, audit logs, webhook creator-email matching) see
	// the same form. Pre-upgrade sessions may carry mixed-case emails.
	claims.UserSession.Email = NormalizeEmail(claims.UserSession.Email)
	// Migrate pre-upgrade JWTs that carry isPlatformAdmin=true but no
	// platformRole field. Without this, old tokens would lose admin
	// privileges after the session helper migration.
	if claims.UserSession.IsPlatformAdmin && claims.UserSession.PlatformRole == "" {
		claims.UserSession.PlatformRole = RoleAdmin
	}
	return &claims.UserSession, nil
}

// RefreshSession creates a new session token from an existing valid session.
func (s *SessionService) RefreshSession(tokenString string) (string, error) {
	user, err := s.ValidateSession(tokenString)
	if err != nil {
		return "", err
	}
	return s.CreateSession(user)
}

// IsPlatformViewerOrAbove returns true if the user has platform viewer
// or higher privileges. Both admin and viewer pass this check.
func (u *UserSession) IsPlatformViewerOrAbove() bool {
	return u.PlatformRole == RoleAdmin || u.PlatformRole == RoleViewer
}

// HasPlatformRole returns true if the user has any platform-wide role.
func (u *UserSession) HasPlatformRole() bool {
	return u.PlatformRole != ""
}

// HasTeamMembership checks if a user belongs to a specific team.
func (u *UserSession) HasTeamMembership(teamName string) bool {
	// Platform admins and viewers have implicit membership in all teams
	if u.PlatformRole == RoleAdmin || u.PlatformRole == RoleViewer {
		return true
	}
	for _, team := range u.Teams {
		if team.Name == teamName {
			return true
		}
	}
	return false
}

// GetTeamMembership returns the user's membership for a specific team, or nil.
// Platform admins get synthetic admin membership; platform viewers get
// synthetic viewer membership unless they have an explicit higher grant.
func (u *UserSession) GetTeamMembership(teamName string) *TeamMembership {
	// Check explicit membership first so it can override synthetic grants
	for _, team := range u.Teams {
		if team.Name == teamName {
			// Platform viewer with explicit higher role: return explicit
			if u.PlatformRole == RoleViewer && RoleHierarchy(team.Role, RoleViewer) {
				return &team
			}
			// Platform admin always gets admin regardless of explicit role
			if u.PlatformRole == RoleAdmin {
				return &TeamMembership{Name: teamName, Role: RoleAdmin}
			}
			return &team
		}
	}
	// No explicit membership; synthesize from platform role
	if u.PlatformRole == RoleAdmin {
		return &TeamMembership{Name: teamName, Role: RoleAdmin}
	}
	if u.PlatformRole == RoleViewer {
		return &TeamMembership{Name: teamName, Role: RoleViewer}
	}
	return nil
}

// HasRole checks if the user has the specified role in any team.
func (u *UserSession) HasRole(role string) bool {
	// Platform admin has all roles; platform viewer has viewer only
	if u.PlatformRole == RoleAdmin {
		return true
	}
	if u.PlatformRole == RoleViewer && role == RoleViewer {
		return true
	}
	for _, team := range u.Teams {
		if team.Role == role {
			return true
		}
	}
	return false
}

// HasRoleInTeam checks if the user has the specified role in a specific team.
func (u *UserSession) HasRoleInTeam(teamName, role string) bool {
	// Platform admin has all roles in all teams
	if u.PlatformRole == RoleAdmin {
		return true
	}
	// Platform viewer: only the viewer role in all teams
	if u.PlatformRole == RoleViewer && role == RoleViewer {
		return true
	}
	membership := u.GetTeamMembership(teamName)
	if membership == nil {
		return false
	}
	return membership.Role == role
}

// IsAdmin checks if the user has admin privileges.
// Returns true if the user is a platform admin or an admin of any team.
// Platform viewers do NOT pass this check.
func (u *UserSession) IsAdmin() bool {
	if u.PlatformRole == RoleAdmin {
		return true
	}
	return u.HasRole(RoleAdmin)
}

// IsAdminOfTeam checks if the user is an admin of a specific team.
// Platform viewers are NOT admins of any team.
func (u *UserSession) IsAdminOfTeam(teamName string) bool {
	if u.PlatformRole == RoleAdmin {
		return true
	}
	return u.HasRoleInTeam(teamName, RoleAdmin)
}

// CanOperateTeam checks if the user can perform operations on a team's resources.
// Admins and operators can perform operations. Platform viewers cannot.
func (u *UserSession) CanOperateTeam(teamName string) bool {
	if u.PlatformRole == RoleAdmin {
		return true
	}
	// Platform viewer cannot operate even though they have membership
	if u.PlatformRole == RoleViewer {
		// Check for explicit operator/admin grant on this team
		for _, team := range u.Teams {
			if team.Name == teamName {
				return team.Role == RoleAdmin || team.Role == RoleOperator
			}
		}
		return false
	}
	membership := u.GetTeamMembership(teamName)
	if membership == nil {
		return false
	}
	return membership.Role == RoleAdmin || membership.Role == RoleOperator
}

// CanViewTeam checks if the user can view a team's resources.
// All team members (admin, operator, viewer) can view. Platform viewers
// can view all teams.
func (u *UserSession) CanViewTeam(teamName string) bool {
	if u.PlatformRole == RoleAdmin || u.PlatformRole == RoleViewer {
		return true
	}
	return u.HasTeamMembership(teamName)
}

// CanOperateInSelectedTeam checks if the user can perform operations
// based on their role in the currently selected team context.
// This is the primary authorization check for tenant resource mutations.
// Platform viewers cannot operate unless they have an explicit higher
// role in the selected team.
func (u *UserSession) CanOperateInSelectedTeam() bool {
	// No team selected - use legacy behavior
	if u.SelectedTeam == "" {
		if u.PlatformRole == RoleAdmin {
			return true
		}
		return u.HasRole(RoleAdmin) || u.HasRole(RoleOperator)
	}

	// Team selected - check role in that team
	return u.SelectedTeamRole == RoleAdmin || u.SelectedTeamRole == RoleOperator
}

// CanViewInSelectedTeam checks if the user can view resources
// based on their role in the currently selected team context.
func (u *UserSession) CanViewInSelectedTeam() bool {
	// No team selected - use legacy behavior
	if u.SelectedTeam == "" {
		if u.PlatformRole == RoleAdmin || u.PlatformRole == RoleViewer {
			return true
		}
		return len(u.Teams) > 0
	}

	// Team selected - any role can view
	return u.SelectedTeamRole != ""
}

// effectiveEnvRole returns the additive max of SelectedTeamRole and
// SelectedEnvironmentRole when an env is selected. When no env is
// selected the SelectedTeamRole is authoritative. ADR-009 says env
// access can only elevate a team-level role, never reduce it; the max
// composition here is how that promise is delivered at session time.
func (u *UserSession) effectiveEnvRole() string {
	if u.SelectedEnvironment == "" {
		return u.SelectedTeamRole
	}
	return HighestRole([]string{u.SelectedTeamRole, u.SelectedEnvironmentRole})
}

// CanOperateInSelectedEnvironment checks if the user can mutate
// resources scoped to the selected environment. Mirrors
// CanOperateInSelectedTeam but uses the env-aware effective role. When
// no env is selected this falls back to team-level semantics.
func (u *UserSession) CanOperateInSelectedEnvironment() bool {
	if u.SelectedEnvironment == "" {
		return u.CanOperateInSelectedTeam()
	}
	if u.PlatformRole == RoleAdmin {
		return true
	}
	role := u.effectiveEnvRole()
	return role == RoleAdmin || role == RoleOperator
}

// CanViewInSelectedEnvironment checks if the user can read resources
// scoped to the selected environment.
func (u *UserSession) CanViewInSelectedEnvironment() bool {
	if u.SelectedEnvironment == "" {
		return u.CanViewInSelectedTeam()
	}
	if u.PlatformRole == RoleAdmin || u.PlatformRole == RoleViewer {
		return true
	}
	return u.effectiveEnvRole() != ""
}

// Role constants
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
)

// RoleHierarchy returns true if role1 has equal or higher privileges than role2.
func RoleHierarchy(role1, role2 string) bool {
	hierarchy := map[string]int{
		RoleAdmin:    3,
		RoleOperator: 2,
		RoleViewer:   1,
	}
	return hierarchy[role1] >= hierarchy[role2]
}

// HighestRole returns the highest role from a list of roles.
func HighestRole(roles []string) string {
	highest := ""
	highestLevel := 0
	hierarchy := map[string]int{
		RoleAdmin:    3,
		RoleOperator: 2,
		RoleViewer:   1,
	}
	for _, role := range roles {
		if level, ok := hierarchy[role]; ok && level > highestLevel {
			highest = role
			highestLevel = level
		}
	}
	return highest
}
