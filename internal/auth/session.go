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
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TeamMembership represents a user's membership in a team.
type TeamMembership struct {
	// Name is the team name (metadata.name from Team CRD)
	Name string `json:"name"`

	// Role is the user's role in the team (admin, operator, viewer)
	Role string `json:"role"`
}

// UserSession represents an authenticated user's session.
type UserSession struct {
	// Subject is the OIDC subject identifier (unique per provider)
	Subject string `json:"sub"`

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

// HasTeamMembership checks if a user belongs to a specific team.
func (u *UserSession) HasTeamMembership(teamName string) bool {
	for _, team := range u.Teams {
		if team.Name == teamName {
			return true
		}
	}
	return false
}

// GetTeamMembership returns the user's membership for a specific team, or nil.
func (u *UserSession) GetTeamMembership(teamName string) *TeamMembership {
	for _, team := range u.Teams {
		if team.Name == teamName {
			return &team
		}
	}
	return nil
}

// HasRole checks if the user has the specified role in any team.
func (u *UserSession) HasRole(role string) bool {
	for _, team := range u.Teams {
		if team.Role == role {
			return true
		}
	}
	return false
}

// HasRoleInTeam checks if the user has the specified role in a specific team.
func (u *UserSession) HasRoleInTeam(teamName, role string) bool {
	membership := u.GetTeamMembership(teamName)
	if membership == nil {
		return false
	}
	return membership.Role == role
}

// IsAdmin checks if the user is an admin in any team.
func (u *UserSession) IsAdmin() bool {
	return u.HasRole("admin")
}

// IsAdminOfTeam checks if the user is an admin of a specific team.
func (u *UserSession) IsAdminOfTeam(teamName string) bool {
	return u.HasRoleInTeam(teamName, "admin")
}

// CanOperateTeam checks if the user can perform operations on a team's resources.
// Admins and operators can perform operations.
func (u *UserSession) CanOperateTeam(teamName string) bool {
	membership := u.GetTeamMembership(teamName)
	if membership == nil {
		return false
	}
	return membership.Role == "admin" || membership.Role == "operator"
}

// CanViewTeam checks if the user can view a team's resources.
// All team members (admin, operator, viewer) can view.
func (u *UserSession) CanViewTeam(teamName string) bool {
	return u.HasTeamMembership(teamName)
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
