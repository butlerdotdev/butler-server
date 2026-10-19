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

package api

import (
	"context"
	"errors"
	"log/slog"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/websocket"
)

// wsSessionValidator validates a session token. Satisfied by *auth.SessionService.
type wsSessionValidator interface {
	ValidateSession(token string) (*auth.UserSession, error)
}

// wsTeamResolver resolves a user's current team memberships from Team CRDs.
// Satisfied by *auth.TeamResolver.
type wsTeamResolver interface {
	ResolveTeams(ctx context.Context, email string, groups []string) ([]auth.TeamMembership, error)
}

// wsPortalVerifier validates portal-minted proofs. Satisfied by
// *auth.PortalJWTVerifier. Pass nil (not a typed nil pointer) when the
// portal public key is not configured.
type wsPortalVerifier interface {
	MaybeVerify(ctx context.Context, token string) (*auth.UserSession, bool, error)
}

// wsUserLookup reads the User CRD so disabled accounts are refused at
// upgrade time. Satisfied by *auth.UserService.
type wsUserLookup interface {
	GetUserByEmail(ctx context.Context, email string) (*auth.UserInfo, error)
}

// wsSessionDeps are the collaborators resolveWSSession needs beyond the
// token validator; portal and users are optional.
type wsSessionDeps struct {
	validator wsSessionValidator
	resolver  wsTeamResolver
	portal    wsPortalVerifier
	users     wsUserLookup
	logger    *slog.Logger
}

var errWSUserDisabled = errors.New("account disabled")

// resolveWSSession validates the token and builds the WebSocket SessionInfo,
// re-resolving team memberships and roles from Team CRDs rather than trusting the
// JWT claims. It accepts the same two carriers as SessionMiddleware: a
// portal proof (iss=butler-portal) when a verifier is configured, otherwise
// an HMAC session. A token that claims the portal shape but fails
// verification is rejected, never retried as an HMAC session. Disabled
// users are refused. On team-resolution error it proceeds with no teams, so
// platform admins still authorize via PlatformRole while team members fail
// closed at the downstream terminal gate.
func resolveWSSession(ctx context.Context, token string, deps wsSessionDeps) (*websocket.SessionInfo, error) {
	logger := deps.logger
	var session *auth.UserSession
	if deps.portal != nil {
		portalSess, claimed, err := deps.portal.MaybeVerify(ctx, token)
		if err != nil {
			return nil, err
		}
		if claimed {
			if portalSess == nil {
				return nil, errors.New("invalid portal proof")
			}
			session = portalSess
		}
	}
	if session == nil {
		s, err := deps.validator.ValidateSession(token)
		if err != nil {
			return nil, err
		}
		session = s
	}
	if deps.users != nil {
		userCRD, err := deps.users.GetUserByEmail(ctx, session.Email)
		if err == nil && userCRD.Disabled {
			logger.Warn("Disabled user attempted WebSocket access", "email", session.Email)
			return nil, errWSUserDisabled
		}
	}
	info := &websocket.SessionInfo{
		Email:           session.Email,
		IsPlatformAdmin: session.IsPlatformAdmin,
		PlatformRole:    session.PlatformRole,
	}
	teams, err := deps.resolver.ResolveTeams(ctx, session.Email, session.Groups)
	if err != nil {
		logger.Warn("Failed to re-resolve teams for WebSocket session",
			"email", session.Email, "error", err)
		teams = nil
	}
	for _, tm := range teams {
		info.Teams = append(info.Teams, websocket.TeamInfo{Name: tm.Name, Role: tm.Role})
	}
	return info, nil
}
