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

// resolveWSSession validates the token and builds the WebSocket SessionInfo,
// re-resolving team memberships and roles from Team CRDs rather than trusting the
// JWT claims. On team-resolution error it proceeds with no teams, so platform
// admins still authorize via PlatformRole while team members fail closed at the
// downstream terminal gate.
func resolveWSSession(ctx context.Context, token string, validator wsSessionValidator, resolver wsTeamResolver, logger *slog.Logger) (*websocket.SessionInfo, error) {
	session, err := validator.ValidateSession(token)
	if err != nil {
		return nil, err
	}
	info := &websocket.SessionInfo{
		Email:           session.Email,
		IsPlatformAdmin: session.IsPlatformAdmin,
		PlatformRole:    session.PlatformRole,
	}
	teams, err := resolver.ResolveTeams(ctx, session.Email, session.Groups)
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
