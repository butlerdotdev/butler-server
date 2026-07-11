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

package websocket

import (
	"log/slog"
	"net/http"
)

// anonymousUser is the user log-key value for rejections where no session
// has been resolved yet (401 paths). Distinguishes anonymous probes from
// authenticated-but-unauthorized attempts in incident-response triage.
const anonymousUser = "<unauthenticated>"

// requireSession extracts and validates the session from the WebSocket
// upgrade request using the configured sessionResolver. On failure it
// writes HTTP 401 to w and returns nil; the caller must return without
// upgrading. See ADR-013.
func requireSession(w http.ResponseWriter, r *http.Request, resolver SessionResolverFunc, log *slog.Logger) *SessionInfo {
	if resolver == nil {
		log.Warn("WebSocket upgrade rejected",
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"reason", "unauthorized",
			"user", anonymousUser,
			"detail", "sessionResolver not configured",
		)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return nil
	}
	session, err := resolver(r)
	if err != nil || session == nil {
		log.Warn("WebSocket upgrade rejected",
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"reason", "unauthorized",
			"user", anonymousUser,
			"error", err,
		)
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return nil
	}
	return session
}

// requirePlatformAdmin gates the caller on platform-admin status. Returns
// true when the session is a platform admin; otherwise writes HTTP 403 and
// returns false.
func requirePlatformAdmin(w http.ResponseWriter, r *http.Request, session *SessionInfo, log *slog.Logger) bool {
	if session.PlatformRole == "admin" {
		return true
	}
	log.Warn("WebSocket upgrade rejected",
		"path", r.URL.Path,
		"remote", r.RemoteAddr,
		"reason", "forbidden",
		"user", session.Email,
		"detail", "platform admin required",
	)
	http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	return false
}

// terminalAccess is the authorization outcome for a tenant terminal request.
type terminalAccess int

const (
	// terminalRefused denies the connection before upgrade.
	terminalRefused terminalAccess = iota
	// terminalReadOnly permits the connection to stream shell output but
	// drops all client input.
	terminalReadOnly
	// terminalWrite permits a fully interactive shell.
	terminalWrite
)

// Butler role names, kept local to the websocket package so the upgrade path
// does not depend on the auth package. These mirror auth.Role* constants.
const (
	roleAdmin    = "admin"
	roleOperator = "operator"
	roleViewer   = "viewer"
)

// resolveTerminalAccess decides whether a session may open a tenant terminal for
// the given team and at what capability, and returns a role label for audit logs.
// The team argument is the cluster's namespace, which in butler-server's model
// equals the owning team name.
//
// It is allowlist-write: terminalWrite is returned only for an explicit
// write-capable match (platform admin, or a team admin or operator membership).
// Every other case, including a membership carrying an unknown or empty role,
// falls through to read-only or refused, never write. The failure mode of a
// permissive default on this path is a tenant cluster-admin shell, so the
// default is deny.
func resolveTerminalAccess(session *SessionInfo, team string) (terminalAccess, string) {
	if session == nil {
		return terminalRefused, ""
	}
	if session.PlatformRole == roleAdmin {
		return terminalWrite, "platform-admin"
	}
	for _, tm := range session.Teams {
		if tm.Name != team {
			continue
		}
		switch tm.Role {
		case roleAdmin, roleOperator:
			return terminalWrite, tm.Role
		default:
			// A real membership carrying viewer, an unrecognized role, or an
			// empty role is never write-capable; the most it grants is read-only.
			return terminalReadOnly, tm.Role
		}
	}
	if session.PlatformRole == roleViewer {
		return terminalReadOnly, "platform-viewer"
	}
	return terminalRefused, ""
}
