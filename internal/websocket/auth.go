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

// requireTeamAccess gates the caller on membership of the given team.
// Platform admins bypass the team check. Returns true when the caller has
// access; otherwise writes HTTP 403 and returns false. Matching is by
// exact team name. The caller passes the team name from the request (URL
// path param on tenant-terminal endpoints), which in butler-server's
// model equals the team namespace that the controller reconciles.
func requireTeamAccess(w http.ResponseWriter, r *http.Request, session *SessionInfo, team string, log *slog.Logger) bool {
	if session.PlatformRole == "admin" || session.PlatformRole == "viewer" {
		return true
	}
	for _, tm := range session.Teams {
		if tm.Name == team {
			return true
		}
	}
	log.Warn("WebSocket upgrade rejected",
		"path", r.URL.Path,
		"remote", r.RemoteAddr,
		"reason", "forbidden",
		"user", session.Email,
		"team", team,
		"detail", "team access required",
	)
	http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	return false
}
