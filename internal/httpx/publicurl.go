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

// Package httpx contains helpers for deriving public-facing URL shapes
// from incoming HTTP requests. Request-shape helpers live here so that
// non-handler callers (audit, email, middleware) can reach them without
// importing the handlers package.
package httpx

import (
	"net/http"

	"github.com/butlerdotdev/butler-server/internal/config"
)

// PublicBaseURL returns the scheme://host (no trailing slash, no path)
// that the server should advertise to clients when producing a URL that
// points back to itself: CLI device-flow verification URIs, invite URLs
// in new code paths, OIDC callback hints.
//
// Precedence:
//
//  1. cfg.FrontendURL if non-empty.
//  2. cfg.Server.BaseURL if non-empty and not the default placeholder
//     "http://localhost:8080". The default-value comparison lets unset
//     deployments fall through to request derivation instead of
//     advertising localhost. Once invite URL construction is migrated
//     off BaseURL, the default can move to empty and this comparison
//     can go away.
//  3. Derived from the request:
//     - scheme: r.TLS != nil means TLS terminates at this process and
//       is ground truth; use https. Else X-Forwarded-Proto when
//       cfg.Server.TrustProxyHeaders is set and the value is one of
//       {http, https}. Else http.
//     - host: X-Forwarded-Host first value when
//       cfg.Server.TrustProxyHeaders is set and non-empty. Else
//       r.Host.
//     - strip the default port for the scheme using net.SplitHostPort,
//       re-bracketing IPv6 literals on reassembly.
//
// Returns the empty string when no override is set and the request has
// no Host. Callers must treat that as a misconfiguration and fail the
// request rather than emitting a placeholder URL.
//
// Proxy headers are attacker-controllable input. The function honors
// X-Forwarded-Proto and X-Forwarded-Host only when the operator has
// asserted, via cfg.Server.TrustProxyHeaders, that the ingress strips
// and replaces these headers at the boundary. Without that assertion,
// an unauthenticated client could cause this function to return an
// attacker-controlled URL that the CLI would later open in the
// operator's browser.
func PublicBaseURL(r *http.Request, cfg *config.Config) string {
	return ""
}
