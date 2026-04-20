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
	"net"
	"net/http"
	"strings"

	"github.com/butlerdotdev/butler-server/internal/config"
)

// baseURLDefaultPlaceholder is the BUTLER_BASE_URL default that config
// loading applies when the env var is unset. PublicBaseURL treats a
// BaseURL equal to this literal as "unset" so that default deployments
// fall through to request-based derivation instead of advertising
// localhost. When BUTLER_BASE_URL moves to an empty default (after
// invite URL construction migrates off the startup capture in
// internal/auth/users.go), this constant and the comparison using it
// can be removed.
const baseURLDefaultPlaceholder = "http://localhost:8080"

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
	if cfg.FrontendURL != "" {
		return strings.TrimRight(cfg.FrontendURL, "/")
	}
	if cfg.Server.BaseURL != "" && cfg.Server.BaseURL != baseURLDefaultPlaceholder {
		return strings.TrimRight(cfg.Server.BaseURL, "/")
	}

	host := derivedHost(r, cfg.Server.TrustProxyHeaders)
	if host == "" {
		return ""
	}
	scheme := derivedScheme(r, cfg.Server.TrustProxyHeaders)
	return scheme + "://" + stripDefaultPort(host, scheme)
}

// derivedScheme returns the scheme the caller is reaching this server
// under. When r.TLS is non-nil, TLS terminates at this process and
// local state is authoritative regardless of any forwarded header,
// which may be attacker-supplied or stale from a previous hop. The
// X-Forwarded-Proto fallback is honored only when the operator has
// opted in via TrustProxyHeaders; the value is lowercased and trimmed
// to tolerate proxies that emit "HTTPS" or include whitespace.
func derivedScheme(r *http.Request, trust bool) string {
	if r.TLS != nil {
		return "https"
	}
	if trust {
		p := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
		if p == "http" || p == "https" {
			return p
		}
	}
	return "http"
}

// derivedHost returns the host:port the client used to reach the
// server. X-Forwarded-Host is honored only when the operator has opted
// in via TrustProxyHeaders; its leftmost comma-separated value wins,
// which matches the convention used by ALB, CloudFront, and nginx
// defaults. Values carrying path, query, fragment, scheme, or
// whitespace characters are rejected as malformed and the code falls
// through to r.Host, so a misconfigured upstream proxy cannot inject
// a URL path into the emitted base URL.
func derivedHost(r *http.Request, trust bool) string {
	if trust {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			if i := strings.Index(h, ","); i >= 0 {
				h = h[:i]
			}
			h = strings.TrimSpace(h)
			if h != "" && isValidHostHeader(h) {
				return h
			}
		}
	}
	return r.Host
}

// isValidHostHeader reports whether s could plausibly be a bare
// host[:port] value. It rejects any character that indicates the value
// carries a URL path, query, fragment, scheme, or embedded whitespace.
// The check is intentionally strict and does not attempt full RFC
// grammar validation; its purpose is to fail closed when an upstream
// proxy emits something other than a host.
func isValidHostHeader(s string) bool {
	return !strings.ContainsAny(s, " \t\r\n/?#\\")
}

// stripDefaultPort removes :443 under https and :80 under http. It
// uses net.SplitHostPort so bracketed IPv6 literals are handled
// correctly; the host is re-bracketed on return if the parsed value
// contains a colon (meaning it came from an IPv6 literal).
func stripDefaultPort(host, scheme string) string {
	h, p, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	if (scheme == "https" && p == "443") || (scheme == "http" && p == "80") {
		if strings.Contains(h, ":") {
			return "[" + h + "]"
		}
		return h
	}
	return host
}
