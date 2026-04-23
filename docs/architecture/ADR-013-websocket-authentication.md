# ADR-013: WebSocket Authentication

## Status

Proposed

## Date

2026-04-23

## Context

butler-server exposes three WebSocket endpoints under `/ws/*`:

- `/ws/clusters`: cluster-watch stream broadcasting TenantCluster events to subscribed clients.
- `/ws/terminal/{type}/{namespace}/{cluster}[/pod/container]`: interactive PTY session into a tenant cluster via kubectl-exec.
- `/ws/terminal/management`: interactive PTY session into the management cluster.

Pre-ADR-013 state (read from `internal/websocket/hub.go`, commit at ADR-009 release):

- `HandleClusterWatch` calls the session resolver for notification filtering but does not reject on resolver failure. An unauthenticated client connects, receives events with empty team context, and the downstream filter hides team-scoped notifications. No shell, but an information channel with undefined trust boundary.
- `HandleTerminal` performs zero auth. Any client reaching the upgrade URL receives a PTY into the tenant cluster. The handler loads the tenant kubeconfig from the cluster's admin Secret via the server SA, so the attacker gets tenant-cluster-admin.
- `HandleManagementTerminal` performs zero auth. Same shape, different target: the management cluster's in-cluster kubeconfig, which is cluster-admin.

HTTP route registration in `internal/api/router.go` explicitly mounts `/ws/*` outside the `SessionMiddleware` chain. The comment on the WS routes notes that per-connection auth is the plan. That plan was never implemented.

This is a pre-Company-1 deploy blocker (tracked as F-SRV-001). The endpoint is reachable from any network path that hits butler-server; an attacker who phishes a laptop onto the butler-beta VPN or Company 1's internal network gets full management access.

Constraints:

- **Reuse the existing session layer.** butler-server already has `SessionResolver` that extracts JWT from the `butler_session` httpOnly cookie and from `Authorization: Bearer <token>`. The fix is wiring, not a new primitive.
- **Console clients must not need code changes.** The console's WebSocket code in `ClusterTerminal.tsx` opens same-origin WebSocket connections; browsers automatically forward the session cookie during the WS handshake.
- **CLI / external clients stay functional.** Any bearer-token client gets the same resolver path, no WS-specific auth knob.
- **Failure mode matches REST.** Unauthorized: 401 before upgrade. Forbidden: 403 before upgrade. Not accept-then-close mid-stream.
- **Authorization parity with REST.** Tenant terminal access requires team view permission on the target team (or platform admin). Management terminal requires platform admin. Cluster-watch requires any authenticated session; filter logic downstream handles team scope.

## Decision

All three `/ws/*` endpoints gate on the existing session resolver before `upgrader.Upgrade()`. After session validation, each endpoint performs endpoint-specific authorization. Unauthorized sessions produce HTTP 401; insufficient permissions produce HTTP 403. No per-connection re-handshake, no WS subprotocol smuggling.

### Session resolution

The handler calls `h.sessionResolver(r)`. The resolver is the same function used by `SessionMiddleware` (cookie first, bearer header fallback). On nil session or error: `http.Error(w, "unauthorized", 401)` and return. The upgrade never happens.

### Per-endpoint authorization

- **`/ws/clusters`**: any authenticated session accepted. Downstream filter applies team scope on events.
- **`/ws/terminal/{type}/{namespace}/{cluster}...`**: require `session.IsPlatformAdmin` OR a team membership whose namespace matches the URL's namespace parameter. Implementation detail: the URL namespace equals the Butler team namespace (team-owned namespace), so the check is team-membership lookup on `session.Teams`.
- **`/ws/terminal/management`**: require `session.IsPlatformAdmin`. No team-scope fallback.

Non-admin on management → 403. Non-team-member on tenant → 403. Returns before upgrade.

### Helper extraction

The three handlers each need the same three-step pattern: resolve session → return 401, authorize → return 403, then upgrade. Common helper in `internal/websocket/auth.go`:

```go
// requireSession extracts and validates the session. Returns the session
// or writes 401 and returns nil.
func requireSession(w http.ResponseWriter, r *http.Request, resolver SessionResolverFunc) *auth.UserSession

// requirePlatformAdmin returns true if the session is platform admin;
// otherwise writes 403 and returns false.
func requirePlatformAdmin(w http.ResponseWriter, session *auth.UserSession) bool

// requireTeamAccess returns true if the session has view access to the
// given team namespace; otherwise writes 403 and returns false.
func requireTeamAccess(w http.ResponseWriter, session *auth.UserSession, teamNamespace string) bool
```

Handlers chain these three into a single top-of-function auth block. Existing upgrade and stream logic stays unchanged.

### Logging

On each rejection, log:

```go
h.log.Warn("WebSocket upgrade rejected",
    "path", r.URL.Path,
    "remote", r.RemoteAddr,
    "reason", "unauthorized" | "forbidden",
    "user", session.Email | "<unauthenticated>",
)
```

The `user` field distinguishes anonymous probes from authenticated-but-unauthorized attempts for incident analysis.

### Testing

Unit tests in `internal/websocket/hub_test.go` cover:

- No cookie → 401 without upgrade side effects.
- Expired/invalid JWT → 401.
- Valid session, non-admin, management endpoint → 403.
- Valid session, non-team-member, tenant endpoint → 403.
- Valid session, platform admin, management endpoint → upgrade succeeds.
- Valid session, team member, tenant endpoint for their team → upgrade succeeds.

Testing framework mirrors the existing `internal/auth/` test style (httptest server + table-driven cases).

## Consequences

### Positive

- F-SRV-001 closed. Production-ready auth gate on every WS endpoint.
- Audit trail: every rejection logged with path + user + reason.
- No console changes required; cookie flow is native to browser WS.
- No protocol changes: standard HTTP handshake carries auth, which is the pattern every WS library already understands.

### Negative

- Handlers hold more authorization logic at the entry point. Acceptable: the logic is small, symmetric across endpoints, and centralized in helpers.
- Any future WS endpoint must remember to call the helpers. Mitigated by documenting the pattern in butler-server's CLAUDE.md and by this ADR.

### Deferred

- Per-command impersonation inside the WS terminal (beyond connection-time auth). The PTY runs as the server SA against the target cluster's admin kubeconfig today; the user's identity gates the connection, not each keystroke. Stronger per-command impersonation (forward the user email into the kubectl exec via `Impersonate-User` headers) is a follow-up if auditors require it; F-SRV-001 does not.
- Session idle timeout enforcement on long-running PTY connections. The JWT carries an expiry; the current pattern validates only at handshake. Re-validating on-stream requires JWT re-fetch and is a separate hardening track.

## References

- `butler-server/internal/websocket/hub.go`: WS handler entry points.
- `butler-server/internal/api/router.go`: `/ws/*` route registration.
- `butler-server/internal/auth/middleware.go`: `SessionMiddleware` as the reference for session extraction.
- ADR-010 butler-server Impersonation Auth: companion decision for HTTP mutation paths.
- ADR-016 butler-cli Device Flow: CLI identity model that produces the bearer tokens WS endpoints will accept.
