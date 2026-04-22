# ADR-010: butler-server Impersonation Auth for apiserver Mutations

## Status

Accepted

## Date

2026-04-21

## Context

butler-server is the HTTP/WebSocket API in front of the Butler control plane. It authenticates end-users via OIDC or internal credentials, issues a JWT session, and translates incoming HTTP into Kubernetes apiserver calls. Today every outgoing apiserver call uses butler-server's own ServiceAccount identity (`system:serviceaccount:butler-system:butler-server`) via a process-wide `rest.Config` built from `rest.InClusterConfig()` at startup (`cmd/server/main.go:141`). Handlers hold a shared `*k8s.Client` and share one dynamic client instance across all requests.

ADR-009 introduces admission webhooks on `Team` and `TenantCluster` that gate mutations on `req.UserInfo.Username`:

- `spec.resourceLimits` on Team requires platform admin; resolution reads the User CRD whose `spec.email` matches UserInfo.Username, or falls back to a SubjectAccessReview.
- `spec.environments[].limits` requires team admin of that team; same identity path.
- `MaxClustersPerMember` enforcement reads the `butler.butlerlabs.dev/creator-email` annotation on create and compares it to UserInfo.Username case-insensitively.

Under the current model every mutation from butler-server arrives at admission with UserInfo.Username = the server's SA. The SA is bound to a ClusterRole that grants `update teams`, so the webhook's SAR fallback returns allowed=true and treats butler-server as a platform admin on every call. Team admins modifying `spec.environments[].limits` would pass the webhook for the wrong reason; platform-only gates would silently accept non-platform callers. The creator-email annotation match fails entirely because the server's SA identity never matches a user email.

This is a production-grade auth hole. The webhook enforcement exists precisely to distinguish platform admins from team admins from operators at apiserver time; the server must forward the authenticated user's identity to close it.

Constraints:

- **No new identity services.** We will not run an external token service, cert-manager per-user cert issuance, or a dedicated OAuth token exchange. Kubernetes has built-in impersonation; use it.
- **No per-user SAs** for the console/API path. The butler-cli device flow (ADR-016) already creates per-user SAs with bound RoleBindings. That pattern does not extend cleanly to interactive HTTP traffic where every request could cost an SA + Role lookup.
- **Audit logs must show the acting user.** Compliance and incident response both require apiserver audit entries to name the human who submitted the mutation, not the proxy.
- **Backward compatibility.** Existing butler-server deployments continue to work. No breaking change to HTTP contract, session shape, or cookie.
- **Pre-existing internal impersonation stays.** `X-Butler-User-Email` from the Backstage portal proxy sets the in-memory session's `user.Email` (middleware.go:90). That is butler-server-internal identity; this ADR is about the apiserver-facing identity forward. Both can coexist.

## Decision

butler-server performs Kubernetes impersonation via `rest.Config.Impersonate` on the subset of outgoing apiserver calls that represent user-initiated mutations. Reads stay on the shared server-SA client because admission webhooks do not fire on reads and impersonation adds cost without benefit. The handler chooses the client explicitly per call; impersonation is opt-in by the handler, not a global middleware transformation.

### Client selection per call

Three client paths:

1. **`h.k8sClient`** - shared server-SA client. Used for reads, internal reconciles, SA provisioning (device flow), watches. Unchanged.
2. **`h.k8sClient.AsUser(session)`** - new helper that returns a request-scoped `*k8s.Client` whose `rest.Config.Impersonate` is populated from the session. Used by handlers that mutate Team, TenantCluster, or other webhook-gated resources.
3. **Hybrid** - handlers that read then mutate use `h.k8sClient` for the read and `h.k8sClient.AsUser(session)` for the mutation.

The `AsUser` helper shallow-copies the existing `rest.Config`, sets `Impersonate`, and constructs a fresh dynamic+typed client pair. Cost: one `rest.Config` copy plus client construction per impersonating call. Benchmark target: under 5ms added latency at the 99th percentile. If the cost becomes significant at scale, a per-session client cache keyed on the session ID can land as a follow-on; the initial shape is stateless.

### Impersonation payload

For every impersonating call, butler-server sends:

- `Impersonate-User: <session.Email>` - the authenticated end-user's canonical email. Lowercased before sending so case does not drift across webhook comparisons.
- `Impersonate-Group: butler-api-users` - a fixed group that carries the RBAC butler-server users need to perform webhook-gated mutations. Bound to a ClusterRole via a ClusterRoleBinding shipped in butler-charts.
- `Impersonate-Group: system:authenticated` - standard implicit identity. Sent explicitly so the apiserver applies built-in bindings consistently.

The user's own OIDC groups are NOT forwarded as impersonation groups. OIDC groups are organizational (e.g., `engineering@acme.com`) and have no Butler RBAC today; passing them adds audit-log noise without affecting authorization. If a future feature needs group-based apiserver authorization (e.g., "the `sre-leads` group can do X in K8s"), that ADR can extend this payload.

### RBAC model

butler-server SA gains:

- `impersonate` verb on `resources: ["users", "groups"]` in `""` apiGroup. Grants the right to send Impersonate-User/Group headers.
- Optionally `impersonate` on `resources: ["userextras"]` if we later need to forward claims; not needed in v1.

A new ClusterRole `butler-api-users` contains the union of RBAC that users may need butler-server to exercise on their behalf:

- Read/update on `teams`, `tenantclusters`, `tenantaddons`, `providerconfigs`, `workspaces`, `workspacetemplates`, `ipallocations`, `networkpools` in `butler.butlerlabs.dev`.
- Read on core types the handlers touch (namespaces, secrets for kubeconfig fetch, events).
- Write on `rolebindings` in `rbac.authorization.k8s.io` (team-membership management).

Bound via ClusterRoleBinding `butler-api-users-role-binding` to the group `butler-api-users`. No direct binding to individual users - the group is synthetic and only butler-server ever sends it.

This grants the SAME baseline K8s permissions to every user acting through butler-server. Butler-level authorization (team admin vs operator vs viewer) lives in the Team admission webhook and the butler-server session's role helpers. K8s RBAC is the coarse "can this caller touch this resource type at all" gate; Butler's admission webhook is the fine-grained "can this specific user modify this specific field on this specific Team" gate.

### Email canonicalization

`UserSession.Email` is canonicalized to lowercase at session creation (OIDC callback, internal login, device-flow token exchange, session refresh). All downstream consumers (middleware, handlers, impersonation, application audit logs) read the canonical form. This removes the need for each consumer to re-canonicalize and eliminates the risk of a mixed-case email in one code path failing an equality check in another. Apiserver audit logs always show the canonical lowercase form; this is the deliberate trade-off for consistency and matches the webhook's `strings.EqualFold` comparison convention.

### UserInfo flow from OIDC session to outgoing call

Session creation: OIDC callback or internal login populates `UserSession.Email` from the authenticated identity (canonicalized per above).

SessionMiddleware already resolves `SelectedTeam`/`SelectedTeamRole` on every request from the `X-Butler-Team` header. This ADR adds:

- `SelectedEnvironment` / `SelectedEnvironmentRole` (separate from impersonation, see ADR-009 §"Enforcement locations"; the env-role composition uses the session email).

Handler path for a mutating call:

```go
func (h *TeamHandler) Update(w http.ResponseWriter, r *http.Request) {
    user := auth.UserFromContext(r.Context())
    // Impersonating client for the mutation; apiserver-admission sees
    // UserInfo.Username = user.Email, which is what the webhook gates on.
    impClient := h.k8sClient.AsUser(user)
    if err := impClient.PatchTeam(r.Context(), name, patch); err != nil {
        // webhook denial surfaces here as a structured 403 (see §Error passthrough)
        writeWebhookError(w, err)
        return
    }
    writeJSON(w, http.StatusOK, ...)
}
```

### Service-account-originated calls

Calls NOT made on behalf of an end-user keep the server-SA identity:

- Device-flow SA provisioning (`internal/auth/serviceaccount.go`): butler-server creates SAs for CLI users. This is an administrative operation; the server SA's RBAC is the correct identity.
- Session validation's User CRD lookup (`internal/auth/users.go:GetUserByEmail`): reads the User CRD to check `disabled`. Server SA identity is correct - the user hasn't been authenticated for this specific call yet.
- Team resolution (`internal/auth/teams.go`): reads Team CRDs. Server SA.
- WebSocket cluster watches (`internal/websocket/hub.go`): long-lived watches. Server SA.
- Health and readiness probes: server SA, no authentication context.

The rule: if the call represents an action the user explicitly asked for AND the call is a MUTATION that could hit a webhook, impersonate. Otherwise, server SA. Reads NEVER need impersonation because no Butler admission webhook gates reads.

### Error passthrough

Webhook denials surface to the apiserver caller as a standard K8s `Forbidden` with the webhook's message embedded. butler-server's handlers today unwrap these as generic 403s. This ADR requires a structured 403 response body for webhook-denied mutations so butler-console can render the denial inline on edit forms:

```json
{
  "error": "webhook denied",
  "reason": "webhook-denied",
  "message": "spec.resourceLimits may only be modified by platform admins; user \"alice@example.com\" is not a platform admin",
  "field": "spec.resourceLimits"
}
```

New helper `writeWebhookError(w, err)` in `internal/api/handlers/helpers.go`. Detects webhook-denial via `apierrors.IsForbidden(err)` plus string sniff for the webhook's message shape, extracts the field path from the wrapped `field.Error` when present, and writes the structured body. Non-webhook 403s (e.g., RBAC denial) still return the existing shape.

## Alternatives Considered

### SA-only with annotation passthrough

Keep all apiserver calls on butler-server's SA. Pass the real user's identity via a Butler annotation (`butler.butlerlabs.dev/requesting-user`). Admission webhook reads the annotation when UserInfo.Username matches the server SA.

**Rejected.** Annotations on the incoming resource are user-controllable. A kubectl-direct caller who can reach the apiserver as butler-server's SA (unlikely but possible via misconfiguration) could set the annotation to any email. ADR-009's creator-email spoof finding (round 3 finding 2) already established that user-controlled annotations cannot be trusted for identity; re-introducing the same pattern at the Team-mutation layer would be regressive.

### Per-user ServiceAccounts

Extend ADR-016's device-flow pattern: for every OIDC-authenticated user, butler-server creates a dedicated SA and binds team-scoped RoleBindings. Handlers use that SA's token for outgoing calls.

**Rejected.** Dozens of operations per user session become Get-or-Create on an SA resource plus RoleBinding resource per team. The ADR-016 CLI flow tolerates this cost because a CLI login is infrequent. Console users generate continuous traffic; the amplification is unjustified. Additionally, stale SA cleanup (ADR-016 has a 30-day TTL) becomes a governance problem when every logged-in user has a long-lived SA.

### Client certificates per user

Issue a short-lived client certificate per user via cert-manager, signed by a cluster CA, with the user's email as CN. butler-server uses the cert for each outgoing call.

**Rejected.** Cert issuance latency (cert-manager roundtrip, CSR signing) blocks the request. Cert caching adds state. Revocation is awkward - CRLs aren't widely supported in K8s authentication. The benefits (stronger identity than a header) don't justify the operational weight when the existing impersonation path already gets audit-log-visible identity.

### Separate auth-proxy sidecar

Deploy an auth-proxy sidecar (e.g., oauth2-proxy) in front of the apiserver that converts OIDC tokens to impersonation headers before forwarding. butler-server sends raw OIDC tokens.

**Rejected.** Adds a network hop, another trusted component to operate and upgrade, and a policy surface that can drift from butler-server. Keeping the impersonation logic in butler-server makes the flow readable in one repo and testable against the apiserver directly.

## Consequences

### Positive

- apiserver audit log names the acting user on every butler-server-originated mutation. Forensics for any change trace to a real human.
- ADR-009's admission webhooks are effective for butler-server traffic as well as kubectl-direct traffic. Same gate fires regardless of ingress path.
- No change to the HTTP contract or session shape. Console and CLI clients continue to send `butler_session` cookie and `X-Butler-Team` header; nothing new to propagate.
- Scales linearly with request rate, not with user count. Per-request client construction is O(1) per mutation; no per-user state to manage.
- Pattern maps cleanly to any future handler that mutates webhook-gated resources. Drop in `AsUser(user)` on the client; handler body unchanged otherwise.

### Negative

- Per-request client construction costs a rest.Config deep-copy and a new dynamic client. Benchmarks required to confirm under 5ms p99 overhead; if higher, a per-session client cache becomes a follow-up.
- butler-server SA gains the `impersonate` verb, which is a privileged primitive. Compromised butler-server can act as any Butler user. The mitigation is the existing deployment model: butler-server runs in the platform namespace with admin-level access today; impersonate is not a material escalation. Security review should confirm.
- **Synthetic group threat model.** A compromised butler-server can impersonate any user AND acts with the full `butler-api-users` ClusterRole. That is a wider blast radius than any single user would have at a K8s RBAC level. Acceptable within the v1 threat model because butler-server already has wide-blast-radius access (today's server-SA RBAC spans every Butler CRD), but stating explicitly: impersonation does not tighten the blast-radius ceiling, it tightens the audit-trail floor.
- The `butler-api-users` group pattern requires operators to ship a new ClusterRoleBinding in butler-charts. Not a breaking change - charts ship together and operators upgrade as a unit.
- Non-mutating reads remain on the server SA, so apiserver audit logs attribute reads to the SA. **Per-user read attribution comes from butler-server's application audit log**, not apiserver audit. Compliance queries that need "which user viewed resource X" require correlating the application log (session.Email + request URL + timestamp) with the apiserver log (same timestamp, SA identity). If read-time apiserver-level attribution becomes required (unlikely in v1), impersonation can be extended to reads.

### Backward compatibility

- Existing butler-server deployments without the `impersonate` RBAC grant continue to work for all non-webhook-gated mutations. Webhook-gated mutations (Team, TenantCluster on team-environments-aware clusters) were already incorrect under the old model (webhook saw server SA, not user); the new model fixes them. There is no regression path - only a forward-fix.
- The butler-charts PR adding impersonate RBAC must land before butler-server rolls out with impersonation enabled. Until then, butler-server running with ADR-009 webhooks enabled and without the RBAC grant would hit `Forbidden: user "system:serviceaccount:butler-system:butler-server" cannot impersonate users`. Rollout order: charts PR first, then butler-server PR.

### Rollout sequence

Merge and deploy order matters. Deploying butler-server with impersonation enabled against a cluster whose butler-server SA lacks the `impersonate` verb produces `Forbidden: user "system:serviceaccount:butler-system:butler-server" cannot impersonate users` on every webhook-gated mutation. Reverse order = broken state.

1. **butler-charts impersonate RBAC PR merges first.** Lands the `impersonate` verb on the butler-server SA and the new `butler-api-users` ClusterRole + ClusterRoleBinding. No Chart.yaml version bump at merge time, per the release-discipline convention established in phase 1 (code on main is cheap; versioned chart releases are commitments).
2. **butler-server feat/team-environments PR merges after.** The implementation depends on the RBAC being present when the server rolls out. Until butler-charts has landed, butler-server cannot exercise the new path at runtime.
3. **Live validation on butler-beta exercises combined state.** Standard dev loop: scale in-cluster butler-server to 0, run butler-server locally against the butler-beta kubeconfig with the updated RBAC applied to the cluster, exercise the webhook-gated mutation scenarios (Team resourceLimits as non-platform-admin, env.limits as team admin, per-member cap creator-email identity).
4. **Coordinated release tags cut across affected repos after steps 5-8 complete.** The ADR-009 team-environments work and this ADR-010 work ship as a single platform increment. Chart bumps (butler-crds, butler-controller, butler-console/butler-server) land together; image tags reference images built after all PRs land on their respective mains. Operators see one atomic upgrade, not a sequence of individually-consistent-but-collectively-broken increments.

### Test harness implications

- Unit tests can set `Impersonate` on a fake rest.Config and verify the outgoing call carries the expected headers. Integration tests need envtest or a live cluster because the fake client does not propagate impersonation headers to admission webhooks (same limitation as the SAR fallback noted in ADR-009 test coverage).
- The structured 403 passthrough is testable via handler-level tests: inject a webhook-denial error at the k8s.Client boundary, assert response body shape.

## Open Questions

None blocking; implementation proceeds with the decision above. Items for follow-on tracking:

- **Per-session client cache**: if benchmarks show per-request client construction above 5ms p99, implement a cache keyed on session ID with TTL matching session lifetime. No action unless benchmarks warrant.
- **WebSocket terminal impersonation**: `/ws/terminal/*` handlers spawn shell processes that run kubectl against tenant clusters. These use tenant kubeconfigs (not the platform apiserver), so platform admission webhooks do not fire. Impersonation is not required on this path. Documented to prevent confusion when reviewers trace identity flow.
- **Backstage proxy impersonation interaction**: the existing `X-Butler-User-Email` header (middleware.go:90) overrides `session.Email` for platform admins coming through the Backstage portal. Under this ADR, that overridden email flows into `Impersonate-User`, which is the correct behavior - the audit log will show the real user even on portal-proxied requests. Confirmed in the implementation plan; no design change needed.
- **Group-based apiserver authorization**: if a future feature binds RBAC to OIDC groups, the Impersonate-Group payload will need to include them. The current fixed group keeps the ADR surface narrow and the audit logs clean. A subsequent ADR can extend if warranted.
- **Service-account mutations from CLI device flow**: `internal/auth/serviceaccount.go` creates per-user SAs for CLI authentication. Those creates use butler-server SA (correct per §"Service-account-originated calls"). Verified no conflict with this ADR.

## References

- [ADR-009: Team Environments](../../../butler-controller/docs/architecture/ADR-009-team-environments.md) - admission webhooks this ADR enables.
- [ADR-016: CLI Authentication](../../../butler-cli/docs/architecture/ADR-016-cli-authentication.md) - the per-user SA pattern we are NOT reusing, with rationale.
- `butler-server/internal/auth/middleware.go:80-131` - current session middleware; this ADR extends it with env context but does not change the impersonation decision (handled at the client level, not middleware).
- `butler-server/internal/auth/session.go` - UserSession shape; Email is the canonical field flowed into Impersonate-User.
- `butler-server/cmd/server/main.go:141-146` - current rest.Config construction; AsUser extends this with Impersonate per-call.
- `butler-server/internal/k8s/client.go:117-164` - k8s.Client struct that will gain the `AsUser` method.
- `butler-server/internal/api/handlers/teams.go` - first handler to adopt impersonation on Update.
- `butler-server/internal/api/handlers/clusters.go` - TenantCluster Create uses impersonation so the creator-email annotation identity check passes.
- Kubernetes impersonation docs: https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation
