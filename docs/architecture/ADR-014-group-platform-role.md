# ADR-014: Group-Based Platform Role Authorization

## Status

Proposed

## Date

2026-04-29

## Context

Butler determines platform-wide administrative access through a single boolean on the User CRD: `spec.isPlatformAdmin`. This field must be set manually, either through `butleradm user create --admin` or by editing the User CRD directly. SSO users created through `EnsureSSOUser()` always start with `isPlatformAdmin: false`.

Meanwhile, Butler already resolves IdP group membership for team-scoped access. When a user logs in via OIDC, their token's `groups` claim flows through `TeamResolver.resolveGroupMappings()`, which maps group identifiers to team memberships and roles via `Team.spec.access.groups[]`. This machinery handles LDAP DN, email-style, and plain-name group formats through `normalizeGroupName()` and `groupMatches()`.

Two gaps exist:

**Gap 1: Group-to-platform disconnect.** Being admin of a specific Team is not the same as being a platform admin. A user in a group like `butler-platform-admin` gets team-scoped admin on whatever teams reference that group, but cannot manage all teams, view all clusters, or access platform-wide administrative endpoints. To grant that level of access, an operator must manually patch the User CRD. This manual step is operationally fragile: access grants are disconnected from the IdP lifecycle, revocation requires the same manual step in reverse, there is no audit trail within Butler for when or why the flag was set, and the pattern does not scale.

**Gap 2: No platform viewer role.** Butler's platform authorization is binary: you are either a full platform admin or you are not. There is no way to grant someone read-only visibility across all teams and clusters without giving them full administrative control. Organizations need a role for managers, auditors, or on-call engineers who need to see everything but should not be able to mutate anything.

Butler also has a parallel kubectl-direct auth path. The `butler-cli-platform-admin` ClusterRole exists for operators who bypass butler-server and use kubectl directly. The team webhook (ADR-009) falls back to a SubjectAccessReview against this ClusterRole when no User CRD matches the caller. This path is orthogonal to the group mapping question and is not modified by this ADR.

## Options Considered

### A. IdentityProvider CRD with role-bearing group entries

Add a `platformRoleGroups` field to the IdentityProvider spec. Each entry maps an IdP group to a platform role (admin or viewer). At login, butler-server checks if any of the user's OIDC groups match and takes the highest matching role.

Pros: Groups are scoped to their IdP. Multi-IdP works naturally. Supports both admin and viewer in the same field. Consistent with Team CRD's per-IdP group matching. Minimal CRD surface.

Cons: Platform role configuration is split across IdP CRDs rather than centralized.

### B. Kubernetes-native RBAC (SubjectAccessReview at login)

Rejected. Butler manages its own auth layer. OIDC groups do not flow to the API server in Butler's model. Making SAR work would require API server OIDC integration or impersonation with group headers, coupling butler-server to cluster-level RBAC.

### C. Special "platform" team

Rejected. Overloads Team semantics. A Team is a tenancy boundary, not an authorization level.

### D. Separate GroupRoleMapping CRD

Rejected for now. Adds CRD sprawl for a problem that fits as a field on IdentityProvider. The struct-based entry (`PlatformRoleGroupEntry` with a `role` field) allows future extension without a new CRD.

### E. Cluster-level singleton config

Rejected. Decouples groups from the IdP that provides them.

## Decision

**Option A: IdentityProvider CRD `platformRoleGroups` field with session-level evaluation.**

### Platform role model

Replace the single `IsPlatformAdmin bool` concept with a two-level platform role:

| Role | Grants |
|---|---|
| `admin` | Full platform access. Manage all teams, clusters, users, settings. Equivalent to current `isPlatformAdmin: true`. |
| `viewer` | Read-only platform access. View all teams, clusters, certificates, members, audit logs. Cannot mutate resources, access management terminal, rotate certificates, or modify infrastructure. |

**No role** (the default) means the user has only their team-scoped permissions.

**Implication relationships:**
- Platform admin implies platform viewer (an admin can do everything a viewer can).
- Platform admin implies team admin on every team (preserves current behavior where platform admins get synthetic admin membership).
- Platform viewer implies team viewer on every team (viewer gets synthetic viewer membership for any team they are not explicitly a member of).
- Platform viewer does NOT imply team operator or team admin. If a platform viewer also has an explicit team membership with a higher role (e.g., operator on team-alpha), the higher role wins for that team. This matches the additive-only inheritance pattern from ADR-009.
- Team-scoped roles are unchanged. This ADR adds platform-scoped roles only.

**Precedence:** Explicit team-scoped grants (`Team.spec.access`) take precedence over synthetic platform-derived grants. A platform viewer with an explicit team operator role on team-alpha has operator on team-alpha (explicit grant) and synthetic viewer on all other teams (platform role). Synthetic memberships never reduce explicit grants. This is additive-only, matching ADR-009.

### Effective platform role computation

The effective platform role at session creation is:

```
effectivePlatformRole = max(
    User.spec.platformRole,                         // manual CRD override
    highestMatchingRole(userGroups, idp.platformRoleGroups)  // IdP group match
)
```

Where `max` uses the hierarchy: admin > viewer > (none).

For backwards compatibility, `User.spec.isPlatformAdmin: true` is treated as `platformRole: admin`.

### Why session-level, not CRD mutation

If butler-server wrote the role to the User CRD on login, it would need a reconciliation mechanism to revoke it when the user is removed from the group. Session-level evaluation sidesteps this: remove a user from the IdP group, and their next login produces a session without the platform role. This matches Butler's existing behavior for team membership.

### API surface

**IdentityProvider CRD (additive, backwards compatible):**

```go
type IdentityProviderSpec struct {
    Type             IdentityProviderType      `json:"type"`
    DisplayName      string                    `json:"displayName,omitempty"`
    OIDC             *OIDCConfig               `json:"oidc,omitempty"`

    // PlatformRoleGroups maps IdP groups to platform-wide roles.
    // Group names are matched using the same normalization as
    // Team.spec.access.groups (LDAP DN, email-style, and plain
    // names are all supported). When a user belongs to multiple
    // matching groups, the highest role wins.
    // +optional
    PlatformRoleGroups []PlatformRoleGroupEntry `json:"platformRoleGroups,omitempty"`
}

// PlatformRoleGroupEntry maps an IdP group to a platform-wide role.
type PlatformRoleGroupEntry struct {
    // Name is the group identifier as it appears in the OIDC token's
    // groups claim.
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:MinLength=1
    Name string `json:"name"`

    // Role is the platform role to grant members of this group.
    // +kubebuilder:validation:Required
    // +kubebuilder:validation:Enum=admin;viewer
    Role string `json:"role"`
}
```

`platformRoleGroups` sits at the IdentityProvider spec level, not nested under `oidc`, because the concept applies to the IdP as a whole.

**Example (Entra):**

```yaml
apiVersion: butler.butlerlabs.dev/v1alpha1
kind: IdentityProvider
metadata:
  name: microsoft-entra
spec:
  type: oidc
  displayName: Microsoft
  oidc:
    issuerURL: https://login.microsoftonline.com/3e20ecb2-.../v2.0
    clientID: "..."
    clientSecretRef:
      name: entra-oidc
      namespace: butler-system
      key: client-secret
    groupsClaim: groups
    emailClaim: email
  platformRoleGroups:
    - name: butler-platform-admin
      role: admin
    - name: butler-platform-viewers
      role: viewer
```

**Example (Google Workspace):**

```yaml
apiVersion: butler.butlerlabs.dev/v1alpha1
kind: IdentityProvider
metadata:
  name: google-workspace
spec:
  type: oidc
  displayName: Google
  oidc:
    issuerURL: https://accounts.google.com
    clientID: "..."
    clientSecretRef:
      name: google-oidc
      namespace: butler-system
      key: client-secret
    googleWorkspace:
      adminEmail: admin@example.com
      serviceAccountKeyRef:
        name: google-sa
        namespace: butler-system
        key: credentials.json
  platformRoleGroups:
    - name: butler-admins@example.com
      role: admin
    - name: butler-readers@example.com
      role: viewer
```

**User CRD change (backwards compatible):**

```go
type UserSpec struct {
    // ... existing fields ...

    // IsPlatformAdmin is DEPRECATED but still honored for backwards
    // compatibility. When true, treated as PlatformRole: "admin".
    // New deployments should use PlatformRole instead.
    // +optional
    IsPlatformAdmin bool `json:"isPlatformAdmin,omitempty"`

    // PlatformRole is the manually-assigned platform-wide role.
    // Takes precedence over (and is additive with) group-based
    // role resolution. Valid values: "admin", "viewer", or ""
    // (empty, meaning no platform role).
    // +optional
    // +kubebuilder:validation:Enum=admin;viewer;""
    PlatformRole string `json:"platformRole,omitempty"`
}
```

Effective CRD role = `max(PlatformRole, isPlatformAdmin ? "admin" : "")`. Existing CRDs with `isPlatformAdmin: true` continue to work without migration.

**No changes to Team CRD.** Team group mapping and team-scoped roles are unaffected.

### Session model changes

**UserSession struct:**

```go
type UserSession struct {
    // ... existing fields ...

    // IsPlatformAdmin is DEPRECATED in the struct but kept for
    // JSON serialization backwards compatibility with existing
    // JWTs and API responses. Computed from PlatformRole.
    IsPlatformAdmin bool `json:"isPlatformAdmin,omitempty"`

    // PlatformRole is the effective platform-wide role.
    // "admin", "viewer", or "" (no platform role).
    PlatformRole string `json:"platformRole,omitempty"`
}
```

`IsPlatformAdmin` becomes a computed field: `IsPlatformAdmin = (PlatformRole == "admin")`. This preserves backwards compatibility for:
- Existing JWT tokens (old tokens without `platformRole` still work via `isPlatformAdmin`)
- API responses consumed by butler-console (which checks `isPlatformAdmin`)
- WebSocket `SessionInfo` (which checks `isPlatformAdmin`)

New code should check `PlatformRole` instead of `IsPlatformAdmin`.

### Session helper changes

Add two new helpers and modify existing ones:

```go
// IsPlatformViewer returns true if the user has platform viewer or
// higher privileges.
func (u *UserSession) IsPlatformViewer() bool {
    return u.PlatformRole == RoleAdmin || u.PlatformRole == RoleViewer
}

// HasPlatformRole returns true if the user has any platform-wide role.
func (u *UserSession) HasPlatformRole() bool {
    return u.PlatformRole != ""
}
```

Existing helpers change behavior for viewers:

- `GetTeamMembership()`: Platform viewer gets synthetic **viewer** membership (not admin).
- `HasRole(role)`: Platform viewer returns true only for `viewer` role.
- `HasRoleInTeam(team, role)`: Platform viewer returns true only for `viewer` role.
- `IsAdmin()`: Platform viewer returns **false** (not an admin).
- `CanOperateTeam()`: Platform viewer returns **false** (read-only).
- `CanViewTeam()`: Platform viewer returns **true** (can view all teams).

### Viewer permissions and restrictions

Based on the call-site survey (see appendix):

**Viewer CAN:**
- View all clusters across all teams (`clusters.go` List, Get)
- View certificate status for any cluster (`certificates.go` checkClusterAccess)
- View team member lists (`teams.go` ListMembers)
- View audit log entries across all teams (`audit.go` ListAll, ListTeam)
- Receive team-scoped WebSocket notifications (via synthetic team membership)
- Access `/api/auth/me`, `/api/auth/teams`, `/api/auth/refresh-permissions`

**Viewer CANNOT:**
- Access management cluster terminal (`websocket/auth.go` requirePlatformAdmin)
- Create, update, delete, or scale clusters
- Apply infrastructure overrides (`clusters.go:680`)
- Rotate certificates or CAs (`certificates.go` canRotateCertificates, canRotateCA)
- Impersonate other users via `X-Butler-User-Email`
- Access routes behind `RequirePlatformAdmin()` middleware
- Receive team-less or security-scoped notifications (same as regular users)

### Middleware changes

`RequirePlatformAdmin()` remains unchanged. It gates admin-only operations.

Add `RequirePlatformViewer()` for routes that should allow both admin and viewer:

```go
func RequirePlatformViewer() func(http.Handler) http.Handler {
    // Allows PlatformRole == "admin" or PlatformRole == "viewer"
}
```

The `SessionMiddleware` fast path (line 87) needs adjustment: platform viewers should still go through team re-resolution (they have synthetic viewer membership, but the re-resolution path applies the selected team context). Only platform admins skip team re-resolution.

### Implementation in butler-server

**1. Load platform role groups with IdP configuration.**

butler-server already reads IdentityProvider CRDs to configure OIDC providers. When loading an IdP, also load its `platformRoleGroups` list. No new watch or informer needed.

**2. Add role resolution helper.**

In `internal/auth/platform_role.go` (new file, ~30 lines):

```go
func ResolvePlatformRole(
    userGroups []string,
    platformRoleGroups []PlatformRoleGroupEntry,
) string {
    groupSet := buildGroupLookupSet(userGroups)
    highest := ""
    for _, prg := range platformRoleGroups {
        if groupMatches(prg.Name, groupSet) {
            highest = HighestRole([]string{highest, prg.Role})
        }
    }
    return highest
}
```

Reuses `buildGroupLookupSet()`, `groupMatches()`, and `HighestRole()` from existing code.

**3. Compute effective platform role in OIDC callback.**

In `auth_oidc.go`, after extracting OIDC claims and calling `EnsureSSOUser()`:

```go
crdRole := user.PlatformRole
if crdRole == "" && user.IsPlatformAdmin {
    crdRole = auth.RoleAdmin  // backwards compat
}
groupRole := auth.ResolvePlatformRole(claims.Groups, idpConfig.PlatformRoleGroups)
effectiveRole := auth.HighestRole([]string{crdRole, groupRole})
```

Set both `PlatformRole` and `IsPlatformAdmin` on the session for backwards compatibility.

**4. Update session helpers.**

Modify the ~12 session helper methods to check `PlatformRole` instead of `IsPlatformAdmin`. The change pattern is consistent:

```go
// Before:
if u.IsPlatformAdmin { return true }

// After (for admin-only helpers like IsAdmin, CanOperateTeam):
if u.PlatformRole == RoleAdmin { return true }

// After (for view-level helpers like CanViewTeam, HasTeamMembership):
if u.PlatformRole == RoleAdmin || u.PlatformRole == RoleViewer { return true }
```

`GetTeamMembership()` requires a role-aware synthetic membership:

```go
if u.PlatformRole == RoleAdmin {
    return &TeamMembership{Name: teamName, Role: RoleAdmin}
}
if u.PlatformRole == RoleViewer {
    return &TeamMembership{Name: teamName, Role: RoleViewer}
}
```

**5. Update middleware fast path.**

In `SessionMiddleware`, the platform admin fast path (line 87) stays admin-only. Platform viewers go through the normal team re-resolution path but skip the "no team access" rejection (since they have implicit viewer access to all teams).

**6. Update WebSocket session info.**

`SessionInfo` in `websocket/hub.go` gains a `PlatformRole` field. `clientCanReceive()` treats platform viewers the same as regular users with team membership (they see notifications for all teams but not team-less notifications).

**7. Extend refresh-permissions.**

The `/api/auth/refresh-permissions` endpoint already re-queries the User CRD. Extend it to also re-evaluate group membership against the IdP's `platformRoleGroups`. Compute effective role using the same `max(crdRole, groupRole)` logic.

**8. Update API response serialization.**

`UserResponse` gains `PlatformRole string` alongside the existing `IsPlatformAdmin bool`. Both are populated for backwards compatibility. butler-console will eventually migrate to checking `platformRole` instead of `isPlatformAdmin`.

### Scope

**In scope:**
- IdentityProvider CRD schema change (`platformRoleGroups` field)
- User CRD schema change (`platformRole` field, `isPlatformAdmin` deprecated but honored)
- butler-server session model (`PlatformRole` field)
- butler-server session helpers (~12 methods)
- butler-server OIDC callback and refresh-permissions
- butler-server middleware (SessionMiddleware viewer path, new RequirePlatformViewer)
- WebSocket session info and notification filtering
- API response backwards compatibility
- CRD regeneration and helm chart bumps
- Unit tests

**Out of scope:**
- Tenant cluster RBAC propagation (separate feature, separate ADR)
- kubectl-direct path changes (the `butler-cli-platform-admin` ClusterRole is unaffected)
- SAML, SCIM, or auth protocols beyond OIDC
- Audit log entry redaction for viewers (follow-up)
- butler-console UI changes for IdentityProvider form or role display (butlerdotdev/butler-console#56)
- butler-cli viewer support (butlerdotdev/butler-cli#37)
- Platform operator role (admin > operator > viewer): if needed, add to the enum later

### Migration

- **CRD schema:** `platformRoleGroups` is optional and defaults to empty. `platformRole` on User CRD is optional and defaults to empty. Existing CRDs are valid without these fields.
- **`isPlatformAdmin: true` users:** Honored through the deprecation period. Treated as `platformRole: admin` internally. No immediate migration required.
- **`isPlatformAdmin` deprecation timeline:** The `isPlatformAdmin` field on User CRD and in API responses will be removed in the first major version bump (v1.0.0) after butler-console and butler-cli have fully migrated to reading `platformRole`. Migration tracked in butlerdotdev/butler-console#56, butlerdotdev/butler-cli#37, and butlerdotdev/butler-server#56. The field is marked deprecated in CRD descriptions starting with this release.
- **Existing JWTs:** Old tokens carry `isPlatformAdmin: true` but no `platformRole`. Session validation detects this and sets `PlatformRole: "admin"` internally.
- **API responses:** Both `isPlatformAdmin` and `platformRole` are returned. Consumers can migrate at their own pace.
- **New deployments:** Can use `platformRoleGroups` and `platformRole` immediately.

## Consequences

**Positive:**
- Platform roles can be managed through IdP group membership. No CRD edits needed for routine access changes.
- Least-privilege: viewers can observe the full platform without mutation capability.
- Audit trail improves via IdP group membership logs.
- Minimal API surface. Two fields across two existing CRDs, no new CRDs or controllers.
- Break-glass override preserved via User CRD fields.
- Full backwards compatibility: `isPlatformAdmin: true` continues to work everywhere.

**Negative:**
- Access revocation has login-time granularity (same as team membership).
- Platform role configuration is per-IdP (correct scoping for multi-IdP, but adds config for operators wanting the same groups across all IdPs).
- The two auth paths (butler-server and kubectl-direct) remain separate.
- Session helper changes touch ~12 methods, increasing the risk surface of this change. Thorough unit tests are required.
- `isPlatformAdmin` deprecation creates a transitional period where both fields coexist.

## Related ADRs

- **ADR-009 (Team Environments):** Introduced the team webhook's dual-path platform admin detection and additive-only role inheritance. This ADR extends the additive-only pattern to platform roles: platform viewer never reduces an explicit team membership.
- **ADR-010 (Impersonation Auth):** Established butler-server's impersonation model. Platform role flows through to webhook decisions via impersonation. The `X-Butler-User-Email` impersonation header remains admin-only.
- **ADR-013 (WebSocket Authentication):** Uses `session.IsPlatformAdmin` to gate management terminal. This remains admin-only; platform viewers cannot access the management terminal.

## Appendix: Call-site survey

Every location in butler-server that checks platform admin status, categorized by whether a platform viewer should also pass.

### Admin-only (viewer must NOT pass)

| Location | Check | Purpose |
|---|---|---|
| `middleware.go:297-314` | `RequirePlatformAdmin()` | Binary middleware gate for admin-only routes |
| `middleware.go:87-141` | `user.IsPlatformAdmin` | SessionMiddleware fast path: skips team re-resolution, enables impersonation |
| `websocket/auth.go:60-76` | `requirePlatformAdmin()` | Gates management cluster terminal WebSocket upgrade |
| `websocket/hub.go:536` | `requirePlatformAdmin()` | HandleManagementTerminal |
| `clusters.go:678-683` | `user.IsPlatformAdmin` | InfrastructureOverride on cluster update |
| `certificates.go:350-365` | `canRotateCA()` | CA certificate rotation |
| `auth_oidc.go:585` | `IsPlatformAdmin: true` | Legacy admin session creation |
| `auth_device.go:336` | `session.IsPlatformAdmin` | EnsureRoleBindings for CLI service account |

### Read-only (viewer SHOULD pass)

| Location | Check | Purpose |
|---|---|---|
| `clusters.go:80,115,166` | `user.IsAdmin()` | View clusters across all teams |
| `certificates.go:301-327` | `checkClusterAccess()` | View certificate status for any cluster |
| `teams.go:540` | `HasTeamMembership \|\| IsPlatformAdmin` | View team member list |
| `audit.go:40-45` | `user.IsPlatformAdmin` | View audit entries across all teams |
| `audit.go:68` | `IsPlatformAdmin \|\| IsAdminOfTeam()` | View audit entries for a specific team |

### Session helpers (need platform role awareness)

| Method | Line | Admin behavior | Viewer behavior |
|---|---|---|---|
| `HasTeamMembership()` | 181 | Implicit membership in all teams | Same |
| `GetTeamMembership()` | 195 | Synthetic admin membership | Synthetic viewer membership |
| `HasRole()` | 211 | Has all roles | Has viewer role only |
| `HasRoleInTeam()` | 225 | Admin in all teams | Viewer in all teams |
| `IsAdmin()` | 242 | true | false |
| `IsAdminOfTeam()` | 250 | true | false |
| `CanOperateTeam()` | 259 | true | false |
| `CanViewTeam()` | 274 | true | true |
| `CanOperateInSelectedTeam()` | 285 | true (no team) | false |
| `CanViewInSelectedTeam()` | 297 | true | true |
| `CanOperateInSelectedEnvironment()` | 323 | true | false |
| `CanViewInSelectedEnvironment()` | 336 | true | true |

### Data filtering

| Location | Check | Admin behavior | Viewer behavior |
|---|---|---|---|
| `websocket/hub.go:251-256` | `clientCanReceive()` | Receives all notifications | Team-scoped notifications only |
