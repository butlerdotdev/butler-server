# Butler Server

Go HTTP/WebSocket API server backing butler-console and butler-cli.

| Field | Value |
|---|---|
| Go module | `github.com/butlerdotdev/butler-server` |
| Go version | 1.24.6 |
| Entry point | `cmd/server/main.go` |
| Framework | chi/v5 router |
| Auth | JWT sessions (HS256) + OIDC (Google, Microsoft, Okta) + internal users |
| K8s access | dynamic client + typed clientset via `internal/k8s.Client` |
| WebSocket | gorilla/websocket for cluster watch + terminal PTY sessions |

## Directory Structure

```
butler-server/
├── cmd/server/
│   └── main.go                          # Entry point: flags, K8s client init, graceful shutdown
├── internal/
│   ├── api/
│   │   ├── router.go                    # Chi router: all routes, middleware chain, handler wiring
│   │   └── handlers/
│   │       ├── auth_oidc.go             # SSO login/callback, internal login, session refresh, /me
│   │       ├── clusters.go              # TenantCluster CRUD, scale, kubeconfig, management cluster info
│   │       ├── addons.go                # Addon catalog, tenant addons, management addons
│   │       ├── teams.go                 # Team CRUD, members, group sync
│   │       ├── users.go                 # User CRUD, invite flow, disable/enable, SSH keys
│   │       ├── providers.go             # ProviderConfig CRUD, test connection, list images/networks
│   │       ├── identity_providers.go    # IdentityProvider CRUD, OIDC discovery validation
│   │       ├── certificates.go          # Cert status, rotation (all/kubeconfigs/ca)
│   │       ├── gitops.go               # GitOps config, FluxCD bootstrap, Helm release discovery, export
│   │       ├── networks.go             # NetworkPool/IPAllocation CRUD
│   │       ├── workspaces.go           # Workspace CRUD, connect/disconnect, services, templates, images
│   │       └── helpers.go              # writeJSON, writeError, MapAddonStatus
│   ├── auth/
│   │   ├── middleware.go               # SessionMiddleware, RequireAdmin, RequirePlatformAdmin, ClusterTeamAuthz
│   │   ├── session.go                  # UserSession, SessionClaims, JWT create/validate/refresh, role helpers
│   │   ├── oidc.go                     # OIDC provider discovery + token exchange
│   │   ├── google_groups.go            # Google Admin SDK group membership sync
│   │   ├── teams.go                    # TeamResolver: resolves email/groups to team memberships from Team CRDs
│   │   ├── users.go                    # UserService: User CRD operations (get by email, check disabled)
│   │   └── errors.go                   # Sentinel errors: ErrInvalidToken, ErrExpiredToken
│   ├── config/
│   │   └── config.go                   # Environment-based config (BUTLER_* vars), OIDC presets
│   ├── k8s/
│   │   └── client.go                   # K8s client: dynamic + typed, GVR constants, CRD helpers
│   └── websocket/
│       ├── hub.go                      # WebSocket hub: client registry, K8s watch broadcast
│       └── terminal.go                 # Terminal session: PTY creation, bidirectional WS<->shell streaming
├── Makefile                            # build, test, lint, docker-build, deploy targets
├── Dockerfile                          # Multi-stage build (requires butler-api as build context)
└── .github/workflows/
    └── ci.yml                          # Build, multi-arch image push to GHCR, release, docs notify
```

## HTTP Routes

### Public Routes (no auth)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/healthz` | inline | Liveness probe |
| GET | `/readyz` | inline | Readiness probe (K8s API check) |

### Auth Routes (`/api/auth`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/auth/providers` | AuthHandler.GetProviders | List configured identity providers |
| POST | `/api/auth/login` | AuthHandler.Login | SSO redirect (builds OIDC auth URL) |
| POST | `/api/auth/login/internal` | AuthHandler.InternalUserLogin | Internal user email/password login |
| POST | `/api/auth/login/legacy` | AuthHandler.LegacyLogin | Legacy admin login |
| POST | `/api/auth/callback` | AuthHandler.Callback | OIDC code exchange, session creation |
| POST | `/api/auth/logout` | AuthHandler.Logout | Clear session cookie |

### Protected Auth Routes (`/api/auth`, requires session)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| POST | `/api/auth/refresh` | AuthHandler.Refresh | Refresh JWT session |
| POST | `/api/auth/refresh-permissions` | AuthHandler.RefreshPermissions | Re-resolve teams/roles |
| GET | `/api/auth/me` | AuthHandler.Me | Current user info |
| GET | `/api/auth/teams` | AuthHandler.Teams | User's team memberships |

### User Invite Routes (public, token-validated)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/users/invite/{token}/validate` | UserHandler.ValidateInvite | Validate invite token |
| POST | `/api/users/invite/{token}/set-password` | UserHandler.SetPassword | Set password via invite |

### Management Cluster (`/api/management`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/management/cluster` | ClusterHandler.GetManagement | Management cluster info |
| GET | `/api/management/cluster/nodes` | ClusterHandler.GetManagementNodes | Management node list |
| GET | `/api/management/cluster/pods` | ClusterHandler.GetManagementPods | Management pod list |

### Management Addons (`/api/management/addons`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/management/addons` | AddonsHandler.ListManagementAddons | List management addons |
| POST | `/api/management/addons` | AddonsHandler.InstallManagementAddon | Install management addon |
| GET | `/api/management/addons/{name}` | AddonsHandler.GetManagementAddon | Get management addon |
| PUT | `/api/management/addons/{name}` | AddonsHandler.UpdateManagementAddon | Update management addon |
| DELETE | `/api/management/addons/{name}` | AddonsHandler.UninstallManagementAddon | Uninstall management addon |

### Management GitOps (`/api/management/gitops`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/management/gitops/status` | GitOpsHandler.GetManagementStatus | Management GitOps status |
| POST | `/api/management/gitops/enable` | GitOpsHandler.EnableManagementGitOps | Bootstrap Flux on mgmt |
| POST | `/api/management/gitops/disable` | GitOpsHandler.DisableManagementGitOps | Remove Flux from mgmt |
| GET | `/api/management/gitops/releases` | GitOpsHandler.DiscoverManagementReleases | Discover Helm releases |
| POST | `/api/management/gitops/export/{name}` | GitOpsHandler.ExportManagementAddon | Export addon to Git |
| POST | `/api/management/gitops/export-catalog/{name}` | GitOpsHandler.ExportManagementCatalogAddon | Export catalog addon |
| POST | `/api/management/gitops/export-all` | GitOpsHandler.ExportAllManagementAddons | Export all mgmt addons |

### Addon Catalog (`/api/addons`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/addons/catalog` | AddonsHandler.GetCatalog | List AddonDefinitions |
| GET | `/api/addons/catalog/{name}` | AddonsHandler.GetAddonDefinition | Get single AddonDefinition |

### Tenant Clusters (`/api/clusters`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/clusters` | ClusterHandler.List | List clusters (team-scoped) |
| POST | `/api/clusters` | ClusterHandler.Create | Create cluster |
| GET | `/api/clusters/{namespace}/{name}` | ClusterHandler.Get | Get cluster details |
| DELETE | `/api/clusters/{namespace}/{name}` | ClusterHandler.Delete | Delete cluster |
| PUT | `/api/clusters/{namespace}/{name}/scale` | ClusterHandler.Scale | Scale worker count |
| PUT | `/api/clusters/{namespace}/{name}/workspaces` | ClusterHandler.ToggleWorkspaces | Toggle workspace feature |
| GET | `/api/clusters/{namespace}/{name}/kubeconfig` | ClusterHandler.GetKubeconfig | Download kubeconfig |
| GET | `/api/clusters/{namespace}/{name}/nodes` | ClusterHandler.GetNodes | List tenant nodes |
| GET | `/api/clusters/{namespace}/{name}/events` | ClusterHandler.GetEvents | List cluster events |

### Cluster Addons (`/api/clusters/{namespace}/{name}/addons`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `.../addons` | AddonsHandler.ListClusterAddons | List installed addons |
| POST | `.../addons` | AddonsHandler.InstallAddon | Install addon |
| PUT | `.../addons/{addonName}` | AddonsHandler.UpdateAddonValues | Update addon values |
| DELETE | `.../addons/{addonName}` | AddonsHandler.UninstallAddon | Uninstall addon |

### GitOps Config (`/api/gitops`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/gitops/config` | GitOpsHandler.GetConfig | Get GitOps configuration |
| POST | `/api/gitops/config` | GitOpsHandler.SaveConfig | Save GitOps configuration |
| GET | `/api/gitops/repositories` | GitOpsHandler.ListRepositories | List GitHub repos |
| GET | `/api/gitops/branches` | GitOpsHandler.ListBranches | List repo branches |
| POST | `/api/gitops/preview` | GitOpsHandler.PreviewManifest | Preview generated manifests |

### Cluster GitOps (`/api/clusters/{namespace}/{name}/gitops`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| POST | `.../gitops/enable` | GitOpsHandler.EnableGitOps | Bootstrap Flux on tenant |
| GET | `.../gitops/status` | GitOpsHandler.GetStatus | Flux sync status |
| POST | `.../gitops/disable` | GitOpsHandler.DisableGitOps | Remove Flux from tenant |
| GET | `.../gitops/releases` | GitOpsHandler.DiscoverReleases | Discover Helm releases |
| POST | `.../gitops/export/{addonName}` | GitOpsHandler.ExportAddon | Export addon to Git |
| POST | `.../gitops/export-release/{releaseName}` | GitOpsHandler.ExportRelease | Export Helm release |
| POST | `.../gitops/export-all` | GitOpsHandler.ExportAllAddons | Export all addons |

### Cluster Certificates (`/api/clusters/{namespace}/{name}/certificates`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `.../certificates` | CertificateHandler.GetCertificates | List all certificates |
| GET | `.../certificates/category/{category}` | CertificateHandler.GetCertificatesByCategory | Certs by category |
| POST | `.../certificates/rotate` | CertificateHandler.RotateCertificates | Trigger rotation |
| GET | `.../certificates/rotate/status` | CertificateHandler.GetRotationStatus | Rotation progress |

### Workspaces (`/api/clusters/{namespace}/{name}/workspaces`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `.../workspaces` | WorkspaceHandler.List | List workspaces |
| POST | `.../workspaces` | WorkspaceHandler.Create | Create workspace |
| GET | `.../workspaces/{workspaceName}` | WorkspaceHandler.Get | Get workspace |
| DELETE | `.../workspaces/{workspaceName}` | WorkspaceHandler.Delete | Delete workspace |
| POST | `.../workspaces/{workspaceName}/connect` | WorkspaceHandler.Connect | Mark connected |
| POST | `.../workspaces/{workspaceName}/disconnect` | WorkspaceHandler.Disconnect | Mark disconnected |
| POST | `.../workspaces/{workspaceName}/start` | WorkspaceHandler.StartWorkspace | Start stopped workspace |
| GET | `.../workspaces/{workspaceName}/metrics` | WorkspaceHandler.GetMetrics | Resource metrics |
| POST | `.../workspaces/{workspaceName}/sync-ssh-keys` | WorkspaceHandler.SyncSSHKeys | Sync SSH keys to pod |

### Cluster Services (`/api/clusters/{namespace}/{name}/services`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `.../services` | WorkspaceHandler.ListServices | List K8s services |
| GET | `.../services/mirrord-config` | WorkspaceHandler.GenerateMirrordConfig | Generate mirrord config |

### Workspace Images and Templates

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/workspace-images` | WorkspaceHandler.ListImages | Static image catalog |
| GET | `/api/clusters/{ns}/{name}/workspace-templates` | WorkspaceHandler.ListTemplates | List templates |
| POST | `/api/clusters/{ns}/{name}/workspace-templates` | WorkspaceHandler.CreateTemplate | Create template |
| PUT | `/api/clusters/{ns}/{name}/workspace-templates/{tmpl}` | WorkspaceHandler.UpdateTemplate | Update template |
| DELETE | `/api/clusters/{ns}/{name}/workspace-templates/{tmpl}` | WorkspaceHandler.DeleteTemplate | Delete template |

### SSH Keys (`/api/ssh-keys`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/ssh-keys` | UserHandler.ListSSHKeys | List current user's keys |
| POST | `/api/ssh-keys` | UserHandler.AddSSHKey | Add SSH key |
| DELETE | `/api/ssh-keys/{fingerprint}` | UserHandler.RemoveSSHKey | Remove SSH key |

### Providers (`/api/providers`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/providers` | ProvidersHandler.List | List all ProviderConfigs |
| POST | `/api/providers` | ProvidersHandler.Create | Create ProviderConfig |
| GET | `/api/providers/{namespace}/{name}` | ProvidersHandler.Get | Get ProviderConfig |
| DELETE | `/api/providers/{namespace}/{name}` | ProvidersHandler.Delete | Delete ProviderConfig |
| POST | `/api/providers/{namespace}/{name}/test` | ProvidersHandler.TestConnection | Test provider connection |
| POST | `/api/providers/validate` | ProvidersHandler.Validate | Validate provider config |
| GET | `/api/providers/{namespace}/{name}/images` | ProvidersHandler.ListImages | List VM images |
| GET | `/api/providers/{namespace}/{name}/networks` | ProvidersHandler.ListNetworks | List available networks |

### Teams (`/api/teams`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/teams` | TeamHandler.List | List teams (user's teams) |
| POST | `/api/teams` | TeamHandler.Create | Create team |
| GET | `/api/teams/{name}` | TeamHandler.Get | Get team |
| PUT | `/api/teams/{name}` | TeamHandler.Update | Update team |
| DELETE | `/api/teams/{name}` | TeamHandler.Delete | Delete team |
| GET | `/api/teams/{name}/clusters` | TeamHandler.ListClusters | List team's clusters |
| GET | `/api/teams/{name}/members` | TeamHandler.ListMembers | List team members |
| POST | `/api/teams/{name}/members` | TeamHandler.AddMember | Add member (admin) |
| PUT | `/api/teams/{name}/members/{email}` | TeamHandler.UpdateMemberRole | Update role (admin) |
| DELETE | `/api/teams/{name}/members/{email}` | TeamHandler.RemoveMember | Remove member (admin) |
| POST | `/api/teams/{name}/groups` | TeamHandler.AddGroupSync | Add group sync (admin) |
| PUT | `/api/teams/{name}/groups/{group}` | TeamHandler.UpdateGroupSyncRole | Update group role (admin) |
| DELETE | `/api/teams/{name}/groups/{group}` | TeamHandler.RemoveGroupSync | Remove group sync (admin) |

### Team Providers (`/api/teams/{name}/providers`)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/teams/{name}/providers` | ProvidersHandler.ListTeamProviders | List team providers |
| POST | `/api/teams/{name}/providers` | ProvidersHandler.CreateTeamProvider | Assign provider to team |
| DELETE | `/api/teams/{name}/providers/{provider}` | ProvidersHandler.DeleteTeamProvider | Remove provider from team |

### Admin Routes (`/api/admin`, requires admin role)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/admin/users` | UserHandler.ListUsers | List all users |
| POST | `/api/admin/users` | UserHandler.CreateUser | Create user |
| GET | `/api/admin/users/{name}` | UserHandler.GetUser | Get user |
| DELETE | `/api/admin/users/{name}` | UserHandler.DeleteUser | Delete user |
| POST | `/api/admin/users/{name}/disable` | UserHandler.DisableUser | Disable user |
| POST | `/api/admin/users/{name}/enable` | UserHandler.EnableUser | Enable user |
| POST | `/api/admin/users/{name}/regenerate-invite` | UserHandler.RegenerateInvite | Regenerate invite |
| GET | `/api/admin/teams` | TeamHandler.List | List all teams (admin view) |
| GET | `/api/admin/identity-providers` | IdentityProvidersHandler.List | List IdPs |
| POST | `/api/admin/identity-providers` | IdentityProvidersHandler.Create | Create IdP |
| GET | `/api/admin/identity-providers/{name}` | IdentityProvidersHandler.Get | Get IdP |
| DELETE | `/api/admin/identity-providers/{name}` | IdentityProvidersHandler.Delete | Delete IdP |
| POST | `/api/admin/identity-providers/test-discovery` | IdentityProvidersHandler.TestDiscovery | Test OIDC discovery |
| POST | `/api/admin/identity-providers/validate` | IdentityProvidersHandler.Validate | Validate IdP config |

### Admin Network Routes (`/api/admin/networks`, requires platform admin)

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/api/admin/networks/pools` | NetworksHandler.ListNetworkPools | List all pools |
| POST | `/api/admin/networks/pools` | NetworksHandler.CreateNetworkPool | Create pool |
| GET | `/api/admin/networks/pools/{namespace}/{name}` | NetworksHandler.GetNetworkPool | Get pool |
| DELETE | `/api/admin/networks/pools/{namespace}/{name}` | NetworksHandler.DeleteNetworkPool | Delete pool |
| GET | `/api/admin/networks/allocations` | NetworksHandler.ListAllAllocations | All allocations |
| GET | `/api/admin/networks/pools/{namespace}/{name}/allocations` | NetworksHandler.ListAllocations | Pool allocations |
| DELETE | `/api/admin/networks/allocations/{namespace}/{name}` | NetworksHandler.ReleaseAllocation | Release allocation |

### WebSocket Routes (`/ws`, auth handled per-connection)

| Path | Handler | Purpose |
|---|---|---|
| `/ws/clusters` | Hub.HandleClusterWatch | Real-time TenantCluster updates via K8s watch |
| `/ws/terminal/{namespace}/{name}` | Hub.HandleTerminal | PTY terminal to tenant cluster |
| `/ws/terminal/management` | Hub.HandleManagementTerminal | PTY terminal to management cluster |

### Static SPA Catch-All

| Method | Path | Handler | Purpose |
|---|---|---|---|
| GET | `/*` | spaHandler | Serves embedded frontend files, falls back to index.html |

## Router and Middleware Chain

The router is assembled in `internal/api/router.go`. Global middleware runs on every request:

```
RequestID -> RealIP -> LoggingMiddleware -> Recoverer -> [CORS in dev mode]
```

Protected routes additionally run through `SessionMiddleware`, which:
1. Extracts JWT from `butler_session` cookie or `Authorization: Bearer` header
2. Validates the JWT signature (HS256) and expiry
3. Checks if user is disabled (via User CRD lookup)
4. Re-resolves team memberships on every request (ensures removal takes effect immediately)
5. Reads `X-Butler-Team` header and sets `SelectedTeam` + `SelectedTeamRole` on the session
6. For platform admins: trusts `X-Butler-User-Email` header for Backstage proxy impersonation

Admin routes layer `RequireAdmin()` middleware. Network routes layer `RequirePlatformAdmin()`.

WebSocket routes skip the standard auth middleware and authenticate per-connection inside the handler.

## Authentication Flow

### SSO/OIDC Login
1. Console calls `POST /api/auth/login` with `{provider, redirectUrl}`
2. Server builds OIDC auth URL with state parameter, returns it
3. Browser redirects to IdP (Google, Microsoft, Okta)
4. IdP redirects back to console callback page
5. Console calls `POST /api/auth/callback` with `{code, state, provider}`
6. Server exchanges code for tokens, extracts claims (email, name, picture, groups)
7. For Google: groups fetched via Admin SDK (not in OIDC token)
8. Server resolves teams from email + groups against Team CRDs
9. Server creates JWT session, sets `butler_session` httpOnly cookie

### Internal User Login
1. Console calls `POST /api/auth/login/internal` with `{email, password}`
2. Server looks up User CRD by email, validates bcrypt password hash from referenced Secret
3. Server resolves teams, creates JWT session

### Invite Flow
1. Admin calls `POST /api/admin/users` to create user with invite
2. Server creates User CRD with invite token, sends invite URL
3. Invitee calls `GET /api/users/invite/{token}/validate` (public)
4. Invitee calls `POST /api/users/invite/{token}/set-password` (public)
5. Invitee can now use internal login

### Session Token
- Algorithm: HS256
- Claims: UserSession (email, name, teams, groups, isPlatformAdmin) + RegisteredClaims
- Cookie: `butler_session`, httpOnly, SameSiteLax, Secure in production
- Refresh: `POST /api/auth/refresh` issues new JWT
- Re-resolve: `POST /api/auth/refresh-permissions` re-resolves teams without re-login

## Team Scoping and Authorization

Every protected request can include an `X-Butler-Team` header. The middleware resolves the user's role in that team and sets `SelectedTeam` and `SelectedTeamRole` on the `UserSession`.

### Roles
- **admin** -- full team management, member/group control, all cluster operations
- **operator** -- cluster create/delete/scale, addon management, workspace operations
- **viewer** -- read-only access to team resources

### Authorization Checks in Handlers
Handlers use methods on `UserSession`:
- `CanViewInSelectedTeam()` -- any role can read
- `CanOperateInSelectedTeam()` -- admin or operator can mutate
- `IsAdminOfTeam(name)` -- team-level admin check
- `IsPlatformAdmin` -- bypasses all team checks

### Platform Admins
- `IsPlatformAdmin` flag grants access to all teams and resources
- When `X-Butler-Team` is set, platform admins still get scoped to that team context
- Platform admins without explicit team membership get synthetic admin role

### Cluster Access Pattern
Cluster handlers (`clusters.go`) use `checkClusterAccess` which:
1. Gets the cluster's team label (`butler.butlerlabs.dev/team`)
2. Checks if the user can view that team
3. For mutations, additionally checks `checkOperatePermission`

## WebSocket Handlers

### Cluster Watch (`/ws/clusters`)
- `Hub` maintains a registry of connected clients
- On connection, starts a goroutine reading from client (for future commands)
- `watchClusters` runs a K8s watch on TenantCluster GVR
- Watch events (ADDED, MODIFIED, DELETED) are broadcast to all connected clients
- Messages are JSON: `{type, cluster}` or `{type, namespace, name}` for deletes

### Terminal Sessions (`/ws/terminal/{namespace}/{name}` and `/ws/terminal/management`)
- Upgrades HTTP to WebSocket
- Creates a PTY (`creack/pty`) and starts a shell process
- For tenant clusters: fetches kubeconfig from cluster secret, writes to temp file, sets `KUBECONFIG` env
- For workspace type: runs `kubectl exec -it` into the workspace pod
- For management type: uses host kubeconfig or in-cluster config
- Bidirectional streaming: PTY stdout -> WebSocket text messages, WebSocket messages -> PTY stdin
- Client messages are JSON `{type, data, cols, rows}`: `"data"` for input, `"resize"` for terminal resize
- Keepalive: ping every 30s, pong extends read deadline to 90s
- Cleanup: kills shell process, closes PTY, removes temp kubeconfig

## Kubernetes Client (`internal/k8s`)

The `Client` struct wraps both a typed `kubernetes.Clientset` and a `dynamic.Interface`.

### GVR Constants (Butler CRDs)
| Variable | Group | Resource |
|---|---|---|
| `TenantClusterGVR` | `butler.butlerlabs.dev/v1alpha1` | `tenantclusters` |
| `ManagementAddonGVR` | `butler.butlerlabs.dev/v1alpha1` | `managementaddons` |
| `ProviderConfigGVR` | `butler.butlerlabs.dev/v1alpha1` | `providerconfigs` |
| `TenantAddonGVR` | `butler.butlerlabs.dev/v1alpha1` | `tenantaddons` |
| `AddonDefinitionGVR` | `butler.butlerlabs.dev/v1alpha1` | `addondefinitions` |
| `NetworkPoolGVR` | `butler.butlerlabs.dev/v1alpha1` | `networkpools` |
| `IPAllocationGVR` | `butler.butlerlabs.dev/v1alpha1` | `ipallocations` |

### GVR Constants (CAPI)
| Variable | Group | Resource |
|---|---|---|
| `ClusterGVR` | `cluster.x-k8s.io/v1beta1` | `clusters` |
| `MachineDeploymentGVR` | `cluster.x-k8s.io/v1beta1` | `machinedeployments` |

### Key Helper Methods
- `ListTenantClusters(ctx, namespace)` -- empty namespace lists across all namespaces
- `GetTenantCluster(ctx, namespace, name)` / `DeleteTenantCluster` / `PatchTenantCluster`
- `GetClusterKubeconfig(ctx, namespace, name)` -- reads admin kubeconfig from tenant secret
- `GetMachineDeployment(ctx, namespace, clusterName)` -- tries `{name}-workers` then `{name}-md-0`
- `ListAddonDefinitions(ctx)` / `GetAddonDefinition(ctx, name)` -- cluster-scoped
- `ListTenantAddons(ctx, namespace, clusterName)` -- uses label selector `butler.butlerlabs.dev/cluster={name}`
- `ListProviderConfigs(ctx, namespace)` / `GetProviderConfig(ctx, namespace, name)`

All CRD operations use `unstructured.Unstructured` via the dynamic client.

## Internal Packages

### `internal/config`
Environment-based configuration loaded from `BUTLER_*` prefixed variables:

| Variable | Default | Purpose |
|---|---|---|
| `BUTLER_SERVER_ADDR` | `:8080` | Listen address |
| `BUTLER_JWT_SECRET` | (required) | JWT signing key |
| `BUTLER_SESSION_EXPIRY` | `24h` | JWT token lifetime |
| `BUTLER_FRONTEND_URL` | `http://localhost:5173` | CORS origin, cookie domain |
| `BUTLER_OIDC_ISSUER` | -- | OIDC issuer URL |
| `BUTLER_OIDC_CLIENT_ID` | -- | OIDC client ID |
| `BUTLER_OIDC_CLIENT_SECRET` | -- | OIDC client secret |
| `BUTLER_GOOGLE_SERVICE_ACCOUNT` | -- | Google Admin SDK SA JSON |
| `BUTLER_GOOGLE_ADMIN_EMAIL` | -- | Google domain admin email |
| `BUTLER_TENANT_NAMESPACE` | `butler-system` | Default tenant namespace |
| `BUTLER_SYSTEM_NAMESPACE` | `butler-system` | System namespace |

OIDC presets: `GoogleWorkspaceConfig`, `MicrosoftEntraConfig`, `OktaConfig` provide default scopes and claim mappings for each provider.

### `internal/auth`
- **SessionService** -- JWT create/validate/refresh with HS256
- **TeamResolver** -- Matches user email and IdP groups against Team CRD `spec.access` to produce `[]TeamMembership`
- **UserService** -- Looks up User CRDs by email, checks disabled flag
- **OIDCProvider** -- Wraps `coreos/go-oidc` for token verification and discovery
- **GoogleGroupsFetcher** -- Uses Google Admin SDK to get group memberships (required because Google OIDC tokens do not include groups)

### `internal/websocket`
- **Hub** -- Manages WebSocket client connections; runs K8s watch loop that broadcasts cluster state changes to all clients
- **TerminalSession** -- Manages a single terminal: PTY allocation, shell process lifecycle, bidirectional WS<->PTY streaming, resize handling, keepalive pings

## Build and Run

### Makefile Targets

| Target | Purpose |
|---|---|
| `make build` | Compile binary to `bin/butler-server` with ldflags (version, commit, buildTime) |
| `make run` | Build and run with `-dev` flag |
| `make test` | Run `go test ./...` |
| `make lint` | Run `golangci-lint run` |
| `make fmt` | Run `gofmt -s -w .` |
| `make tidy` | Run `go mod tidy` |
| `make generate` | Run `go generate ./...` |
| `make build-console` | Build console and copy to `internal/api/static/` for embedding |
| `make build-all` | Build console then build server |
| `make docker-build` | Build Docker image (requires `../butler-api` as adjacent directory) |
| `make docker-push` | Push to `ghcr.io/butlerdotdev/butler-server` |
| `make deploy` | Apply Kubernetes manifests |
| `make undeploy` | Remove Kubernetes manifests |

### Docker Build
The Dockerfile uses a multi-stage build and requires butler-api as a build context:
```bash
docker build --build-context butler-api=../butler-api -t butler-server .
```

### CLI Flags
```
-addr string    Listen address (default ":8080")
-kubeconfig     Path to kubeconfig (default: in-cluster or ~/.kube/config)
-dev            Enable dev mode (CORS permissive, debug logging)
-version        Print version and exit
```

## CI/CD (`.github/workflows/ci.yml`)

Runs on self-hosted `butler-runners`. Triggered by pushes to `main` and `v*` tags.

| Job | What It Does |
|---|---|
| `build` | Go compile, runs on every push |
| `image` | Multi-arch Docker build+push to `ghcr.io/butlerdotdev/butler-server` (main + tags) |
| `release` | Creates GitHub Release on `v*` tags |
| `notify-docs` | Triggers `butlerlabs-docs` rebuild via repository dispatch |

The image job clones `butler-api` adjacent for the Docker build context.

## Key Conventions

- **Structured logging**: `log/slog` with JSON output. Logger passed via dependency injection, not globals.
- **Error responses**: All errors returned as `{"error": "message"}` JSON with appropriate HTTP status codes via `writeError()`.
- **Request context**: User session stored in context via `userContextKey`. Retrieved with `auth.UserFromContext(ctx)`.
- **Team scoping**: Handlers check `user.SelectedTeam` and call `CanViewInSelectedTeam()` / `CanOperateInSelectedTeam()` before accessing resources.
- **CRD access**: All Butler CRDs accessed via dynamic client with `unstructured.Unstructured`. No generated Go types from butler-api are imported at runtime -- only the GVR constants.
- **Namespace convention**: Team resources live in `team-{name}` namespaces. System resources live in `butler-system`.
- **Label convention**: `butler.butlerlabs.dev/team` on all team-owned resources.
- **Route parameters**: Chi URL params via `chi.URLParam(r, "name")`. Namespace and name are separate params: `{namespace}/{name}`.
- **Graceful shutdown**: `cmd/server/main.go` catches SIGINT/SIGTERM and calls `server.Shutdown(ctx)` with 30s timeout.
- **Copyright headers**: Apache 2.0 license with "The Butler Authors" copyright on all files.

## Impersonation on apiserver mutations (ADR-010)

butler-server forwards the authenticated user's identity to the apiserver via Kubernetes impersonation on mutations that go through admission webhooks. The webhook gates defined in ADR-009 (Team spec.resourceLimits, spec.environments[].limits, TenantCluster per-member cap) key on `req.UserInfo.Username`; without impersonation, every mutation presents butler-server's ServiceAccount identity and the gate either false-allows or false-denies.

The helper `k8sClient.AsUser(session)` returns a request-scoped client whose outgoing calls carry `Impersonate-User: <session.Email>` and `Impersonate-Group: butler-api-users`. Opt-in per call, not transparent middleware.

**When to call `AsUser(user)`** (impersonate):
- Handlers that MUTATE webhook-gated resources: Team spec changes (PATCH, PUT), TenantCluster create/update (POST, PATCH, PUT).
- Any handler that creates a TenantCluster must impersonate so the creator-email annotation the handler stamps matches the admission request's UserInfo. Otherwise the per-member cap check rejects the create for identity mismatch.

**When NOT to call `AsUser`** (use the shared server-SA client):
- Reads (GET, LIST, WATCH). No Butler admission webhook fires on reads; impersonation adds cost without benefit.
- Service-account-originated operations: device-flow SA provisioning (`internal/auth/serviceaccount.go`), session validation's User CRD lookup, team resolution, background reconciles, health probes.
- WebSocket cluster watches (`internal/websocket/hub.go`). Long-lived connections use server SA; tenant-cluster terminal sessions use the tenant kubeconfig (not platform apiserver).
- Team resolution from auth middleware — the session is establishing identity, not exercising it.

The convention is opt-in. If you are unsure whether a new handler needs impersonation, err on the side of opting in. A read that doesn't need it is slightly slower; a mutation that needed it and didn't opt in fails admission in ways that look like generic permission errors.

Email is canonicalized to lowercase at session creation (OIDC callback, internal login, device-flow token exchange, refresh). All downstream consumers read the canonical form. Do not re-canonicalize in handlers.

## What NOT to Do

- **Do not import butler-api Go types at runtime.** The server uses `unstructured.Unstructured` for all CRD access. butler-api is only a build dependency for the Dockerfile context.
- **Do not add routes without wiring them in `router.go`.** All routes are defined in `internal/api/router.go`, not in handler files.
- **Do not skip team authorization checks.** Every handler that accesses team-scoped resources must check `CanViewInSelectedTeam()` or `CanOperateInSelectedTeam()`.
- **Do not store mutable state in the JWT.** Team memberships are re-resolved on every request by `SessionMiddleware`. The JWT only stores identity claims.
- **Do not use global variables for config or clients.** Everything is injected through handler struct fields.
- **Do not add auth middleware to WebSocket routes.** WebSocket connections authenticate inside the handler after the upgrade.
- **Do not use typed K8s clients for Butler CRDs.** Use the dynamic client with the GVR constants defined in `internal/k8s/client.go`.
- **Do not hardcode namespace names.** Use `config.TenantNamespace` and `config.SystemNamespace` from the config, or derive team namespaces from the team name.
- **Do not log sensitive data.** Never log JWT tokens, passwords, kubeconfig contents, or provider credentials.
- **Do not commit CLAUDE.md to the repository.**
