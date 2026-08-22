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
	"net/http"
	"strings"
	"time"

	"github.com/butlerdotdev/butler-server/internal/api/handlers"
	"github.com/butlerdotdev/butler-server/internal/audit"
	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"
	"github.com/butlerdotdev/butler-server/internal/websocket"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

// RouterConfig holds configuration for the router.
type RouterConfig struct {
	K8sClient     *k8s.Client
	Config        *config.Config
	DevMode       bool
	StaticHandler http.Handler
	Logger        *slog.Logger
}

// NewRouter creates a new HTTP router with all routes configured.
func NewRouter(cfg RouterConfig) (http.Handler, error) {
	r := chi.NewRouter()

	// Initialize auth components
	sessionService := auth.NewSessionService(cfg.Config.Auth.JWTSecret, cfg.Config.Auth.SessionExpiry)
	teamResolver := auth.NewTeamResolver(cfg.K8sClient.Dynamic(), cfg.Logger.With("component", "teams"))

	// User service for internal user management
	userService := auth.NewUserService(
		cfg.K8sClient.Dynamic(),
		cfg.K8sClient.Clientset(),
		cfg.Logger.With("component", "users"),
	)

	// Sync bootstrap admin password hash to Secret
	// The Secret is created by butler-console Helm chart
	// The User CRD (created by butler-addons) references this Secret
	if cfg.Config.Auth.AdminPassword != "" {
		if err := userService.SyncBootstrapAdminPassword(context.Background(), auth.BootstrapAdminConfig{
			Username:        cfg.Config.Auth.AdminUsername,
			Password:        cfg.Config.Auth.AdminPassword,
			SecretName:      "butler-console-admin", // Matches butler-console chart
			SecretNamespace: cfg.Config.SystemNamespace,
			HashKey:         "password-hash",
		}); err != nil {
			cfg.Logger.Error("Failed to sync bootstrap admin password", "error", err)
			// Don't fail startup - admin can still auth via legacy path
		}
	}

	// Initialize OIDC provider if configured
	var oidcProvider *auth.OIDCProvider
	if cfg.Config.IsOIDCConfigured() {
		var err error
		// Load platformRoleGroups from IdentityProvider CRDs. These map IdP
		// groups to platform-wide roles (admin, viewer) at session creation.
		platformRoleGroups := auth.LoadAllPlatformRoleGroups(context.Background(), cfg.K8sClient.Dynamic())
		if len(platformRoleGroups) > 0 {
			cfg.Logger.Info("Loaded platform role groups from IdentityProvider CRDs",
				"count", len(platformRoleGroups),
			)
		}

		oidcProvider, err = auth.NewOIDCProvider(context.Background(), &auth.OIDCConfig{
			IssuerURL:          cfg.Config.OIDC.IssuerURL,
			ClientID:           cfg.Config.OIDC.ClientID,
			ClientSecret:       cfg.Config.OIDC.ClientSecret,
			RedirectURL:        cfg.Config.OIDC.RedirectURL,
			Scopes:             cfg.Config.OIDC.Scopes,
			HostedDomain:       cfg.Config.OIDC.HostedDomain,
			GroupsClaim:        cfg.Config.OIDC.GroupsClaim,
			EmailClaim:         cfg.Config.OIDC.EmailClaim,
			GoogleWorkspace:    loadGoogleWorkspaceConfig(&cfg.Config.OIDC),
			PlatformRoleGroups: platformRoleGroups,
		}, cfg.Logger)
		if err != nil {
			cfg.Logger.Error("Failed to initialize OIDC provider", "error", err)
		} else {
			cfg.Logger.Info("OIDC provider initialized",
				"issuer", cfg.Config.OIDC.IssuerURL,
				"hostedDomain", cfg.Config.OIDC.HostedDomain,
			)
		}
	} else {
		cfg.Logger.Warn("OIDC not configured - SSO login disabled")
	}

	// Initialize WebSocket hub
	wsHub := websocket.NewHub(cfg.K8sClient, cfg.Logger.With("component", "websocket"))
	go wsHub.Run()

	// Global middleware
	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(LoggingMiddleware(cfg.Logger))
	r.Use(chimiddleware.Recoverer)

	// CORS for development
	if cfg.DevMode {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   []string{"http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:5173"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}

	// Audit emitter
	auditEmitter := audit.NewEmitter(10000, "", cfg.Logger.With("component", "audit"))
	auditEmitter.SetHub(wsHub)

	// Wire session resolver for WebSocket upgrade auth (ADR-013) and
	// per-client notification filtering. Cookie first, bearer header
	// fallback so CLI/API clients can authenticate the same way
	// browser clients do.
	wsHub.SetSessionResolver(func(r *http.Request) (*websocket.SessionInfo, error) {
		var token string
		if cookie, err := r.Cookie("butler_session"); err == nil {
			token = cookie.Value
		}
		if token == "" {
			if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
				token = strings.TrimPrefix(h, "Bearer ")
			}
		}
		if token == "" {
			return nil, http.ErrNoCookie
		}
		// resolveWSSession re-resolves team memberships and roles from Team CRDs
		// rather than trusting the JWT claims, mirroring SessionMiddleware. This
		// keeps membership and role current for the terminal authorization gate
		// and for per-client notification filtering.
		return resolveWSSession(r.Context(), token, sessionService, teamResolver, cfg.Logger)
	})

	// Initialize device flow for CLI authentication
	var deviceFlowHandler *handlers.DeviceFlowHandler
	if cfg.Config.CLIAuth.Enabled {
		deviceStore := auth.NewDeviceStore()
		deviceStore.StartCleanup(context.Background(), 1*time.Minute)

		saManager := auth.NewCLIServiceAccountManager(
			cfg.K8sClient.Clientset(),
			cfg.K8sClient.Config(),
			cfg.Logger.With("component", "cli-sa-manager"),
			cfg.Config.SystemNamespace,
			cfg.Config.CLIAuth.TokenExpiry,
			cfg.Config.CLIAuth.ExternalAPIURL,
		)

		deviceFlowHandler = handlers.NewDeviceFlowHandler(
			deviceStore,
			saManager,
			teamResolver,
			userService,
			sessionService,
			cfg.Config,
			cfg.Logger.With("component", "cli-device-flow"),
			auditEmitter,
		)

		cfg.Logger.Info("CLI device flow authentication enabled")
	} else {
		cfg.Logger.Info("CLI device flow authentication disabled")
	}

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(
		oidcProvider,
		sessionService,
		teamResolver,
		userService,
		cfg.Config,
		cfg.Logger.With("component", "auth"),
		auditEmitter,
	)
	userHandler := handlers.NewUserHandler(
		userService,
		sessionService,
		teamResolver,
		cfg.K8sClient,
		cfg.Config,
		cfg.Logger.With("component", "users"),
	)
	clusterHandler := handlers.NewClusterHandler(cfg.K8sClient, cfg.Config)
	providerHandler := handlers.NewProvidersHandler(cfg.K8sClient, cfg.Config)
	addonsHandler := handlers.NewAddonsHandler(cfg.K8sClient, cfg.Config)
	teamHandler := handlers.NewTeamHandler(cfg.K8sClient, teamResolver, userService, cfg.Logger.With("component", "teams"))
	certificateHandler := handlers.NewCertificateHandler(cfg.K8sClient, cfg.Config, cfg.Logger.With("component", "certificates"))
	gitopsHandler := handlers.NewGitOpsHandler(cfg.K8sClient, cfg.Config, cfg.Logger.With("component", "gitops"))
	identityProviderHandler := handlers.NewIdentityProvidersHandler(cfg.K8sClient, cfg.Config)
	adminPoliciesHandler := handlers.NewAdminPoliciesHandler(cfg.K8sClient)
	networksHandler := handlers.NewNetworksHandler(cfg.K8sClient, cfg.Config)
	workspaceHandler := handlers.NewWorkspaceHandler(cfg.K8sClient, cfg.Config, cfg.Logger.With("component", "workspaces"))
	observabilityHandler := handlers.NewObservabilityHandler(cfg.K8sClient, cfg.Config, cfg.Logger.With("component", "observability"))
	imagesHandler := handlers.NewImagesHandler(cfg.K8sClient, cfg.Config, cfg.Logger.With("component", "images"))
	configHandler := handlers.NewConfigHandler(cfg.K8sClient, cfg.Config, cfg.Logger.With("component", "config"), auditEmitter, wsHub)
	stewardHandler := handlers.NewStewardHandler(cfg.K8sClient, cfg.Config)
	auditHandler := handlers.NewAuditHandler(auditEmitter)

	// Portal verifier is constructed only when an Ed25519 public key is
	// configured. Stage 1 default ships with BUTLER_PORTAL_PUBKEY unset, so
	// the verifier is nil and SessionMiddleware's portal branch stays
	// dormant. Stage 2 onward sets the pubkey via the same env var.
	var portalVerifier *auth.PortalJWTVerifier
	if pemData := cfg.Config.Auth.PortalPubKey; pemData != "" {
		keys, err := auth.ParsePortalPublicKeysPEM(pemData)
		if err != nil {
			cfg.Logger.Error("BUTLER_PORTAL_PUBKEY parse failed", "error", err)
		} else {
			verifier, err := auth.NewPortalJWTVerifier(keys, userService)
			if err != nil {
				cfg.Logger.Error("portal verifier construction failed", "error", err)
			} else {
				portalVerifier = verifier
				cfg.Logger.Info("Portal JWT verifier ready", "keys", len(keys))
			}
		}
	}

	// Auth middleware - SECURITY: Now re-validates team membership on every request
	authMiddleware := auth.SessionMiddleware(auth.SessionMiddlewareConfig{
		SessionService:           sessionService,
		TeamResolver:             teamResolver,
		UserService:              userService,
		Logger:                   cfg.Logger.With("component", "auth-middleware"),
		PortalVerifier:           portalVerifier,
		AllowHeaderImpersonation: cfg.Config.Auth.AllowHeaderImpersonation,
	})
	// adminMiddleware passes admins of any team; it stays on the team
	// member and group-sync routes, whose handlers narrow it to the
	// named team. Platform-level mutations use RequirePlatformAdmin.
	adminMiddleware := auth.AdminMiddleware()
	platformAdminMiddleware := auth.RequirePlatformAdmin()

	r.Route("/api", func(r chi.Router) {
		// Public auth routes (no authentication required)
		r.Route("/auth", func(r chi.Router) {
			// Get available providers (for login page)
			r.Get("/providers", authHandler.GetProviders)

			// SSO login flow (redirects to IdP)
			if oidcProvider != nil {
				r.Get("/login/sso", authHandler.Login)
				r.Get("/callback", authHandler.Callback)
			}

			// Username/password login (internal users + legacy admin)
			r.Post("/login", authHandler.InternalUserLogin)

			// Legacy endpoint for backward compatibility
			r.Post("/login/legacy", authHandler.LegacyLogin)

			// Invite flow (public - user clicking invite link)
			r.Get("/invite/{token}", userHandler.ValidateInvite)
			r.Post("/set-password", userHandler.SetPassword)

			// CLI device flow (public endpoints)
			if deviceFlowHandler != nil {
				r.Post("/cli/device", deviceFlowHandler.DeviceAuthorize)
				r.Post("/cli/token", deviceFlowHandler.DeviceToken)
				r.Post("/cli/verify", deviceFlowHandler.DeviceVerify)
				r.Post("/cli/refresh", deviceFlowHandler.DeviceRefresh)
			}
		})

		// Protected routes (authentication required)
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware)
			r.Use(audit.Middleware(auditEmitter))

			// Auth endpoints
			r.Post("/auth/logout", authHandler.Logout)
			r.Post("/auth/refresh", authHandler.Refresh)
			r.Post("/auth/refresh-permissions", authHandler.RefreshPermissions)
			r.Get("/auth/me", authHandler.Me)
			r.Get("/auth/teams", authHandler.Teams)

			// CLI device flow approval (requires authenticated session)
			if deviceFlowHandler != nil {
				r.Post("/auth/cli/approve", deviceFlowHandler.DeviceApprove)
			}

			// Management cluster
			r.Get("/management", clusterHandler.GetManagement)
			r.Get("/management/nodes", clusterHandler.GetManagementNodes)
			r.Get("/management/pods/{namespace}", clusterHandler.GetManagementPods)

			// Management addons (reads)
			r.Get("/management/addons", addonsHandler.ListManagementAddons)
			r.Get("/management/addons/{name}", addonsHandler.GetManagementAddon)

			// Management addons (mutations - platform admin only)
			r.Group(func(r chi.Router) {
				r.Use(platformAdminMiddleware)
				r.Post("/management/addons", addonsHandler.InstallManagementAddon)
				r.Put("/management/addons/{name}", addonsHandler.UpdateManagementAddon)
				r.Delete("/management/addons/{name}", addonsHandler.UninstallManagementAddon)
			})

			// Management GitOps (reads)
			r.Get("/management/gitops/status", gitopsHandler.GetManagementStatus)
			r.Get("/management/gitops/discover", gitopsHandler.DiscoverManagementReleases)

			// Management GitOps (mutations - platform admin only)
			r.Group(func(r chi.Router) {
				r.Use(platformAdminMiddleware)
				r.Post("/management/gitops/enable", gitopsHandler.EnableManagementGitOps)
				r.Delete("/management/gitops", gitopsHandler.DisableManagementGitOps)
				// Deprecated: v1 per-addon export — emits pre-standard tree
				// shape (clusters/management/<tier>/<addon>/), inconsistent
				// with /management/gitops/export-cluster. Per-addon
				// catalog-install alignment onto the v2 emit engine is a
				// follow-up.
				r.Post("/management/gitops/export", gitopsHandler.ExportManagementAddon)
				r.Post("/management/gitops/export-catalog", gitopsHandler.ExportManagementCatalogAddon)
				// Deprecated: superseded by /management/gitops/export-cluster (v2
				// preview-first cluster-wide export). Kept for one release cycle
				// to avoid breaking any non-console caller; remove in a follow-up.
				r.Post("/management/gitops/migrate", gitopsHandler.ExportAllManagementAddons)
				// v2 cluster-wide preview + export (mgmt). Symmetric with the
				// tenant pair below. Preview runs discovery + layout + coverage
				// with no git interaction; export wraps the same pipeline with
				// RunExportV2's git push.
				r.Post("/management/gitops/preview-cluster", gitopsHandler.PreviewManagementCluster)
				r.Post("/management/gitops/export-cluster", gitopsHandler.ExportManagementCluster)
			})

			// Steward: TenantControlPlane and DataStore visibility
			r.Get("/management/tenantcontrolplanes", stewardHandler.ListTenantControlPlanes)
			r.Get("/management/tenantcontrolplanes/{namespace}/{name}", stewardHandler.GetTenantControlPlane)
			r.Get("/management/datastores", stewardHandler.ListDataStores)
			r.Get("/management/datastores/{name}", stewardHandler.GetDataStore)

			// Addon catalog
			r.Get("/addons/catalog", addonsHandler.GetCatalog)
			r.Get("/addons/catalog/{name}", addonsHandler.GetAddonDefinition)

			// Tenant clusters
			r.Get("/clusters", clusterHandler.List)
			r.Post("/clusters", clusterHandler.Create)
			r.Get("/clusters/{namespace}/{name}", clusterHandler.Get)
			r.Delete("/clusters/{namespace}/{name}", clusterHandler.Delete)
			r.Put("/clusters/{namespace}/{name}", clusterHandler.Update)
			r.Patch("/clusters/{namespace}/{name}/scale", clusterHandler.Scale)
			r.Put("/clusters/{namespace}/{name}/environment", clusterHandler.ChangeEnvironment)
			r.Post("/clusters/{namespace}/{name}/settings/workspaces", clusterHandler.ToggleWorkspaces)
			r.Get("/clusters/{namespace}/{name}/kubeconfig", clusterHandler.GetKubeconfig)
			r.Get("/clusters/{namespace}/{name}/nodes", clusterHandler.GetNodes)
			r.Get("/clusters/{namespace}/{name}/events", clusterHandler.GetEvents)
			r.Get("/clusters/{namespace}/{name}/export", clusterHandler.ExportYAML)
			r.Get("/clusters/{namespace}/{name}/machines", clusterHandler.ListMachineRequests)
			r.Get("/clusters/{namespace}/{name}/load-balancers", clusterHandler.ListLoadBalancerRequests)
			r.Get("/clusters/{namespace}/{name}/tenantcontrolplane", stewardHandler.GetClusterTenantControlPlane)

			// Cluster addons
			r.Get("/clusters/{namespace}/{name}/addons", addonsHandler.ListClusterAddons)
			r.Post("/clusters/{namespace}/{name}/addons", addonsHandler.InstallAddon)
			r.Get("/clusters/{namespace}/{name}/addons/{addon}", addonsHandler.GetAddonDetails)
			r.Put("/clusters/{namespace}/{name}/addons/{addon}", addonsHandler.UpdateAddonValues)
			r.Delete("/clusters/{namespace}/{name}/addons/{addon}", addonsHandler.UninstallAddon)

			// GitOps global configuration (Git provider setup)
			r.Route("/gitops", func(r chi.Router) {
				r.Get("/config", gitopsHandler.GetConfig)
				r.Get("/repos", gitopsHandler.ListRepositories)
				r.Get("/repos/branches", gitopsHandler.ListBranches)

				// Mutations require platform admin (credentials and manifest generation)
				r.Group(func(r chi.Router) {
					r.Use(platformAdminMiddleware)
					r.Post("/config", gitopsHandler.SaveConfig)
					r.Delete("/config", gitopsHandler.ClearConfig)
					r.Post("/preview", gitopsHandler.PreviewManifest)
				})
			})

			// Cluster GitOps
			r.Get("/clusters/{namespace}/{name}/gitops/status", gitopsHandler.GetStatus)
			r.Post("/clusters/{namespace}/{name}/gitops/enable", gitopsHandler.EnableGitOps)
			r.Delete("/clusters/{namespace}/{name}/gitops", gitopsHandler.DisableGitOps)
			r.Get("/clusters/{namespace}/{name}/gitops/discover", gitopsHandler.DiscoverReleases)
			// Deprecated: v1 per-addon export — emits pre-standard tree
			// shape (clusters/<cluster>/<tier>/<addon>/), inconsistent
			// with /clusters/{ns}/{name}/gitops/export-cluster. Per-addon
			// catalog-install alignment onto the v2 emit engine is a
			// follow-up.
			r.Post("/clusters/{namespace}/{name}/gitops/export", gitopsHandler.ExportAddon)
			r.Post("/clusters/{namespace}/{name}/gitops/export-release", gitopsHandler.ExportRelease)
			// Deprecated: superseded by /clusters/{ns}/{name}/gitops/export-cluster
			// (v2 preview-first cluster-wide export). Kept for one release cycle
			// to avoid breaking any non-console caller; remove in a follow-up.
			r.Post("/clusters/{namespace}/{name}/gitops/migrate", gitopsHandler.ExportAllAddons)
			// v2 cluster-wide preview + export. Symmetric pair with the
			// per-addon /export and /export-release routes above; this pair
			// operates on the full cluster inventory rather than a single
			// addon. Preview runs discovery + layout + coverage with no git
			// interaction; export wraps the same pipeline with RunExportV2.
			r.Post("/clusters/{namespace}/{name}/gitops/preview-cluster", gitopsHandler.PreviewCluster)
			r.Post("/clusters/{namespace}/{name}/gitops/export-cluster", gitopsHandler.ExportCluster)

			// Cluster certificates
			r.Get("/clusters/{namespace}/{name}/certificates", certificateHandler.GetCertificates)
			r.Post("/clusters/{namespace}/{name}/certificates/rotate", certificateHandler.RotateCertificates)
			r.Get("/clusters/{namespace}/{name}/certificates/rotation-status", certificateHandler.GetRotationStatus)
			r.Get("/clusters/{namespace}/{name}/certificates/{category}", certificateHandler.GetCertificatesByCategory)

			// Workspaces
			r.Get("/clusters/{namespace}/{name}/workspaces", workspaceHandler.List)
			r.Post("/clusters/{namespace}/{name}/workspaces", workspaceHandler.Create)
			r.Get("/clusters/{namespace}/{name}/workspaces/{workspace}", workspaceHandler.Get)
			r.Delete("/clusters/{namespace}/{name}/workspaces/{workspace}", workspaceHandler.Delete)
			r.Post("/clusters/{namespace}/{name}/workspaces/{workspace}/connect", workspaceHandler.Connect)
			r.Post("/clusters/{namespace}/{name}/workspaces/{workspace}/disconnect", workspaceHandler.Disconnect)
			r.Post("/clusters/{namespace}/{name}/workspaces/{workspace}/start", workspaceHandler.StartWorkspace)
			r.Get("/clusters/{namespace}/{name}/workspaces/{workspace}/metrics", workspaceHandler.GetMetrics)
			r.Post("/clusters/{namespace}/{name}/workspaces/{workspace}/sync-ssh-keys", workspaceHandler.SyncSSHKeys)

			// Cluster services (for mirrord)
			r.Get("/clusters/{namespace}/{name}/services", workspaceHandler.ListServices)
			r.Post("/clusters/{namespace}/{name}/mirrord-config", workspaceHandler.GenerateMirrordConfig)

			// Workspace images and templates
			r.Get("/workspace-images", workspaceHandler.ListImages)
			r.Get("/workspace-templates", workspaceHandler.ListTemplates)
			r.Post("/workspace-templates", workspaceHandler.CreateTemplate)
			r.Post("/workspace-templates/{namespace}/{name}", workspaceHandler.UpdateTemplate)
			r.Delete("/workspace-templates/{namespace}/{name}", workspaceHandler.DeleteTemplate)

			// SSH keys (user self-service)
			r.Get("/auth/ssh-keys", userHandler.ListSSHKeys)
			r.Post("/auth/ssh-keys", userHandler.AddSSHKey)
			r.Delete("/auth/ssh-keys/{fingerprint}", userHandler.RemoveSSHKey)

			// Observability config (any authenticated user can read)
			r.Get("/observability/config", observabilityHandler.GetConfig)

			// Image syncs
			r.Get("/image-syncs", imagesHandler.ListImageSyncs)
			r.Post("/image-syncs", imagesHandler.CreateImageSync)
			r.Get("/image-syncs/{namespace}/{name}", imagesHandler.GetImageSync)
			r.Delete("/image-syncs/{namespace}/{name}", imagesHandler.DeleteImageSync)
			r.Put("/image-syncs/{namespace}/{name}", imagesHandler.UpdateImageSync)

			// Image factory proxy
			r.Get("/image-factory/catalog", imagesHandler.GetFactoryCatalog)
			r.Get("/image-factory/schematics/{id}", imagesHandler.GetFactorySchematic)

			// Providers (reads)
			r.Get("/providers", providerHandler.List)
			r.Get("/providers/{namespace}/{name}/images", providerHandler.ListImages)
			r.Get("/providers/{namespace}/{name}/networks", providerHandler.ListNetworks)
			r.Get("/providers/{namespace}/{name}/clusters", providerHandler.ListClusters)
			r.Get("/providers/{namespace}/{name}/storage-containers", providerHandler.ListStorageContainers)
			r.Get("/providers/{namespace}/{name}", providerHandler.Get)
			r.Get("/providers/{namespace}/{name}/ca-info", providerHandler.GetCAInfo)

			// Provider mutations (platform admin only - credentials are sensitive)
			r.Group(func(r chi.Router) {
				r.Use(platformAdminMiddleware)
				r.Post("/providers", providerHandler.Create)
				r.Post("/providers/test", providerHandler.TestConnection)
				r.Put("/providers/{namespace}/{name}", providerHandler.Update)
				r.Delete("/providers/{namespace}/{name}", providerHandler.Delete)
				r.Post("/providers/{namespace}/{name}/validate", providerHandler.Validate)
			})

			// Teams
			r.Get("/teams", teamHandler.List)
			r.Post("/teams", teamHandler.Create)
			r.Get("/teams/{name}", teamHandler.Get)
			r.Put("/teams/{name}", teamHandler.Update)
			r.Delete("/teams/{name}", teamHandler.Delete)
			r.Get("/teams/{name}/clusters", teamHandler.ListClusters)
			r.Get("/teams/{name}/members", teamHandler.ListMembers)
			r.Get("/teams/{name}/groups", teamHandler.ListGroupSyncs)
			r.Get("/teams/{name}/audit", auditHandler.ListTeam)

			// Team provider management (team members can list, team admins can create/delete)
			r.Get("/teams/{name}/providers", providerHandler.ListTeamProviders)
			r.Post("/teams/{name}/providers", providerHandler.CreateTeamProvider)
			r.Post("/teams/{name}/providers/test", providerHandler.TestConnection)
			r.Delete("/teams/{name}/providers/{namespace}/{providerName}", providerHandler.DeleteTeamProvider)

			// Team environment management (ADR-009). The Team admission
			// webhook is the authoritative gate for mutation authority
			// (team admin for env limits, platform admin for resource
			// limits); these handlers impersonate the caller so the
			// webhook sees the real identity.
			r.Post("/teams/{name}/environments", teamHandler.AddEnvironment)
			r.Put("/teams/{name}/environments/{env}", teamHandler.UpdateEnvironment)
			r.Delete("/teams/{name}/environments/{env}", teamHandler.RemoveEnvironment)

			// User listing (any authenticated user can view)
			r.Get("/users", userHandler.ListUsers)

			// Admin read-only routes (platform viewer or above)
			r.Route("/admin", func(r chi.Router) {
				r.Use(auth.RequirePlatformViewer())

				// Identity providers (read-only for viewers)
				r.Get("/identity-providers", identityProviderHandler.List)
				r.Get("/identity-providers/{name}", identityProviderHandler.Get)

				// ClusterCreationPolicy (read-only for viewers, ADR-018)
				r.Get("/policies", adminPoliciesHandler.List)
				r.Get("/policies/{name}", adminPoliciesHandler.Get)

				// Network pools (read-only for viewers)
				r.Get("/networks", networksHandler.ListNetworkPools)
				r.Get("/networks/{namespace}/{name}", networksHandler.GetNetworkPool)
				r.Get("/networks/{namespace}/{name}/allocations", networksHandler.ListAllocations)
				r.Get("/ipallocations", networksHandler.ListAllAllocations)

				// Audit log (read-only for viewers). Platform config stays
				// admin-only below: it carries audit and notification
				// webhook URLs.
				r.Get("/audit", auditHandler.ListAll)

				// Team membership and group sync (platform admin, or admin of
				// the named team; the handlers enforce the team scope)
				r.Group(func(r chi.Router) {
					r.Use(adminMiddleware)
					r.Post("/teams/{name}/members", teamHandler.AddMember)
					r.Patch("/teams/{name}/members/{email}", teamHandler.UpdateMemberRole)
					r.Delete("/teams/{name}/members/{email}", teamHandler.RemoveMember)
					r.Post("/teams/{name}/groups", teamHandler.AddGroupSync)
					r.Patch("/teams/{name}/groups/{groupName}", teamHandler.UpdateGroupSyncRole)
					r.Delete("/teams/{name}/groups/{groupName}", teamHandler.RemoveGroupSync)
				})

				// Platform-admin-only mutations
				r.Group(func(r chi.Router) {
					r.Use(platformAdminMiddleware)

					// User management
					r.Post("/users", userHandler.CreateUser)
					r.Get("/users/{username}", userHandler.GetUser)
					r.Delete("/users/{username}", userHandler.DeleteUser)
					r.Post("/users/{username}/disable", userHandler.DisableUser)
					r.Post("/users/{username}/enable", userHandler.EnableUser)
					r.Post("/users/{username}/invite", userHandler.RegenerateInvite)

					// Team lifecycle
					r.Post("/teams", teamHandler.Create)
					r.Delete("/teams/{name}", teamHandler.Delete)

					// Identity provider mutations
					r.Post("/identity-providers", identityProviderHandler.Create)
					r.Post("/identity-providers/test", identityProviderHandler.TestDiscovery)
					r.Put("/identity-providers/{name}", identityProviderHandler.Update)
					r.Delete("/identity-providers/{name}", identityProviderHandler.Delete)
					r.Post("/identity-providers/{name}/validate", identityProviderHandler.Validate)

					// ClusterCreationPolicy mutations (ADR-018)
					r.Post("/policies", adminPoliciesHandler.Create)
					r.Put("/policies/{name}", adminPoliciesHandler.Update)
					r.Delete("/policies/{name}", adminPoliciesHandler.Delete)

					// Addon catalog management
					r.Post("/addons/catalog", addonsHandler.CreateAddonDefinition)
					r.Put("/addons/catalog/{name}", addonsHandler.UpdateAddonDefinition)
					r.Delete("/addons/catalog/{name}", addonsHandler.DeleteAddonDefinition)

					// Network pool mutations
					r.Post("/networks", networksHandler.CreateNetworkPool)
					r.Put("/networks/{namespace}/{name}", networksHandler.UpdateNetworkPool)
					r.Delete("/networks/{namespace}/{name}", networksHandler.DeleteNetworkPool)
					r.Delete("/ipallocations/{namespace}/{name}", networksHandler.ReleaseAllocation)

					// Platform configuration
					r.Get("/config", configHandler.GetConfig)
					r.Put("/config", configHandler.UpdateConfig)

					// Observability management
					r.Put("/observability/config", observabilityHandler.UpdateConfig)
					r.Get("/observability/status", observabilityHandler.GetStatus)
					r.Post("/observability/pipeline/setup", observabilityHandler.SetupPipeline)
					r.Delete("/observability/pipeline", observabilityHandler.DeregisterPipeline)
				})
			})
		})
	})

	// WebSocket routes (authentication handled per-connection)
	r.Route("/ws", func(r chi.Router) {
		r.Get("/clusters", wsHub.HandleClusterWatch)
		r.Get("/terminal/management", wsHub.HandleManagementTerminal)
		r.Get("/terminal/{type}/{namespace}/{cluster}", wsHub.HandleTerminal)
		r.Get("/terminal/{type}/{namespace}/{cluster}/{pod}", wsHub.HandleTerminal)
		r.Get("/terminal/{type}/{namespace}/{cluster}/{pod}/{container}", wsHub.HandleTerminal)
	})

	// Health endpoints
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	// Static files (SPA)
	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		cfg.StaticHandler.ServeHTTP(w, r)
	})

	return r, nil
}

// LoggingMiddleware creates a request logging middleware.
func LoggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func() {
				logger.Info("request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", ww.Status(),
					"bytes", ww.BytesWritten(),
					"request_id", chimiddleware.GetReqID(r.Context()),
				)
			}()
			next.ServeHTTP(ww, r)
		})
	}
}

func loadGoogleWorkspaceConfig(oidcCfg *config.OIDCConfig) *auth.GoogleGroupsConfig {
	if oidcCfg.GoogleServiceAccountJSON == "" || oidcCfg.GoogleAdminEmail == "" {
		return nil
	}
	return &auth.GoogleGroupsConfig{
		ServiceAccountJSON: oidcCfg.GoogleServiceAccountJSON,
		AdminEmail:         oidcCfg.GoogleAdminEmail,
		Domain:             oidcCfg.HostedDomain,
	}
}
