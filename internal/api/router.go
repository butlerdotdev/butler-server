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

	"github.com/butlerdotdev/butler-server/internal/api/handlers"
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
	baseURL := cfg.Config.Server.BaseURL
	if baseURL == "" {
		baseURL = "http://localhost:8080" // Default for dev
	}
	userService := auth.NewUserService(
		cfg.K8sClient.Dynamic(),
		cfg.K8sClient.Clientset(),
		baseURL,
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
		oidcProvider, err = auth.NewOIDCProvider(context.Background(), &auth.OIDCConfig{
			IssuerURL:       cfg.Config.OIDC.IssuerURL,
			ClientID:        cfg.Config.OIDC.ClientID,
			ClientSecret:    cfg.Config.OIDC.ClientSecret,
			RedirectURL:     cfg.Config.OIDC.RedirectURL,
			Scopes:          cfg.Config.OIDC.Scopes,
			HostedDomain:    cfg.Config.OIDC.HostedDomain,
			GroupsClaim:     cfg.Config.OIDC.GroupsClaim,
			EmailClaim:      cfg.Config.OIDC.EmailClaim,
			GoogleWorkspace: loadGoogleWorkspaceConfig(&cfg.Config.OIDC),
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

	// Initialize handlers
	authHandler := handlers.NewAuthHandler(
		oidcProvider,
		sessionService,
		teamResolver,
		userService,
		cfg.Config,
		cfg.Logger.With("component", "auth"),
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
	teamHandler := handlers.NewTeamHandler(cfg.K8sClient, teamResolver, cfg.Logger.With("component", "teams"))
	certificateHandler := handlers.NewCertificateHandler(cfg.K8sClient, cfg.Config, cfg.Logger.With("component", "certificates"))
	gitopsHandler := handlers.NewGitOpsHandler(cfg.K8sClient, cfg.Config, cfg.Logger.With("component", "gitops"))
	identityProviderHandler := handlers.NewIdentityProvidersHandler(cfg.K8sClient, cfg.Config)
	networksHandler := handlers.NewNetworksHandler(cfg.K8sClient, cfg.Config)
	workspaceHandler := handlers.NewWorkspaceHandler(cfg.K8sClient, cfg.Config, cfg.Logger.With("component", "workspaces"))

	// Auth middleware - SECURITY: Now re-validates team membership on every request
	authMiddleware := auth.SessionMiddleware(auth.SessionMiddlewareConfig{
		SessionService: sessionService,
		TeamResolver:   teamResolver,
		UserService:    userService,
		Logger:         cfg.Logger.With("component", "auth-middleware"),
	})
	adminMiddleware := auth.AdminMiddleware()

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
		})

		// Protected routes (authentication required)
		r.Group(func(r chi.Router) {
			r.Use(authMiddleware)

			// Auth endpoints
			r.Post("/auth/logout", authHandler.Logout)
			r.Post("/auth/refresh", authHandler.Refresh)
			r.Post("/auth/refresh-permissions", authHandler.RefreshPermissions)
			r.Get("/auth/me", authHandler.Me)
			r.Get("/auth/teams", authHandler.Teams)

			// Management cluster
			r.Get("/management", clusterHandler.GetManagement)
			r.Get("/management/nodes", clusterHandler.GetManagementNodes)
			r.Get("/management/pods/{namespace}", clusterHandler.GetManagementPods)

			// Management addons
			r.Get("/management/addons", addonsHandler.ListManagementAddons)
			r.Post("/management/addons", addonsHandler.InstallManagementAddon)
			r.Get("/management/addons/{name}", addonsHandler.GetManagementAddon)
			r.Put("/management/addons/{name}", addonsHandler.UpdateManagementAddon)
			r.Delete("/management/addons/{name}", addonsHandler.UninstallManagementAddon)

			// Management GitOps
			r.Get("/management/gitops/status", gitopsHandler.GetManagementStatus)
			r.Post("/management/gitops/enable", gitopsHandler.EnableManagementGitOps)
			r.Delete("/management/gitops", gitopsHandler.DisableManagementGitOps)
			r.Get("/management/gitops/discover", gitopsHandler.DiscoverManagementReleases)
			r.Post("/management/gitops/export", gitopsHandler.ExportManagementAddon)
			r.Post("/management/gitops/export-catalog", gitopsHandler.ExportManagementCatalogAddon)
			r.Post("/management/gitops/migrate", gitopsHandler.ExportAllManagementAddons)

			// Addon catalog
			r.Get("/addons/catalog", addonsHandler.GetCatalog)
			r.Get("/addons/catalog/{name}", addonsHandler.GetAddonDefinition)

			// Tenant clusters
			r.Get("/clusters", clusterHandler.List)
			r.Post("/clusters", clusterHandler.Create)
			r.Get("/clusters/{namespace}/{name}", clusterHandler.Get)
			r.Delete("/clusters/{namespace}/{name}", clusterHandler.Delete)
			r.Patch("/clusters/{namespace}/{name}/scale", clusterHandler.Scale)
			r.Post("/clusters/{namespace}/{name}/settings/workspaces", clusterHandler.ToggleWorkspaces)
			r.Get("/clusters/{namespace}/{name}/kubeconfig", clusterHandler.GetKubeconfig)
			r.Get("/clusters/{namespace}/{name}/nodes", clusterHandler.GetNodes)
			r.Get("/clusters/{namespace}/{name}/events", clusterHandler.GetEvents)

			// Cluster addons
			r.Get("/clusters/{namespace}/{name}/addons", addonsHandler.ListClusterAddons)
			r.Post("/clusters/{namespace}/{name}/addons", addonsHandler.InstallAddon)
			r.Get("/clusters/{namespace}/{name}/addons/{addon}", addonsHandler.GetAddonDetails)
			r.Put("/clusters/{namespace}/{name}/addons/{addon}", addonsHandler.UpdateAddonValues)
			r.Delete("/clusters/{namespace}/{name}/addons/{addon}", addonsHandler.UninstallAddon)

			// GitOps global configuration (Git provider setup)
			r.Route("/gitops", func(r chi.Router) {
				r.Get("/config", gitopsHandler.GetConfig)
				r.Post("/config", gitopsHandler.SaveConfig)
				r.Get("/repos", gitopsHandler.ListRepositories)
				r.Get("/repos/{owner}/{repo}/branches", gitopsHandler.ListBranches)
				r.Post("/preview", gitopsHandler.PreviewManifest)
			})

			// Cluster GitOps
			r.Get("/clusters/{namespace}/{name}/gitops/status", gitopsHandler.GetStatus)
			r.Post("/clusters/{namespace}/{name}/gitops/enable", gitopsHandler.EnableGitOps)
			r.Delete("/clusters/{namespace}/{name}/gitops", gitopsHandler.DisableGitOps)
			r.Get("/clusters/{namespace}/{name}/gitops/discover", gitopsHandler.DiscoverReleases)
			r.Post("/clusters/{namespace}/{name}/gitops/export", gitopsHandler.ExportAddon)
			r.Post("/clusters/{namespace}/{name}/gitops/export-release", gitopsHandler.ExportRelease)
			r.Post("/clusters/{namespace}/{name}/gitops/migrate", gitopsHandler.ExportAllAddons)

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

			// Providers
			r.Get("/providers", providerHandler.List)
			r.Post("/providers", providerHandler.Create)
			r.Post("/providers/test", providerHandler.TestConnection)
			r.Get("/providers/{namespace}/{name}/images", providerHandler.ListImages)
			r.Get("/providers/{namespace}/{name}/networks", providerHandler.ListNetworks)
			r.Get("/providers/{namespace}/{name}", providerHandler.Get)
			r.Delete("/providers/{namespace}/{name}", providerHandler.Delete)
			r.Post("/providers/{namespace}/{name}/validate", providerHandler.Validate)

			// Teams
			r.Get("/teams", teamHandler.List)
			r.Post("/teams", teamHandler.Create)
			r.Get("/teams/{name}", teamHandler.Get)
			r.Put("/teams/{name}", teamHandler.Update)
			r.Delete("/teams/{name}", teamHandler.Delete)
			r.Get("/teams/{name}/clusters", teamHandler.ListClusters)
			r.Get("/teams/{name}/members", teamHandler.ListMembers)
			r.Get("/teams/{name}/groups", teamHandler.ListGroupSyncs)

			// Team provider management (team members can list, team admins can create/delete)
			r.Get("/teams/{name}/providers", providerHandler.ListTeamProviders)
			r.Post("/teams/{name}/providers", providerHandler.CreateTeamProvider)
			r.Post("/teams/{name}/providers/test", providerHandler.TestConnection)
			r.Delete("/teams/{name}/providers/{namespace}/{providerName}", providerHandler.DeleteTeamProvider)

			// User listing (any authenticated user can view)
			r.Get("/users", userHandler.ListUsers)

			// Admin routes (require admin role for management actions)
			r.Route("/admin", func(r chi.Router) {
				r.Use(adminMiddleware)

				// User management (admin only)
				r.Post("/users", userHandler.CreateUser)
				r.Get("/users/{username}", userHandler.GetUser)
				r.Delete("/users/{username}", userHandler.DeleteUser)
				r.Post("/users/{username}/disable", userHandler.DisableUser)
				r.Post("/users/{username}/enable", userHandler.EnableUser)
				r.Post("/users/{username}/invite", userHandler.RegenerateInvite)

				// Team management (admin only)
				r.Post("/teams", teamHandler.Create)
				r.Delete("/teams/{name}", teamHandler.Delete)
				r.Post("/teams/{name}/members", teamHandler.AddMember)
				r.Patch("/teams/{name}/members/{email}", teamHandler.UpdateMemberRole)
				r.Delete("/teams/{name}/members/{email}", teamHandler.RemoveMember)

				// Team group sync management (admin only)
				r.Post("/teams/{name}/groups", teamHandler.AddGroupSync)
				r.Patch("/teams/{name}/groups/{groupName}", teamHandler.UpdateGroupSyncRole)
				r.Delete("/teams/{name}/groups/{groupName}", teamHandler.RemoveGroupSync)

				r.Route("/identity-providers", func(r chi.Router) {
					r.Get("/", identityProviderHandler.List)
					r.Post("/", identityProviderHandler.Create)
					r.Post("/test", identityProviderHandler.TestDiscovery)
					r.Get("/{name}", identityProviderHandler.Get)
					r.Delete("/{name}", identityProviderHandler.Delete)
					r.Post("/{name}/validate", identityProviderHandler.Validate)
				})

				// Network pools and IP allocations
				r.Get("/networks", networksHandler.ListNetworkPools)
				r.Post("/networks", networksHandler.CreateNetworkPool)
				r.Get("/networks/{namespace}/{name}", networksHandler.GetNetworkPool)
				r.Delete("/networks/{namespace}/{name}", networksHandler.DeleteNetworkPool)
				r.Get("/networks/{namespace}/{name}/allocations", networksHandler.ListAllocations)
				r.Get("/ipallocations", networksHandler.ListAllAllocations)
				r.Delete("/ipallocations/{namespace}/{name}", networksHandler.ReleaseAllocation)

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
