/*
Copyright 2025 The Butler Authors.

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
	"log/slog"
	"net/http"

	"github.com/butlerdotdev/butler-server/internal/api/handlers"
	"github.com/butlerdotdev/butler-server/internal/api/middleware"
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
func NewRouter(cfg RouterConfig) http.Handler {
	r := chi.NewRouter()

	tokenService := auth.NewTokenService(cfg.Config.Auth.JWTSecret, cfg.Config.Auth.JWTExpiry)

	wsHub := websocket.NewHub(cfg.K8sClient, cfg.Logger.With("component", "websocket"))
	go wsHub.Run()

	r.Use(chimiddleware.RequestID)
	r.Use(chimiddleware.RealIP)
	r.Use(middleware.Logger(cfg.Logger))
	r.Use(chimiddleware.Recoverer)

	if cfg.DevMode {
		r.Use(cors.Handler(cors.Options{
			AllowedOrigins:   []string{"http://localhost:3000", "http://127.0.0.1:3000"},
			AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
			AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Request-ID"},
			ExposedHeaders:   []string{"Link"},
			AllowCredentials: true,
			MaxAge:           300,
		}))
	}

	authHandler := handlers.NewAuthHandler(tokenService, cfg.Config)
	clusterHandler := handlers.NewClusterHandler(cfg.K8sClient, cfg.Config)
	providerHandler := handlers.NewProvidersHandler(cfg.K8sClient, cfg.Config)
	addonsHandler := handlers.NewAddonsHandler(cfg.K8sClient, cfg.Config)

	authMiddleware := middleware.Auth(tokenService)

	r.Route("/api", func(r chi.Router) {
		r.Route("/auth", func(r chi.Router) {
			r.Post("/login", authHandler.Login)
		})

		r.Group(func(r chi.Router) {
			r.Use(authMiddleware)

			r.Post("/auth/logout", authHandler.Logout)
			r.Post("/auth/refresh", authHandler.Refresh)
			r.Get("/auth/me", authHandler.Me)

			r.Get("/management", clusterHandler.GetManagement)
			r.Get("/management/nodes", clusterHandler.GetManagementNodes)
			r.Get("/management/pods/{namespace}", clusterHandler.GetManagementPods)

			r.Get("/management/addons", addonsHandler.ListManagementAddons)
			r.Post("/management/addons", addonsHandler.InstallManagementAddon)
			r.Get("/management/addons/{name}", addonsHandler.GetManagementAddon)
			r.Put("/management/addons/{name}", addonsHandler.UpdateManagementAddon)
			r.Delete("/management/addons/{name}", addonsHandler.UninstallManagementAddon)

			r.Get("/addons/catalog", addonsHandler.GetCatalog)
			r.Get("/addons/catalog/{name}", addonsHandler.GetAddonDefinition)

			r.Get("/clusters", clusterHandler.List)
			r.Post("/clusters", clusterHandler.Create)
			r.Get("/clusters/{namespace}/{name}", clusterHandler.Get)
			r.Delete("/clusters/{namespace}/{name}", clusterHandler.Delete)
			r.Patch("/clusters/{namespace}/{name}/scale", clusterHandler.Scale)
			r.Get("/clusters/{namespace}/{name}/kubeconfig", clusterHandler.GetKubeconfig)
			r.Get("/clusters/{namespace}/{name}/nodes", clusterHandler.GetNodes)
			r.Get("/clusters/{namespace}/{name}/events", clusterHandler.GetEvents)

			r.Get("/clusters/{namespace}/{name}/addons", addonsHandler.ListClusterAddons)
			r.Post("/clusters/{namespace}/{name}/addons", addonsHandler.InstallAddon)
			r.Get("/clusters/{namespace}/{name}/addons/{addon}", addonsHandler.GetAddonDetails)
			r.Put("/clusters/{namespace}/{name}/addons/{addon}", addonsHandler.UpdateAddonValues)
			r.Delete("/clusters/{namespace}/{name}/addons/{addon}", addonsHandler.UninstallAddon)

			r.Get("/providers", providerHandler.List)
			r.Post("/providers", providerHandler.Create)
			r.Post("/providers/test", providerHandler.TestConnection)
			r.Get("/providers/{namespace}/{name}/images", providerHandler.ListImages)
			r.Get("/providers/{namespace}/{name}/networks", providerHandler.ListNetworks)
			r.Get("/providers/{namespace}/{name}", providerHandler.Get)
			r.Delete("/providers/{namespace}/{name}", providerHandler.Delete)
			r.Post("/providers/{namespace}/{name}/validate", providerHandler.Validate)
		})
	})

	r.Route("/ws", func(r chi.Router) {
		r.Get("/clusters", wsHub.HandleClusterWatch)
		r.Get("/terminal/management", wsHub.HandleManagementTerminal)
		r.Get("/terminal/{type}/{namespace}/{cluster}", wsHub.HandleTerminal)
		r.Get("/terminal/{type}/{namespace}/{cluster}/{pod}", wsHub.HandleTerminal)
		r.Get("/terminal/{type}/{namespace}/{cluster}/{pod}/{container}", wsHub.HandleTerminal)
	})

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		cfg.StaticHandler.ServeHTTP(w, r)
	})

	return r
}
