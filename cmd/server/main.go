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

package main

import (
	"context"
	"flag"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/butlerdotdev/butler-server/internal/api"
	"github.com/butlerdotdev/butler-server/internal/config"
	"github.com/butlerdotdev/butler-server/internal/k8s"
	"github.com/butlerdotdev/butler-server/internal/static"

	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Build information set via ldflags.
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	var (
		addr        string
		kubeconfig  string
		devMode     bool
		showVersion bool
	)

	flag.StringVar(&addr, "addr", ":8080", "Server listen address")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (uses in-cluster config if not specified)")
	flag.BoolVar(&devMode, "dev", false, "Enable development mode (CORS, verbose logging)")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	flag.Parse()

	if showVersion {
		slog.Info("Butler Server", "version", version, "commit", commit, "buildTime", buildTime)
		os.Exit(0)
	}

	logLevel := slog.LevelInfo
	if devMode {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel}))
	slog.SetDefault(logger)

	slog.Info("Starting Butler Server", "version", version, "addr", addr, "dev", devMode)

	cfg := config.Load()

	restConfig, err := buildRESTConfig(kubeconfig)
	if err != nil {
		slog.Error("Failed to create Kubernetes config", "error", err)
		os.Exit(1)
	}

	k8sClient, err := k8s.NewClient(restConfig)
	if err != nil {
		slog.Error("Failed to create Kubernetes client", "error", err)
		os.Exit(1)
	}

	staticHandler := createStaticHandler(devMode)

	router := api.NewRouter(api.RouterConfig{
		K8sClient:     k8sClient,
		Config:        cfg,
		DevMode:       devMode,
		StaticHandler: staticHandler,
		Logger:        logger,
	})

	// Create listener first to fail fast on port conflicts
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("Failed to bind address", "addr", addr, "error", err)
		os.Exit(1)
	}

	server := &http.Server{
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		slog.Info("Server listening", "addr", addr)
		if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
			slog.Error("Server failed", "error", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("Shutting down server...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		slog.Error("Server forced to shutdown", "error", err)
	}

	slog.Info("Server exited")
}

func buildRESTConfig(kubeconfig string) (*rest.Config, error) {
	if kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}
	return rest.InClusterConfig()
}

func createStaticHandler(devMode bool) http.Handler {
	if devMode {
		return http.FileServer(http.Dir("./internal/static/files"))
	}

	subFS, err := fs.Sub(static.FS, "files")
	if err != nil {
		slog.Error("Failed to create static file system", "error", err)
		os.Exit(1)
	}
	return http.FileServer(http.FS(subFS))
}
