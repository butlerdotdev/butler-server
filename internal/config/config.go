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

package config

import (
	"os"
	"time"
)

// Config holds the server configuration.
type Config struct {
	Auth            AuthConfig
	TenantNamespace string
	SystemNamespace string
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	JWTSecret     string
	JWTExpiry     time.Duration
	AdminUsername string
	AdminPassword string
}

// Load loads configuration from environment variables.
func Load() *Config {
	return &Config{
		Auth: AuthConfig{
			JWTSecret:     getEnv("BUTLER_JWT_SECRET", "butler-dev-secret-change-me"),
			JWTExpiry:     24 * time.Hour,
			AdminUsername: getEnv("BUTLER_ADMIN_USERNAME", "admin"),
			AdminPassword: getEnv("BUTLER_ADMIN_PASSWORD", "admin"),
		},
		TenantNamespace: getEnv("BUTLER_TENANT_NAMESPACE", "butler-tenants"),
		SystemNamespace: getEnv("BUTLER_SYSTEM_NAMESPACE", "butler-system"),
	}
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
