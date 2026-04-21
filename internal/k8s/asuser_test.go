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

package k8s

import (
	"testing"

	"k8s.io/client-go/rest"
)

// AsUser builds a per-request client whose rest.Config carries
// Kubernetes impersonation. The ADR-010 payload shape is pinned here
// because drift in the group set or user field would invalidate
// admission-webhook identity matching without causing a build break.

func TestAsUser_SetsImpersonationConfig(t *testing.T) {
	base := &Client{
		config: &rest.Config{Host: "https://apiserver.local"},
	}
	imp, err := base.AsUser("Alice@Example.COM")
	if err != nil {
		t.Fatalf("AsUser: %v", err)
	}
	if imp == base {
		t.Fatal("AsUser must return a new client, not the shared server-SA instance")
	}
	if imp.config.Impersonate.UserName != "Alice@Example.COM" {
		t.Errorf("UserName = %q, want verbatim email (canonicalization happens at session layer, not here)", imp.config.Impersonate.UserName)
	}
	groups := imp.config.Impersonate.Groups
	hasAPIGroup := false
	hasAuthenticated := false
	for _, g := range groups {
		if g == ButlerAPIUsersGroup {
			hasAPIGroup = true
		}
		if g == "system:authenticated" {
			hasAuthenticated = true
		}
	}
	if !hasAPIGroup {
		t.Errorf("Groups missing %q: %v", ButlerAPIUsersGroup, groups)
	}
	if !hasAuthenticated {
		t.Errorf("Groups missing system:authenticated: %v", groups)
	}
}

func TestAsUser_EmptyEmailReturnsSharedClient(t *testing.T) {
	base := &Client{config: &rest.Config{Host: "https://apiserver.local"}}
	imp, err := base.AsUser("")
	if err != nil {
		t.Fatalf("AsUser: %v", err)
	}
	if imp != base {
		t.Fatal("empty email should return the shared client, not a fresh one")
	}
}

func TestAsUser_DoesNotMutateBaseConfig(t *testing.T) {
	base := &Client{config: &rest.Config{Host: "https://apiserver.local"}}
	_, err := base.AsUser("alice@example.com")
	if err != nil {
		t.Fatalf("AsUser: %v", err)
	}
	if base.config.Impersonate.UserName != "" {
		t.Errorf("base config mutated: Impersonate.UserName = %q", base.config.Impersonate.UserName)
	}
}
