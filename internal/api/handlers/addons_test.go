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

package handlers

import (
	"encoding/json"
	"testing"
)

// InstalledAddonResponse JSON contract tests.
//
// These verify the API shape that butler-console and other consumers
// depend on. The Addon field was added to distinguish the canonical
// AddonDefinition name from the K8s metadata name, which differ for
// auto-enrolled TenantAddons.

func TestInstalledAddonResponse_AutoEnrolled(t *testing.T) {
	// Auto-enrolled TenantAddons have metadata names like <cluster>-<addon>
	// but spec.addon is the canonical AddonDefinition name.
	resp := InstalledAddonResponse{
		Name:      "obs-perf-dev-vector-agent",
		Addon:     "vector-agent",
		Status:    "installed",
		ManagedBy: "butler",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded["name"] != "obs-perf-dev-vector-agent" {
		t.Errorf("name = %q, want %q", decoded["name"], "obs-perf-dev-vector-agent")
	}
	if decoded["addon"] != "vector-agent" {
		t.Errorf("addon = %q, want %q", decoded["addon"], "vector-agent")
	}
}

func TestInstalledAddonResponse_ManuallyNamed(t *testing.T) {
	// Manually-created TenantAddons can have any metadata name.
	// Addon still reflects the AddonDefinition name from spec.addon.
	resp := InstalledAddonResponse{
		Name:      "my-custom-name",
		Addon:     "vector-agent",
		Status:    "installed",
		ManagedBy: "butler",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded["name"] != "my-custom-name" {
		t.Errorf("name = %q, want %q", decoded["name"], "my-custom-name")
	}
	if decoded["addon"] != "vector-agent" {
		t.Errorf("addon = %q, want %q", decoded["addon"], "vector-agent")
	}
}

func TestInstalledAddonResponse_BackwardsCompat(t *testing.T) {
	// Existing consumers that only read the Name field should be unaffected.
	// When Addon is empty, omitempty ensures it's absent from the JSON.
	resp := InstalledAddonResponse{
		Name:   "vector-agent",
		Status: "installed",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded["name"] != "vector-agent" {
		t.Errorf("name = %q, want %q", decoded["name"], "vector-agent")
	}
	if _, exists := decoded["addon"]; exists {
		t.Error("addon field should be omitted when empty")
	}
}

func TestInstalledAddonResponse_PlatformManaged(t *testing.T) {
	// Platform-managed addons from observedState have Name == Addon.
	resp := InstalledAddonResponse{
		Name:      "cilium",
		Addon:     "cilium",
		Status:    "installed",
		ManagedBy: "platform",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]interface{}
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if decoded["name"] != "cilium" {
		t.Errorf("name = %q, want %q", decoded["name"], "cilium")
	}
	if decoded["addon"] != "cilium" {
		t.Errorf("addon = %q, want %q", decoded["addon"], "cilium")
	}
}
