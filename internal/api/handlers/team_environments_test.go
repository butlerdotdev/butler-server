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

// envToUnstructured builds the map[string]interface{} payload that
// lands in Team.spec.environments[]. The shape is contract-pinned:
// unset limits fields must not emit zero caps, and the CRD's
// listMapKey=name relies on the name being present.

func int32Ptr(v int32) *int32 { return &v }

func TestEnvToUnstructured_NameOnly(t *testing.T) {
	env := envToUnstructured(&EnvironmentRequest{Name: "dev"})
	if env["name"] != "dev" {
		t.Fatalf("name = %v, want dev", env["name"])
	}
	if _, ok := env["limits"]; ok {
		t.Errorf("limits key should be absent when Limits is nil; got %v", env["limits"])
	}
}

func TestEnvToUnstructured_LimitsPresentButEmpty(t *testing.T) {
	env := envToUnstructured(&EnvironmentRequest{
		Name:   "dev",
		Limits: &EnvironmentLimits{},
	})
	if _, ok := env["limits"]; ok {
		t.Errorf("empty limits should emit no limits key; got %v", env["limits"])
	}
}

func TestEnvToUnstructured_OnlyMaxClusters(t *testing.T) {
	env := envToUnstructured(&EnvironmentRequest{
		Name:   "prod",
		Limits: &EnvironmentLimits{MaxClusters: int32Ptr(10)},
	})
	limits, ok := env["limits"].(map[string]interface{})
	if !ok {
		t.Fatalf("limits = %v, want map", env["limits"])
	}
	if limits["maxClusters"] != int64(10) {
		t.Errorf("maxClusters = %v, want int64(10)", limits["maxClusters"])
	}
	if _, ok := limits["maxClustersPerMember"]; ok {
		t.Errorf("maxClustersPerMember should be omitted when unset")
	}
}

func TestEnvToUnstructured_OnlyPerMember(t *testing.T) {
	env := envToUnstructured(&EnvironmentRequest{
		Name:   "sandbox",
		Limits: &EnvironmentLimits{MaxClustersPerMember: int32Ptr(1)},
	})
	limits, _ := env["limits"].(map[string]interface{})
	if limits["maxClustersPerMember"] != int64(1) {
		t.Errorf("maxClustersPerMember = %v, want int64(1)", limits["maxClustersPerMember"])
	}
	if _, ok := limits["maxClusters"]; ok {
		t.Errorf("maxClusters should be omitted when unset")
	}
}

func TestEnvToUnstructured_BothLimits(t *testing.T) {
	env := envToUnstructured(&EnvironmentRequest{
		Name: "dev",
		Limits: &EnvironmentLimits{
			MaxClusters:          int32Ptr(5),
			MaxClustersPerMember: int32Ptr(1),
		},
	})
	limits, _ := env["limits"].(map[string]interface{})
	if limits["maxClusters"] != int64(5) || limits["maxClustersPerMember"] != int64(1) {
		t.Errorf("limits = %v, want both fields populated", limits)
	}
}

// EnvironmentRequest round-trips through JSON without mutating semantics.
// Specifically, an omitted limits block in the JSON must land as a nil
// pointer, not as an empty struct with zeroed caps.
func TestEnvironmentRequest_JSONRoundTrip_OmittedLimits(t *testing.T) {
	raw := []byte(`{"name":"dev"}`)
	var req EnvironmentRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Name != "dev" {
		t.Errorf("name = %q, want dev", req.Name)
	}
	if req.Limits != nil {
		t.Errorf("limits = %+v, want nil", req.Limits)
	}
}

func TestEnvironmentRequest_JSONRoundTrip_ZeroLimits(t *testing.T) {
	// Explicit {"limits": {}} should decode as a non-nil pointer to an
	// empty struct so callers can distinguish "I set no caps" from "I
	// did not submit a limits block." envToUnstructured then elides the
	// limits key on empty structs so the CRD does not end up with an
	// empty map.
	raw := []byte(`{"name":"dev","limits":{}}`)
	var req EnvironmentRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if req.Limits == nil {
		t.Fatal("limits should be non-nil pointer when the key is present")
	}
	if req.Limits.MaxClusters != nil || req.Limits.MaxClustersPerMember != nil {
		t.Errorf("limits fields should be nil when unset; got %+v", req.Limits)
	}
}
