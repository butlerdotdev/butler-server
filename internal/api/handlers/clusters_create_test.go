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

func boolPtr(b bool) *bool { return &b }

func TestCreateClusterRequest_IngressEnabled_Unmarshal(t *testing.T) {
	tests := []struct {
		name     string
		payload  string
		wantNil  bool
		wantVal  bool
	}{
		{
			name:    "field omitted defaults to nil",
			payload: `{"name":"test","providerConfigRef":"pc"}`,
			wantNil: true,
		},
		{
			name:    "explicit false",
			payload: `{"name":"test","providerConfigRef":"pc","ingressEnabled":false}`,
			wantNil: false,
			wantVal: false,
		},
		{
			name:    "explicit true",
			payload: `{"name":"test","providerConfigRef":"pc","ingressEnabled":true}`,
			wantNil: false,
			wantVal: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req CreateClusterRequest
			if err := json.Unmarshal([]byte(tt.payload), &req); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			if tt.wantNil {
				if req.IngressEnabled != nil {
					t.Errorf("IngressEnabled = %v, want nil", *req.IngressEnabled)
				}
			} else {
				if req.IngressEnabled == nil {
					t.Fatal("IngressEnabled = nil, want non-nil")
				}
				if *req.IngressEnabled != tt.wantVal {
					t.Errorf("IngressEnabled = %v, want %v", *req.IngressEnabled, tt.wantVal)
				}
			}
		})
	}
}

func TestCreateClusterRequest_IngressEnabled_SpecBuilding(t *testing.T) {
	// Mirrors the spec-building logic in Create() for the ingress field.
	buildIngressSpec := func(req *CreateClusterRequest) map[string]interface{} {
		spec := map[string]interface{}{}
		if req.IngressEnabled != nil && !*req.IngressEnabled {
			addonsMap, _ := spec["addons"].(map[string]interface{})
			if addonsMap == nil {
				addonsMap = map[string]interface{}{}
			}
			addonsMap["ingress"] = map[string]interface{}{
				"enabled": false,
			}
			spec["addons"] = addonsMap
		}
		return spec
	}

	tests := []struct {
		name          string
		req           CreateClusterRequest
		expectAddons  bool
		expectIngress bool
	}{
		{
			name:          "nil does not set addons",
			req:           CreateClusterRequest{IngressEnabled: nil},
			expectAddons:  false,
			expectIngress: false,
		},
		{
			name:          "true does not set addons",
			req:           CreateClusterRequest{IngressEnabled: boolPtr(true)},
			expectAddons:  false,
			expectIngress: false,
		},
		{
			name:          "false sets addons.ingress.enabled=false",
			req:           CreateClusterRequest{IngressEnabled: boolPtr(false)},
			expectAddons:  true,
			expectIngress: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := buildIngressSpec(&tt.req)

			addonsRaw, hasAddons := spec["addons"]
			if hasAddons != tt.expectAddons {
				t.Fatalf("spec has addons = %v, want %v", hasAddons, tt.expectAddons)
			}
			if !tt.expectAddons {
				return
			}

			addonsMap, ok := addonsRaw.(map[string]interface{})
			if !ok {
				t.Fatal("spec[addons] is not a map")
			}

			ingressRaw, hasIngress := addonsMap["ingress"]
			if hasIngress != tt.expectIngress {
				t.Fatalf("addons has ingress = %v, want %v", hasIngress, tt.expectIngress)
			}
			if !tt.expectIngress {
				return
			}

			ingressMap, ok := ingressRaw.(map[string]interface{})
			if !ok {
				t.Fatal("addons[ingress] is not a map")
			}

			enabled, ok := ingressMap["enabled"]
			if !ok {
				t.Fatal("ingress missing enabled field")
			}
			if enabled != false {
				t.Errorf("ingress.enabled = %v, want false", enabled)
			}
		})
	}
}
