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
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// The update handler writes the OIDC map back with SetNestedMap, which
// deep-copies its argument. A Go []string is not a JSON-shaped value and
// made that deep copy panic, so every update carrying scopes failed with
// an empty 500. The converted form must survive the same call.
func TestUpdateScopesSurviveSetNestedMap(t *testing.T) {
	obj := map[string]interface{}{
		"spec": map[string]interface{}{
			"oidc": map[string]interface{}{"issuerURL": "https://issuer.example"},
		},
	}
	oidc, _, _ := unstructured.NestedMap(obj, "spec", "oidc")
	oidc["scopes"] = toUnstructuredStrings([]string{"openid", "email"})

	if err := unstructured.SetNestedMap(obj, oidc, "spec", "oidc"); err != nil {
		t.Fatalf("SetNestedMap with converted scopes: %v", err)
	}
	got, found, err := unstructured.NestedStringSlice(obj, "spec", "oidc", "scopes")
	if err != nil || !found {
		t.Fatalf("scopes not readable back: found=%v err=%v", found, err)
	}
	if len(got) != 2 || got[0] != "openid" || got[1] != "email" {
		t.Fatalf("scopes round trip: %v", got)
	}
}

func TestRawStringSliceBreaksSetNestedMap(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatalf("expected the deep copy of a raw []string to panic; if this no longer panics the conversion helper can go")
		}
	}()
	obj := map[string]interface{}{"spec": map[string]interface{}{}}
	_ = unstructured.SetNestedMap(obj, map[string]interface{}{"scopes": []string{"openid"}}, "spec", "oidc")
}

func TestToUnstructuredStringsEmpty(t *testing.T) {
	if got := toUnstructuredStrings(nil); len(got) != 0 {
		t.Fatalf("expected empty, got %v", got)
	}
}
