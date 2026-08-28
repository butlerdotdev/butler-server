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

func providerWithScope(name, scopeType, teamRef string) unstructured.Unstructured {
	spec := map[string]interface{}{"provider": "harvester"}
	if scopeType != "" {
		scope := map[string]interface{}{"type": scopeType}
		if teamRef != "" {
			scope["teamRef"] = map[string]interface{}{"name": teamRef}
		}
		spec["scope"] = scope
	}
	return unstructured.Unstructured{Object: map[string]interface{}{
		"metadata": map[string]interface{}{"name": name},
		"spec":     spec,
	}}
}

func names(items []map[string]interface{}) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		md, _ := item["metadata"].(map[string]interface{})
		n, _ := md["name"].(string)
		out = append(out, n)
	}
	return out
}

func TestProvidersVisibleToTeam(t *testing.T) {
	items := []unstructured.Unstructured{
		providerWithScope("unscoped", "", ""),
		providerWithScope("platform", "platform", ""),
		providerWithScope("ours", "team", "platform-engineering"),
		providerWithScope("theirs", "team", "data"),
		providerWithScope("team-without-ref", "team", ""),
	}

	got := names(providersVisibleToTeam(items, "platform-engineering"))
	want := []string{"unscoped", "platform", "ours"}
	if len(got) != len(want) {
		t.Fatalf("visible = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("visible = %v, want %v", got, want)
		}
	}
}

func TestProvidersVisibleToTeam_OtherTeamSeesOnlyPlatform(t *testing.T) {
	items := []unstructured.Unstructured{
		providerWithScope("platform", "platform", ""),
		providerWithScope("ours", "team", "platform-engineering"),
	}

	got := names(providersVisibleToTeam(items, "data"))
	if len(got) != 1 || got[0] != "platform" {
		t.Fatalf("visible to data = %v, want [platform]", got)
	}
}

func TestProvidersVisibleToTeam_Empty(t *testing.T) {
	if got := providersVisibleToTeam(nil, "any"); len(got) != 0 {
		t.Fatalf("visible = %v, want empty", got)
	}
}
