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

package audit

import (
	"net/http"
	"testing"
)

func TestIsAuditedRead(t *testing.T) {
	tests := []struct {
		method, path string
		want         bool
	}{
		{http.MethodGet, "/api/clusters/team-a/c1/kubeconfig", true},
		{http.MethodGet, "/api/clusters/team-a/c1/export", true},
		{http.MethodGet, "/api/clusters/team-a/c1", false},
		{http.MethodGet, "/api/clusters/team-a/c1/nodes", false},
		{http.MethodGet, "/api/management/nodes", false},
		{http.MethodPost, "/api/clusters/team-a/c1/kubeconfig", false},
	}
	for _, tt := range tests {
		if got := isAuditedRead(tt.method, tt.path); got != tt.want {
			t.Errorf("isAuditedRead(%s %s) = %v, want %v", tt.method, tt.path, got, tt.want)
		}
	}
}

func TestResolveActionForAuditedReads(t *testing.T) {
	if got := resolveAction(http.MethodGet, "/api/clusters/a/b/kubeconfig"); got != "download-kubeconfig" {
		t.Fatalf("resolveAction kubeconfig = %q", got)
	}
	if got := resolveAction(http.MethodGet, "/api/clusters/a/b/export"); got != "export" {
		t.Fatalf("resolveAction export = %q", got)
	}
	if got := resolveAction(http.MethodPatch, "/api/clusters/a/b/scale"); got != "scale" {
		t.Fatalf("resolveAction scale = %q", got)
	}
}
