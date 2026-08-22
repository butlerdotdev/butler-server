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

	"github.com/butlerdotdev/butler-server/internal/auth"
)

func clusterOwnedBy(team string) *unstructured.Unstructured {
	obj := map[string]interface{}{"spec": map[string]interface{}{}}
	if team != "" {
		obj["spec"].(map[string]interface{})["teamRef"] = map[string]interface{}{"name": team}
	}
	return &unstructured.Unstructured{Object: obj}
}

func TestCheckClusterVisibility(t *testing.T) {
	alphaViewer := &auth.UserSession{Teams: []auth.TeamMembership{{Name: "alpha", Role: auth.RoleViewer}}}
	scopedToAlpha := &auth.UserSession{SelectedTeam: "alpha", Teams: alphaViewer.Teams}
	tests := []struct {
		name    string
		user    *auth.UserSession
		cluster *unstructured.Unstructured
		wantErr bool
	}{
		{"platform admin any team", &auth.UserSession{PlatformRole: auth.RoleAdmin}, clusterOwnedBy("beta"), false},
		{"platform admin team-less", &auth.UserSession{PlatformRole: auth.RoleAdmin}, clusterOwnedBy(""), false},
		{"member own team", alphaViewer, clusterOwnedBy("alpha"), false},
		{"member other team", alphaViewer, clusterOwnedBy("beta"), true},
		{"member team-less", alphaViewer, clusterOwnedBy(""), true},
		{"scoped own team", scopedToAlpha, clusterOwnedBy("alpha"), false},
		{"scoped other team", scopedToAlpha, clusterOwnedBy("beta"), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkClusterVisibility(tt.user, tt.cluster)
			if (err != nil) != tt.wantErr {
				t.Fatalf("checkClusterVisibility error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
