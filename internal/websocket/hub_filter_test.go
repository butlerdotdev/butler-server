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

package websocket

import (
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestClientCanReceiveCluster(t *testing.T) {
	admin := &Client{seesAllClusters: true, isPlatformAdmin: true}
	viewer := &Client{seesAllClusters: true}
	alphaMember := &Client{teams: []string{"alpha"}}
	nobody := &Client{}

	update := func(team string) Message {
		return Message{Type: MessageTypeClusterUpdate, team: team}
	}
	del := func(team string) Message {
		return Message{Type: MessageTypeClusterDelete, team: team}
	}

	tests := []struct {
		name string
		c    *Client
		m    Message
		want bool
	}{
		{"admin sees any team", admin, update("beta"), true},
		{"admin sees team-less", admin, update(""), true},
		{"viewer sees any team", viewer, del("beta"), true},
		{"member sees own team update", alphaMember, update("alpha"), true},
		{"member sees own team delete", alphaMember, del("alpha"), true},
		{"member blocked from other team", alphaMember, update("beta"), false},
		{"member blocked from team-less", alphaMember, update(""), false},
		{"no memberships blocked", nobody, update("alpha"), false},
		{"pong passes through", nobody, Message{Type: MessageTypePong}, true},
		{"notification routed elsewhere", nobody, Message{Type: MessageTypeNotification}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := clientCanReceiveCluster(tt.c, tt.m); got != tt.want {
				t.Fatalf("clientCanReceiveCluster = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestClusterTeam(t *testing.T) {
	withTeam := &unstructured.Unstructured{Object: map[string]interface{}{
		"spec": map[string]interface{}{"teamRef": map[string]interface{}{"name": "alpha"}},
	}}
	if got := clusterTeam(withTeam); got != "alpha" {
		t.Fatalf("clusterTeam = %q, want alpha", got)
	}
	if got := clusterTeam(&unstructured.Unstructured{Object: map[string]interface{}{}}); got != "" {
		t.Fatalf("clusterTeam without teamRef = %q, want empty", got)
	}
	if got := clusterTeam("not an object"); got != "" {
		t.Fatalf("clusterTeam on non-unstructured = %q, want empty", got)
	}
}
