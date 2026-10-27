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

func teamCluster(team string) *unstructured.Unstructured {
	spec := map[string]interface{}{}
	if team != "" {
		spec["teamRef"] = map[string]interface{}{"name": team}
	}
	return &unstructured.Unstructured{Object: map[string]interface{}{"spec": spec}}
}

// An admin of team alpha with no platform role. Before this change
// IsAdmin() made this session pass every no-header check.
func alphaAdmin() *auth.UserSession {
	return &auth.UserSession{Teams: []auth.TeamMembership{{Name: "alpha", Role: auth.RoleAdmin}}}
}

func TestNoHeaderChecks_TeamAdminIsNotPlatformAdmin(t *testing.T) {
	ch := &ClusterHandler{}
	ah := &AddonsHandler{}
	gh := &GitOpsHandler{}
	certs := &CertificateHandler{}
	user := alphaAdmin()

	if err := ch.checkClusterAccess(user, teamCluster("alpha")); err != nil {
		t.Fatalf("own-team visibility: %v", err)
	}
	if err := ch.checkClusterAccess(user, teamCluster("beta")); err == nil {
		t.Fatal("team admin of alpha could see beta's cluster")
	}
	if err := ch.checkOperatePermission(user, "beta", "delete"); err == nil {
		t.Fatal("team admin of alpha could operate on beta")
	}
	if err := ch.checkOperatePermission(user, "alpha", "delete"); err != nil {
		t.Fatalf("own-team operate: %v", err)
	}
	if err := ah.checkOperatePermission(user, teamCluster("beta"), "install"); err == nil {
		t.Fatal("team admin of alpha could install addons on beta")
	}
	if err := gh.checkOperatePermission(user, teamCluster("beta"), "enable"); err == nil {
		t.Fatal("team admin of alpha could enable gitops on beta")
	}
	if err := certs.checkClusterAccess(user, teamCluster("beta")); err == nil {
		t.Fatal("team admin of alpha could read beta's certificates")
	}
	if certs.canRotateCertificates(user, teamCluster("beta")) {
		t.Fatal("team admin of alpha could rotate beta's certificates")
	}
	if !certs.canRotateCertificates(user, teamCluster("alpha")) {
		t.Fatal("team admin of alpha should rotate alpha's certificates")
	}
}

func TestNoHeaderChecks_PlatformRoles(t *testing.T) {
	ch := &ClusterHandler{}
	certs := &CertificateHandler{}
	admin := &auth.UserSession{PlatformRole: auth.RoleAdmin}
	viewer := &auth.UserSession{PlatformRole: auth.RoleViewer}

	if err := ch.checkClusterAccess(viewer, teamCluster("beta")); err != nil {
		t.Fatalf("platform viewer visibility: %v", err)
	}
	if err := ch.checkOperatePermission(viewer, "beta", "scale"); err == nil {
		t.Fatal("platform viewer could operate")
	}
	if err := ch.checkOperatePermission(admin, "", "scale"); err != nil {
		t.Fatalf("platform admin operate on team-less cluster: %v", err)
	}
	if err := certs.checkClusterAccess(viewer, teamCluster("beta")); err != nil {
		t.Fatalf("platform viewer certificate read: %v", err)
	}
	if certs.canRotateCertificates(viewer, teamCluster("beta")) {
		t.Fatal("platform viewer could rotate certificates")
	}
	if !certs.canRotateCA(admin, teamCluster("")) {
		t.Fatal("platform admin should rotate CA of team-less cluster")
	}
}
