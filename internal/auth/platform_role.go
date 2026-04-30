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

package auth

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic"
)

// LoadPlatformRoleGroups reads the IdentityProvider CRD and returns its
// spec.platformRoleGroups entries. Returns nil (not an error) if the CRD
// has no platformRoleGroups configured or if the CRD is not found.
func LoadPlatformRoleGroups(ctx context.Context, client dynamic.Interface, idpName string) []PlatformRoleGroupEntry {
	if client == nil || idpName == "" {
		return nil
	}

	idp, err := client.Resource(IdentityProviderGVR).Get(ctx, idpName, metav1.GetOptions{})
	if err != nil {
		return nil
	}

	return parsePlatformRoleGroups(idp)
}

// LoadAllPlatformRoleGroups reads all IdentityProvider CRDs and returns
// the platformRoleGroups from whichever one is configured. For single-IdP
// deployments this returns the one IdP's groups. For multi-IdP setups,
// callers should use LoadPlatformRoleGroups with a specific name.
//
// Today butler-server supports a single OIDC provider, so merging across
// all CRDs is safe. If multi-IdP support is added, this function should
// be replaced with per-provider loading to preserve IdP isolation.
func LoadAllPlatformRoleGroups(ctx context.Context, client dynamic.Interface) []PlatformRoleGroupEntry {
	if client == nil {
		return nil
	}

	list, err := client.Resource(IdentityProviderGVR).List(ctx, metav1.ListOptions{})
	if err != nil || len(list.Items) == 0 {
		return nil
	}

	// Merge from all IdPs; in practice most deployments have one.
	var all []PlatformRoleGroupEntry
	for i := range list.Items {
		all = append(all, parsePlatformRoleGroups(&list.Items[i])...)
	}
	return all
}

// parsePlatformRoleGroups extracts platformRoleGroups from an unstructured
// IdentityProvider object.
func parsePlatformRoleGroups(idp *unstructured.Unstructured) []PlatformRoleGroupEntry {
	groups, found, err := unstructured.NestedSlice(idp.Object, "spec", "platformRoleGroups")
	if err != nil || !found || len(groups) == 0 {
		return nil
	}

	var entries []PlatformRoleGroupEntry
	for _, g := range groups {
		entry, ok := g.(map[string]interface{})
		if !ok {
			continue
		}
		name, _ := entry["name"].(string)
		role, _ := entry["role"].(string)
		if name != "" && role != "" {
			entries = append(entries, PlatformRoleGroupEntry{Name: name, Role: role})
		}
	}
	return entries
}

// PlatformRoleGroupEntry maps an IdP group to a platform-wide role.
// This mirrors the butler-api type for use in session-level resolution
// without requiring a direct import of the CRD types at the auth layer.
type PlatformRoleGroupEntry struct {
	Name string
	Role string
}

// ResolvePlatformRole determines the effective platform role for a user
// based on their IdP group memberships and the IdentityProvider's
// platformRoleGroups configuration. Returns the highest matching role
// ("admin" > "viewer" > ""). Group matching uses the same normalization
// as Team.spec.access.groups: LDAP DN, email-style, and plain names are
// all supported.
//
// See ADR-014 for the full platform role model.
func ResolvePlatformRole(userGroups []string, platformRoleGroups []PlatformRoleGroupEntry) string {
	if len(userGroups) == 0 || len(platformRoleGroups) == 0 {
		return ""
	}

	groupSet := buildGroupLookupSet(userGroups)
	highest := ""
	for _, entry := range platformRoleGroups {
		if matchGroup(entry.Name, groupSet) {
			highest = HighestRole([]string{highest, entry.Role})
		}
	}
	return highest
}

// EffectivePlatformRole computes the effective platform role from a
// manually-set CRD role, the deprecated isPlatformAdmin bool, and an
// IdP group-derived role. The highest of the three wins. This is the
// single place where all platform role sources merge into one value.
func EffectivePlatformRole(crdPlatformRole string, isPlatformAdmin bool, groupRole string) string {
	roles := []string{crdPlatformRole, groupRole}
	if isPlatformAdmin {
		roles = append(roles, RoleAdmin)
	}
	return HighestRole(roles)
}

// matchGroup checks if a configured group name matches any entry in the
// user's group lookup set. Uses the same normalization as
// TeamResolver.groupMatches: normalized (domain-stripped, CN-extracted)
// and exact (lowercased) comparisons.
func matchGroup(configuredGroup string, groupSet map[string]bool) bool {
	if groupSet[normalizeGroupName(configuredGroup)] {
		return true
	}
	if groupSet[strings.ToLower(configuredGroup)] {
		return true
	}
	return false
}
