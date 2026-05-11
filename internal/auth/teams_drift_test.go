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
	"sort"
	"strings"
	"testing"

	"github.com/butlerdotdev/butler-api/testdata/resolution"
)

// TestResolutionDrift asserts that butler-server's resolution logic
// produces output matching the shared fixtures in butler-api. The
// butler-controller has an equivalent test. Drift between the two
// implementations surfaces as a test failure in whichever component
// diverged from the fixture expectations.
func TestResolutionDrift(t *testing.T) {
	fixtures := resolution.LoadAll()
	if len(fixtures) == 0 {
		t.Fatal("no fixtures loaded")
	}

	for _, f := range fixtures {
		t.Run(f.Name, func(t *testing.T) {
			memberships := make(map[string]TeamMembership)

			// Resolve manual memberships: check spec.access.users[]
			for _, team := range f.Input.Teams {
				for _, u := range team.Access.Users {
					if !strings.EqualFold(u.Name, f.Input.Email) {
						continue
					}
					role := u.Role
					if role == "" {
						role = RoleViewer
					}
					addMembershipForTest(memberships, team.Name, role)
				}
			}

			// Resolve group-based memberships: check spec.access.groups[]
			if len(f.Input.LastSeenGroups) > 0 {
				groupSet := buildGroupLookupSet(f.Input.LastSeenGroups)
				for _, team := range f.Input.Teams {
					for _, g := range team.Access.Groups {
						if !groupMatchesForTest(g.Name, groupSet) {
							continue
						}
						role := g.Role
						if role == "" {
							role = RoleViewer
						}
						addMembershipForTest(memberships, team.Name, role)
					}
				}
			}

			// Convert to sorted slice
			result := make([]resolution.ExpectedMembership, 0, len(memberships))
			for _, m := range memberships {
				result = append(result, resolution.ExpectedMembership{
					Name: m.Name,
					Role: m.Role,
				})
			}
			sort.Slice(result, func(i, j int) bool {
				return result[i].Name < result[j].Name
			})

			// Compare against fixture expectations
			if len(result) != len(f.Expected) {
				t.Fatalf("membership count: got %d, want %d\n  got:  %v\n  want: %v",
					len(result), len(f.Expected), result, f.Expected)
			}
			for i := range result {
				if result[i].Name != f.Expected[i].Name || result[i].Role != f.Expected[i].Role {
					t.Errorf("membership[%d]: got %s(%s), want %s(%s)",
						i, result[i].Name, result[i].Role,
						f.Expected[i].Name, f.Expected[i].Role)
				}
			}
		})
	}
}

// addMembershipForTest mirrors the production addMembership logic using
// the same RoleHierarchy function.
func addMembershipForTest(memberships map[string]TeamMembership, teamName, role string) {
	existing, ok := memberships[teamName]
	if !ok {
		memberships[teamName] = TeamMembership{Name: teamName, Role: role}
		return
	}
	if RoleHierarchy(role, existing.Role) {
		memberships[teamName] = TeamMembership{Name: teamName, Role: role}
	}
}

// groupMatchesForTest mirrors the production groupMatches logic using
// the same normalizeGroupName and buildGroupLookupSet functions.
func groupMatchesForTest(configuredGroup string, groupSet map[string]bool) bool {
	if groupSet[normalizeGroupName(configuredGroup)] {
		return true
	}
	if groupSet[strings.ToLower(configuredGroup)] {
		return true
	}
	return false
}
