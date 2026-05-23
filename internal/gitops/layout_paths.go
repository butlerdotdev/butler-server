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

package gitops

import "fmt"

// Per-kind placement rules for ADR-016 layout v2. Centralized here so the
// layout decisions are auditable in one table rather than scattered through
// the generator.

// infrastructureNamespaces is the set of targetNamespaces that classify an
// unmatched Helm release as infrastructure rather than apps. ADR-016
// subsection 3.2. Extend by adding a single line; the heuristic is intended
// to be cheap to maintain.
var infrastructureNamespaces = map[string]bool{
	"flux-system":     true,
	"cert-manager":    true,
	"kube-system":     true,
	"longhorn-system": true,
	"metallb-system":  true,
	"traefik":         true,
	"butler-system":   true,
	"steward-system":  true,
}

// Tier names used by layout v2. Matched releases get their tier from
// tierForAddon() (ADR-015); unmatched releases get their tier from
// classifyUnmatchedRelease() (ADR-016 subsection 3.2). Native resources
// have a hard-coded path per kind (subsection 3.3) and do not flow through
// this tier abstraction. The label set matches ADR-015's AddonTier enum —
// "infrastructure" releases land in infrastructure/controllers/<name>.yaml
// as a single consolidated file, "apps" releases land in
// apps/base/<name>/{repository,release,kustomization,optional namespace}.yaml.
const (
	TierInfrastructure = "infrastructure"
	TierApps           = "apps"
)

// classifyUnmatchedRelease decides infrastructure vs apps for a Helm
// release that has no matching AddonDefinition. The namespace heuristic
// is intentionally narrow: only the well-known controller namespaces map
// to infrastructure. A user-installed chart targeting a custom namespace
// falls to apps and is recoverable on operator review of the export
// output. See ADR-016 subsection 3.2 for the tradeoff that argued this
// over a HelmRelease annotation.
func classifyUnmatchedRelease(targetNamespace string) string {
	if infrastructureNamespaces[targetNamespace] {
		return TierInfrastructure
	}
	return TierApps
}

// PathForNative returns the v2 layout path for a discovered native resource.
// The env parameter is the apps overlay env (e.g. "prd"); it is only consumed
// by kinds placed under apps/<env>/.
//
// Returns empty string for kinds that have no v2 placement rule — caller
// must treat that as "skip this object" rather than fall through to a default,
// otherwise the prune-safety guarantee weakens (subsection 6.2). Any new
// discovery kind needs an explicit entry here.
func PathForNative(n *DiscoveredNative, env string) string {
	switch n.Kind {
	case "IdentityProvider":
		return fmt.Sprintf("infrastructure/configs/identity-providers/%s.yaml", n.Name)
	case "NetworkPool":
		return fmt.Sprintf("infrastructure/configs/network-pools/%s.yaml", n.Name)
	case "ProviderConfig":
		return fmt.Sprintf("infrastructure/configs/provider-configs/%s.yaml", n.Name)
	case "ClusterCreationPolicy":
		return fmt.Sprintf("infrastructure/configs/cluster-creation-policies/%s.yaml", n.Name)
	case "IPAddressPool", "L2Advertisement":
		return fmt.Sprintf("infrastructure/configs/metallb/%s.yaml", n.Name)
	case "SealedSecret":
		return fmt.Sprintf("infrastructure/configs/sealed-secrets/%s-%s.yaml", n.Namespace, n.Name)
	case "ConfigMap":
		if n.Name == "butler-gitops-config" {
			return "infrastructure/configs/butler-gitops-config.yaml"
		}
		return ""
	case "StewardControlPlane", "StewardControlPlaneTemplate":
		return fmt.Sprintf("infrastructure/configs/steward/%s.yaml", n.Name)
	case "Team":
		return fmt.Sprintf("apps/%s/teams/%s.yaml", env, n.Name)
	}
	return ""
}
