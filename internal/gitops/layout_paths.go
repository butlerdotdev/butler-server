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
// release that has no matching AddonDefinition.
//
// Order of signals (ADR-017 D2):
//
//  1. ChartInstallsCRDs — if the chart bundles CRDs (either in crds/ or
//     via templates containing kind: CustomResourceDefinition), the
//     chart is necessarily infrastructure-tier: it provides types other
//     workloads consume; placing it in apps/base/ breaks Flux dependsOn
//     ordering. This signal is robust to namespace choice — catches
//     tenant operators like kube-prometheus-stack, strimzi-kafka-operator,
//     cert-manager, longhorn whose charts install CRDs in non-heuristic
//     namespaces.
//  2. Namespace heuristic (ADR-016 D-A.1) — well-known controller
//     namespaces map to infrastructure. Catches charts that don't
//     install CRDs but are placed in known infra namespaces.
//  3. Default — apps. A user-installed chart targeting a custom
//     namespace with no CRDs in its chart falls here; recoverable on
//     operator review of the export output.
//
// Takes the full DiscoveredRelease so the chart-CRD signal is available;
// the previous targetNamespace-only signature is no longer sufficient
// for the tenant case where namespace alone mis-tiers operators.
func classifyUnmatchedRelease(rel *DiscoveredRelease) string {
	if rel == nil {
		return TierApps
	}
	if rel.ChartInstallsCRDs {
		return TierInfrastructure
	}
	if infrastructureNamespaces[rel.Namespace] {
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
	case "Team":
		return fmt.Sprintf("apps/%s/teams/%s.yaml", env, n.Name)
	}
	return ""
}
