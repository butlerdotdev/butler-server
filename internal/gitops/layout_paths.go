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
	// ADR-017 D4: tenant operator namespaces. Used by the scope-tiered
	// default placement (PathForNativeWithDefault) to route namespaced
	// infra-shaped resources (Deployment, ServiceAccount, RBAC) in these
	// namespaces to infrastructure/configs/ rather than apps/<env>/workloads/.
	"keda-system":    true,
	"strimzi-system": true,
	"reflector":      true,
	"observability":  true,
}

// clusterScopedInfraKinds enumerates kinds that, when discovered via the
// inventory walk and not matched by a specific entry in PathForNative,
// default to infrastructure/configs/<sanitized-group>/<kind>/<name>.yaml.
// ADR-017 D4 scope-tiered default placement — the capi-steward case is
// the test: its CRDs + ClusterRoles + ClusterRoleBindings land here, not
// in apps/<env>/workloads/.
var clusterScopedInfraKinds = map[string]bool{
	"CustomResourceDefinition":        true,
	"ClusterRole":                     true,
	"ClusterRoleBinding":              true,
	"ValidatingWebhookConfiguration":  true,
	"MutatingWebhookConfiguration":    true,
	"APIService":                      true,
	"PriorityClass":                   true,
	"RuntimeClass":                    true,
	"IngressClass":                    true,
	"MutatingAdmissionPolicy":         true,
	"ValidatingAdmissionPolicy":       true,
	"StorageClass":                    true,
}

// namespacedInfraKinds enumerates kinds that, when in an
// infrastructureNamespaces entry, default to infrastructure/configs/...
// Mostly controller-machinery shapes (deployments, RBAC, configmaps
// adjacent to a controller).
var namespacedInfraKinds = map[string]bool{
	"Deployment":     true,
	"ServiceAccount": true,
	"Role":           true,
	"RoleBinding":    true,
	"Service":        true,
	"ConfigMap":      true,
	"NetworkPolicy":  true,
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
// Returns empty string for kinds that have no specific placement rule —
// callers should consult PathForNativeWithDefault to route those through the
// scope-tiered default placement (ADR-017 D4).
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
	// ADR-017 D4 — tenant-relevant kinds.
	case "ClusterIssuer":
		return fmt.Sprintf("infrastructure/configs/cluster-issuers/%s.yaml", n.Name)
	case "StorageClass":
		return fmt.Sprintf("infrastructure/configs/storage-classes/%s.yaml", n.Name)
	case "Kafka", "KafkaNodePool", "KafkaTopic", "KafkaUser", "KafkaConnect":
		return fmt.Sprintf("apps/%s/workloads/strimzi/%s/%s-%s.yaml", env, n.Kind, n.Namespace, n.Name)
	case "ScaledObject", "ScaledJob", "TriggerAuthentication":
		return fmt.Sprintf("apps/%s/workloads/keda/%s/%s-%s.yaml", env, n.Kind, n.Namespace, n.Name)
	}
	return ""
}

// PathForNativeWithDefault returns a path for any DiscoveredNative,
// using PathForNative's explicit table first, then the ADR-017 D4
// scope-tiered default placement for kinds with no specific entry.
//
// The default placement avoids the single-bucket misplacement ADR-017
// revision 2 caught: a unified apps/<env>/workloads/ bucket would route
// capi-steward's CRDs + ClusterRoles + Deployment to apps/workloads,
// which is wrong — they're infrastructure. Tiered placement:
//
//   - Cluster-scoped infra kinds (CRDs, ClusterRole, ClusterRoleBinding,
//     ValidatingWebhookConfiguration, MutatingWebhookConfiguration,
//     APIService, PriorityClass, RuntimeClass, IngressClass, StorageClass,
//     Admission*Policy) → infrastructure/configs/<group>/<kind>/<name>.yaml
//   - Namespaced infra kinds (Deployment, ServiceAccount, Role,
//     RoleBinding, Service, ConfigMap, NetworkPolicy) in known infra
//     namespaces → infrastructure/configs/<group>/<kind>/<ns>-<name>.yaml
//   - Anything else (namespaced user-workload-shaped) →
//     apps/<env>/workloads/<group>/<kind>/<ns>-<name>.yaml
//
// The capi-steward case (9 raw resources from butler-crop-live-infra's
// hand-rolled infrastructure/controllers/capi-steward.yaml) lands in
// infrastructure/configs/<group>/<kind>/... under this rule, not in
// apps/<env>/workloads/.
func PathForNativeWithDefault(n *DiscoveredNative, env string) string {
	if p := PathForNative(n, env); p != "" {
		return p
	}
	group := apiGroup(n.APIVersion)
	groupSeg := sanitizeGroupSegment(group)
	if clusterScopedInfraKinds[n.Kind] {
		return fmt.Sprintf("infrastructure/configs/%s/%s/%s.yaml", groupSeg, n.Kind, n.Name)
	}
	if n.Namespace != "" && infrastructureNamespaces[n.Namespace] && namespacedInfraKinds[n.Kind] {
		return fmt.Sprintf("infrastructure/configs/%s/%s/%s-%s.yaml", groupSeg, n.Kind, n.Namespace, n.Name)
	}
	return fmt.Sprintf("apps/%s/workloads/%s/%s/%s-%s.yaml", env, groupSeg, n.Kind, n.Namespace, n.Name)
}

// apiGroup extracts the API group from an apiVersion string. Returns
// "core" for core/v1 (no slash). Used by the default-placement segmenter.
func apiGroup(apiVersion string) string {
	if apiVersion == "" {
		return "core"
	}
	idx := -1
	for i, c := range apiVersion {
		if c == '/' {
			idx = i
			break
		}
	}
	if idx < 0 {
		return "core"
	}
	return apiVersion[:idx]
}

// sanitizeGroupSegment converts an API group into a path-segment-safe
// directory name. Replaces dots with hyphens so the path doesn't have
// hidden filesystem semantics; preserves the group identity so the
// output is auditable (e.g. "cert-manager.io" → "cert-manager-io",
// "apiextensions.k8s.io" → "apiextensions-k8s-io").
func sanitizeGroupSegment(group string) string {
	if group == "" {
		return "core"
	}
	out := make([]byte, 0, len(group))
	for i := 0; i < len(group); i++ {
		c := group[i]
		if c == '.' {
			out = append(out, '-')
			continue
		}
		out = append(out, c)
	}
	return string(out)
}
