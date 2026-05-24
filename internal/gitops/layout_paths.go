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

import (
	"fmt"
	"strings"
)

// Layout v2 placement, corrected: discovery is agnostic; placement is
// opinionated by TIER (infra vs app, namespaced vs cluster-scoped) and
// derives the path from cluster-resolvable fields — no per-kind table.
//
// Three top-source verification (Flux canonical, onedr0p template,
// live tenant repo) established that no convention uses
// <group>/<kind>/ directories. The corrected rule is:
//
//   - Namespace kind → apps/<env>/<name>-namespace.yaml (flat). The
//     one ratified kind special-case, matching the live tenant repo's
//     apps/<env>/<name>-namespace.yaml and onedr0p's per-bundle
//     namespace.yaml conventions.
//
//   - All other kinds → <tier-base>/<group-short>/<filename>:
//       tier-base: infrastructure/configs (infra tier) or
//                  apps/<env> (app tier)
//       group-short: derived from API group via TLD strip
//                    (kafka.strimzi.io → strimzi, keda.sh → keda)
//       filename: namespaced → <kind-lower>-<namespace>-<name>.yaml
//                 cluster-scoped → <kind-lower>-<name>.yaml
//
// The asymmetry at the apps tier (no intermediate "workloads/" wrapper)
// vs. infra tier (where infrastructure/configs/<group-short>/ is the
// first grouping level) is intentional and matches three independent
// top sources (Flux canonical, onedr0p, live tenant repo). At the apps
// tier, apps/<env>/ IS the env scope and the bundle name <group-short>
// IS the operator signal — no additional wrapper repeats anything.
// At the infra tier there's no env context, so <group-short>/ is the
// first grouping level and carries load.
//
// Kind appears in the FILENAME, not the path. Namespace appears in
// the filename only when the kind is namespaced (cluster-derived from
// DiscoveredNative.IsNamespaced, populated by RESTMapper at fetch
// time). The verbose-but-always-unique namespaced filename closes
// the within-group within-kind cross-namespace collision class:
// watchAnyNamespace operators with same kind+name in two namespaces
// no longer silently overwrite to one path.

// infrastructureNamespaces classifies a target namespace as
// infrastructure-tier. Used by classifyUnmatchedRelease (Helm path)
// and classifyTier (native path).
var infrastructureNamespaces = map[string]bool{
	"flux-system":     true,
	"cert-manager":    true,
	"kube-system":     true,
	"longhorn-system": true,
	"metallb-system":  true,
	"traefik":         true,
	"butler-system":   true,
	"steward-system":  true,
	"keda-system":     true,
	"strimzi-system":  true,
	"reflector":       true,
	"observability":   true,
}

// Tier names used by the Helm path. Native path uses an internal
// tier classification (see classifyTier).
const (
	TierInfrastructure = "infrastructure"
	TierApps           = "apps"
)

// classifyUnmatchedRelease decides infrastructure vs apps for an
// unmatched Helm release (no AddonDefinition). Kept as-is from the
// Helm path; not affected by the native-path rule rewrite.
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

// nativeTier values returned by classifyNativeTier. Internal to
// layout placement — not exposed.
const (
	nativeTierNamespaceFlat = "namespace-flat"
	nativeTierInfra         = "infra"
	nativeTierApp           = "app"
)

// classifyNativeTier decides which placement tier a native item lands
// in. Three tiers, all derivable from cluster-resolvable signals
// (scope + namespace) plus the one ratified kind special-case:
//
//   - namespace-flat: the standalone Namespace kind (the one ratified
//     kind special-case). Routes to apps/<env>/<name>-namespace.yaml.
//   - infra: cluster-scoped (any kind) OR namespaced in a known
//     infrastructure namespace. Cluster-scoped → infra reflects the
//     reality that cluster-scoped CRs are almost always machinery
//     (CRDs, RBAC, StorageClass, ClusterIssuer, butler-platform
//     cluster CRs). Operator can move post-export if a specific
//     cluster-scoped CR belongs elsewhere.
//   - app: everything else (namespaced in a non-infra namespace).
//
// No kind-name table lookups. Scope from DiscoveredNative.IsNamespaced
// (RESTMapper-derived at fetch time); namespace from the object;
// one literal kind name ("Namespace") for the ratified special-case.
func classifyNativeTier(n *DiscoveredNative) string {
	if n == nil {
		return nativeTierApp
	}
	if n.Kind == "Namespace" {
		return nativeTierNamespaceFlat
	}
	if !n.IsNamespaced {
		return nativeTierInfra
	}
	if n.Namespace != "" && infrastructureNamespaces[n.Namespace] {
		return nativeTierInfra
	}
	return nativeTierApp
}

// PathForNative returns the layout path for a discovered native
// resource per the corrected D4 rule. See package-level doc comment
// for the full rule and rationale.
//
// Returns "" only for nil input. Every non-nil item produces a path.
func PathForNative(n *DiscoveredNative, env string) string {
	if n == nil {
		return ""
	}
	tier := classifyNativeTier(n)
	if tier == nativeTierNamespaceFlat {
		return fmt.Sprintf("apps/%s/%s-namespace.yaml", env, n.Name)
	}
	var base string
	if tier == nativeTierInfra {
		base = "infrastructure/configs"
	} else {
		base = fmt.Sprintf("apps/%s", env)
	}
	groupShort := groupShortFromAPIVersion(n.APIVersion)
	kindLower := strings.ToLower(n.Kind)
	var filename string
	if n.IsNamespaced && n.Namespace != "" {
		filename = fmt.Sprintf("%s-%s-%s.yaml", kindLower, n.Namespace, n.Name)
	} else {
		filename = fmt.Sprintf("%s-%s.yaml", kindLower, n.Name)
	}
	// Bare core/v1 objects (Service, ConfigMap, ServiceAccount, etc.)
	// emit FLAT at the tier base — the live convention places these
	// flat-by-purpose (often co-located with their app), never under a
	// generic "core/" wrapper. groupShortFromAPIVersion returns the
	// "core" sentinel for empty groups; PathForNative branches on it
	// to drop the subdir, the same way the Namespace special-case
	// produces a flat path. No kind lookup involved — group-string
	// signal only.
	if groupShort == "core" {
		return fmt.Sprintf("%s/%s", base, filename)
	}
	return fmt.Sprintf("%s/%s/%s", base, groupShort, filename)
}

// PathForNativeWithDefault is preserved as an alias of PathForNative
// for callers that referenced the previous explicit-table vs
// default-placement split. The unified rule covers all kinds; there
// is no longer a meaningful difference between the two functions.
func PathForNativeWithDefault(n *DiscoveredNative, env string) string {
	return PathForNative(n, env)
}

// groupShortFromAPIVersion derives the bundle identifier from a
// Kubernetes apiVersion string. Three classes, each derived from a
// stable group-string property:
//
//  1. Empty/core group (apiVersion="v1"): returns "core" as a
//     SENTINEL — callers must emit FLAT (no group-short subdir).
//     The live convention places bare-v1 objects (Service, ConfigMap,
//     ServiceAccount) flat-by-purpose at the tier base, never under
//     a generic "core/" bundle. The sentinel lets PathForNative
//     branch on this without inventing a kind check.
//
//  2. Group ends in ".k8s.io" (K8s API-machinery family): returns
//     the FIRST segment. storage.k8s.io → storage, rbac.authorization.k8s.io
//     → rbac, apiextensions.k8s.io → apiextensions, networking.k8s.io
//     → networking. The convention bundles k8s-machinery types by
//     PURPOSE (the first segment), not by operator — confirmed in the
//     live observability-pipeline-prd repo (infrastructure/storage/
//     for StorageClass). Distinct from operator-CR grouping, which
//     bundles by OPERATOR.
//
//  3. Operator/vendor groups (anything else with a dot, not
//     ".k8s.io"): returns the LAST segment before the TLD.
//     kafka.strimzi.io → strimzi (operator), keda.sh → keda,
//     cert-manager.io → cert-manager, butler.butlerlabs.dev →
//     butlerlabs. The OPERATOR is the bundle, matching how the live
//     tenant repos group these (apps/<env>/kafka/, apps/<env>/scaledobjects/).
//
// Single-segment groups (apps/v1, batch/v1) hit class 3 — last
// (only) segment returned as-is (apps, batch).
//
// The .k8s.io check is a group-STRING classification (stable
// derivable property of the API group), not a kind-name lookup.
// Grep-prove: this file has one kind literal ("Namespace" for the
// flat-path special-case) and zero kind tables. The .k8s.io check
// reflects the real convention difference between K8s API machinery
// (grouped by purpose) and operator CRs (grouped by operator), both
// observable in live repos.
func groupShortFromAPIVersion(apiVersion string) string {
	group := apiGroup(apiVersion)
	if group == "" || group == "core" {
		return "core"
	}
	if strings.HasSuffix(group, ".k8s.io") {
		return strings.SplitN(group, ".", 2)[0]
	}
	parts := strings.Split(group, ".")
	if len(parts) > 1 {
		parts = parts[:len(parts)-1]
	}
	return parts[len(parts)-1]
}

// apiGroup extracts the API group from an apiVersion string. Returns
// "core" for core/v1 (no slash). Internal helper.
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
