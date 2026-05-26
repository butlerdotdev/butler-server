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

// infrastructureNamespaces is the set classifyNativeTier treats as
// infrastructure-tier for native CR placement. CRs in any of these
// land in infrastructure/configs/.
//
// Includes butler-system/steward-system/keda-system/etc. — these host
// platform-level CRs (IdentityProvider, NetworkPool, Kafka,
// ScaledObject) that route to infra/configs.
//
// classifyUnmatchedRelease uses a narrower set — helmControllerNamespaces
// — because most namespaces here host workloads, not the controller chart.
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

// helmControllerNamespaces is the namespace set classifyUnmatchedRelease
// treats as infrastructure-tier for an unmatched Helm release.
//
// Differs from infrastructureNamespaces only by excluding butler-system —
// butler-system hosts workloads (butler-console, butler-server,
// butler-addons), not controllers. butler-controller (the one controller
// in butler-system) is caught by controllerReleaseNames instead.
var helmControllerNamespaces = map[string]bool{
	"flux-system":     true,
	"cert-manager":    true,
	"kube-system":     true,
	"longhorn-system": true,
	"metallb-system":  true,
	"traefik":         true,
	"steward-system":  true,
	"keda-system":     true,
	"strimzi-system":  true,
	"reflector":       true,
	"observability":   true,
}

// controllerReleaseNames are unmatched releases routed to infra by
// name. Used when ChartInstallsCRDs misses and the target namespace
// isn't in helmControllerNamespaces.
var controllerReleaseNames = map[string]bool{
	"butler-controller": true,
	"steward":           true,
}

// Tier names used by the Helm path. Native path uses an internal
// tier classification (see classifyTier).
const (
	TierInfrastructure = "infrastructure"
	TierApps           = "apps"
)

// classifyUnmatchedRelease decides infrastructure vs apps for a Helm
// release with no AddonDefinition. Three signals, primary-to-fallback:
//
//  1. ChartInstallsCRDs — chart bundles CRDs (cert-manager, butler-crds).
//  2. controllerReleaseNames — known by name (butler-controller, steward).
//  3. helmControllerNamespaces — target namespace is a controller namespace.
//
// Otherwise apps. butler-console, butler-server, butler-addons land
// here (workloads in butler-system, no controller signal).
func classifyUnmatchedRelease(rel *DiscoveredRelease) string {
	if rel == nil {
		return TierApps
	}
	if rel.ChartInstallsCRDs {
		return TierInfrastructure
	}
	if controllerReleaseNames[rel.Name] {
		return TierInfrastructure
	}
	if helmControllerNamespaces[rel.Namespace] {
		return TierInfrastructure
	}
	return TierApps
}

// nativeTier values returned by classifyNativeTier. Internal to
// layout placement — not exposed.
const (
	nativeTierInfra = "infra"
	nativeTierApp   = "app"
)

// classifyNativeTier returns infra or app for a native item. Two
// signals from the DiscoveredNative: scope (IsNamespaced, RESTMapper-
// derived) and namespace.
//
//   - infra: cluster-scoped (any kind) OR namespaced in a known
//     infrastructure namespace.
//   - app: everything else.
//
// Kind=="Namespace" is NOT classified here — the HR emit path
// co-locates namespaces with their owning HelmRelease. See
// emitHelmReleases (apps) / emitInfrastructureRelease (inline) and
// emitNativeResources for the skip.
func classifyNativeTier(n *DiscoveredNative) string {
	if n == nil {
		return nativeTierApp
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
// resource.
//
// App-tier CRs whose namespace appears in helmOwnerByNamespace
// co-locate under apps/<env>/<owner>/<filename>.yaml. No owner →
// fallback to apps/<env>/<group>/<filename>.yaml. Cluster-wide CRs
// land in infrastructure/configs/.
//
// Returns "" for nil and for Kind=="Namespace" (the HR emit path
// owns namespace emission; emitNativeResources skips Namespace
// items).
func PathForNative(n *DiscoveredNative, env string, helmOwnerByNamespace map[string]string) string {
	if n == nil {
		return ""
	}
	if n.Kind == "Namespace" {
		return ""
	}
	tier := classifyNativeTier(n)
	groupShort := groupShortFromAPIVersion(n.APIVersion)
	kindLower := strings.ToLower(n.Kind)
	var filename string
	if n.IsNamespaced && n.Namespace != "" {
		filename = fmt.Sprintf("%s-%s-%s.yaml", kindLower, n.Namespace, n.Name)
	} else {
		filename = fmt.Sprintf("%s-%s.yaml", kindLower, n.Name)
	}

	if tier == nativeTierInfra {
		// core/v1 bare objects emit flat at the tier base; everything
		// else nests under its API-group short.
		if groupShort == "core" {
			return fmt.Sprintf("infrastructure/configs/%s", filename)
		}
		return fmt.Sprintf("infrastructure/configs/%s/%s", groupShort, filename)
	}

	// app-tier: owner-aware placement when a HelmRelease owns the ns.
	if owner := helmOwnerByNamespace[n.Namespace]; owner != "" {
		return fmt.Sprintf("apps/%s/%s/%s", env, owner, filename)
	}

	// Orphan: no owning HR. Fall back to group-short subdir so prune-
	// safety holds — dropping the file would let Flux prune live state.
	base := fmt.Sprintf("apps/%s", env)
	if groupShort == "core" {
		return fmt.Sprintf("%s/%s", base, filename)
	}
	return fmt.Sprintf("%s/%s/%s", base, groupShort, filename)
}

// PathForNativeWithDefault is preserved as an alias of PathForNative
// for callers that referenced the previous explicit-table vs
// default-placement split. The unified rule covers all kinds; there
// is no longer a meaningful difference between the two functions.
//
// The owner-map is omitted for backwards compatibility callers; pass
// the real map via PathForNative when owner-aware routing is needed.
func PathForNativeWithDefault(n *DiscoveredNative, env string) string {
	return PathForNative(n, env, nil)
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
