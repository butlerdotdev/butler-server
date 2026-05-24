# ADR-017: GitOps Export — Tenant Cluster Support

## Status

Proposed

## Date

2026-05-23

## Context

ADR-016 designed the gitops export against the management cluster
(usini2kpbtlrkn) with butler-crop-live-infra as the reference target
layout. The local-against-live validation loop confirmed the export
produces a correct tree for that one cluster shape.

Validating the same export against a real tenant cluster
(observability-pipeline-prd) surfaced that the v1 design does not
generalize. The tenant produces a tree that captures roughly 19% of the
gitops-managed objects Flux is reconciling, silently dropping user
workload declarations (Kafka, KafkaTopic, KafkaUser, ScaledObject),
platform configuration kinds the v1 discovery set doesn't enumerate
(ClusterIssuer, StorageClass), and namespace metadata (pod-security
labels). The tenant uses a 9-Kustomization per-component layout that
diverges from the 3-tier canonical the v1 export emits. Five of six
HelmRelease CRs reference HelmRepository CRs with chart-publisher names
(`kedacore`, `prometheus-community`, `emberstack`, `strimzi`,
`vector-repo`) that differ from the release name — exposing a name-
reconstruction bug ADR-016's mgmt-only validation did not surface
because mgmt's HelmRepository names happen to match HR names.

The product direction is that the export must work correctly on both
mgmt and tenant clusters. A guard refusing tenants is not a real
feature — the export's value is consistency across cluster types.
This ADR extends ADR-016 to cover tenant export, replacing the
fixed-kind discovery set with a Flux-inventory-driven approach,
adding chart-CRD detection to the unmatched-release classifier, and
defining the tenant reference layout.

Two correctness items the tenant run also surfaced — HelmRepository
CR name preservation and Namespace metadata preservation — are
already fixed in code (commit 5733616) under the same
"source-from-cluster, don't reconstruct" class principle that the
sealed-secrets HR CR name fix established. They are recorded here
for completeness but do not require ratification.

### Evidence — local-against-live validation on observability-pipeline-prd

Discovery counts:

| Source | Mgmt (usini2kpbtlrkn) | Tenant (observability-pipeline-prd) |
|---|---|---|
| Matched Helm releases | 6 | 0 (no AddonDefinitions registered) |
| Unmatched Helm releases | 5 | 11 |
| `butler.butlerlabs.dev` native CRs | 4 kinds, 5 instances | 0 (CRDs not registered) |
| SealedSecrets | 6 | 1 |
| MetalLB pools | 2 | 2 |
| ClusterCreationPolicy | 1 | 0 |
| `butler-gitops-config` ConfigMap | present | not present |

Flux Kustomizations the tenant runs (9 total):

| Kustomization | Inventory items | Notes |
|---|---|---|
| `apps` | 6 | vector HelmRelease, vector-repo HelmRepository, `vector` and `perftest` Namespaces, `butler-internal-ca` ClusterIssuer, `vector-otlp-tls` SealedSecret |
| `flux-system` | 48 | Flux bootstrap — out-of-scope for export by design |
| `infra-controllers` | 5 | sealed-secrets HR, kube-prometheus-stack HR, prometheus-community HelmRepository, `observability` Namespace |
| `infra-keda` | 3 | keda HR, kedacore HelmRepository, `keda-system` Namespace |
| `infra-reflector` | 3 | reflector HR, emberstack HelmRepository, `reflector` Namespace |
| `infra-storage` | 1 | `longhorn-rf1` StorageClass |
| `infra-strimzi` | 4 | strimzi-kafka-operator HR, strimzi HelmRepository, `strimzi-system` and `kafka` Namespaces |
| `kafka-resources` | 11 | 1 Kafka + 1 KafkaNodePool + 3 KafkaTopic + 6 KafkaUser |
| `scaledobjects` | 1 | 1 KEDA ScaledObject |

Prune-safety property test: 82 inventory items total; 10 covered by
v1 export tree; 72 uncovered. Subtracting 29 Flux-self-management
items (expected uncovered — bootstrap-owned), the in-scope coverage
gap is 43 items across the kinds listed below.

Categories of in-scope uncovered items:

1. **User workload declarations (12)**: Kafka, KafkaNodePool, KafkaTopic, KafkaUser, ScaledObject, ClusterIssuer. These are user-declared, gitops-managed — and silently dropped by v1's fixed-kind discovery.
2. **Standalone Namespaces with metadata (8)**: per-namespace pod-security labels and network-policy targeting labels lost in the synthesized-bare Namespace emit. Fixed in commit 5733616.
3. **HelmRepository name mismatches (5)**: tenant HRs reference publisher-named HelmRepositories that diverge from the HR's name. Fixed in commit 5733616.
4. **StorageClass (1)**: declared, gitops-managed, no entry in v1 discovery.
5. **Operator-tier mis-classification**: kube-prometheus-stack, strimzi-kafka-operator, reflector, keda are CRD-installing operators that the tenant correctly puts in dedicated infra-Kustomizations; v1's namespace heuristic places them in `apps/base/` because their namespaces are not in the heuristic set.

## Decision

Six sub-decisions. D1, D2, D4 require ratification; D3, D5 carry the
already-shipped correctness fixes; D6 is the implementation breakdown.

### D1 — Discovery approach: Flux-inventory-driven with placement table

Replace the v1 fixed-kind discovery (`nativeKinds()` table in
`internal/gitops/native_discovery.go`) with a discovery pass that reads
what Flux is actually reconciling on the cluster.

Mechanism:

1. List every `kustomize.toolkit.fluxcd.io/v1` Kustomization cluster-wide.
2. For each, read `.status.inventory.entries` (each entry is
   `<namespace>_<name>_<group>_<kind>`).
3. Filter out the Flux-self-management deny-list (kinds in the Flux GVRs,
   the bootstrap `flux-system` Kustomization's own inventory, the CRDs
   Flux registers for itself).
4. For each remaining entry, fetch the live object via the dynamic
   client and add it to discovery output.
5. Helm releases continue to be discovered via the existing
   `sh.helm.release.v1.*` secret-label path because the Helm release
   name + chart metadata + values are in those secrets, not directly
   in Flux inventory. The HR CR enrichment pass already cross-references
   these (commit 5733616).

Placement: per-kind table from ADR-016 (extended below in D4) routes
known kinds to specific paths. Kinds not in the table fall through to
a default bucket (see D4) AND get logged in the coverage report (D5)
so the operator can see what landed in the bucket.

#### Why Flux-inventory-driven over fixed-list

A fixed-kind list is brittle by construction. Every new tenant runs a
different operator set; maintaining the list means revisiting this code
for every new tenant pattern. Reading the inventory is the same
operation Flux's own prune logic performs — if Flux can reliably
identify the gitops-managed set, the export can too.

#### Why not expanded-but-fixed list (option C in the user's framing)

It addresses the specific tenant we validated but not the next one. The
generic approach handles any tenant without code changes.

#### Tradeoffs surfaced for ratification

| Concern | Resolution |
|---|---|
| Couples to Flux inventory format | Acceptable: `kustomize.toolkit.fluxcd.io/v1` is stable; Butler clusters use Flux exclusively. Migration to a future Flux API version is a one-touch change. |
| Doesn't cover gitops-managed-outside-Flux | Out of scope for v1: Butler-managed clusters use Flux. A future ArgoCD support ADR would add a parallel inventory reader. |
| Requires Flux installed | Already required by Butler stack on every supported cluster. |
| Includes objects that should NOT be re-exported | Explicit deny-list (Flux self-management) + per-kind placement filter handle this. The bootstrap Flux components are owned by `flux bootstrap`, not the export. |
| Discovery output grows large on tenants with many inventory items | Acceptable: the alternative is silently dropping them. Coverage report makes the count visible. |

### D2 — Unmatched-release classifier: chart-CRD detection added

ADR-016 D-A.1's namespace heuristic mis-tiers tenant operators
(kube-prometheus-stack, strimzi-kafka-operator, reflector, keda) to
`apps/base/` because their namespaces are not in the heuristic set.
Add a chart-CRD detection signal:

```
func classifyUnmatchedRelease(rel *DiscoveredRelease) string {
    if chartInstallsCRDs(rel) {
        return TierInfrastructure
    }
    if infrastructureNamespaces[rel.Namespace] {
        return TierInfrastructure
    }
    return TierApps
}
```

`chartInstallsCRDs` inspects the Helm release's chart manifest content
(already decoded in discovery) for any `kind: CustomResourceDefinition`
document. Charts that install CRDs are necessarily infrastructure-tier:
they provide the type system other workloads consume; placing them in
`apps/base/` breaks the dependsOn ordering that workloads using their
CRDs rely on.

#### Why chart-CRD detection over a HelmRelease annotation

An annotation requires every chart installer (butler-bootstrap, tenant
operators, users) to set it consistently. Chart-CRD detection works
without operator action and is correct by construction for the operator
class.

#### Tradeoffs surfaced for ratification

| Concern | Resolution |
|---|---|
| Heuristic miss: chart bundles CRDs separately (Helm `crds/` directory) | Heuristic still catches the common case (CRDs in `templates/`). For bundled-separately, the namespace heuristic remains the fallback. Tracked as an enhancement if it shows up. |
| Heuristic over-match: chart installs CRDs but is conceptually app-tier | Rare in practice. The conservative direction (more things in infrastructure-tier) is safer than the reverse — infrastructure reconciles before apps, so over-classification just shifts reconcile order. |
| Doesn't change mgmt behavior | Correct — mgmt's CRD-installing charts are already matched via AddonDefinition.Tier, so the heuristic doesn't fire for them. |

### D3 — HelmRepository CR name + Namespace metadata preservation (correctness, no ratification)

Already fixed in commit 5733616 under the established "source-from-
cluster, don't reconstruct" class principle:

- `DiscoveredRelease.HelmRepositoryCRName` and
  `HelmRepositoryCRNamespace` populated from each HR's
  `spec.chart.sourceRef.{name,namespace}` by
  `enrichWithHelmReleaseCRs`. Layout v2's `exportedHelmRepoName` /
  `exportedHelmRepoNamespace` prefer the looked-up values.
- `DiscoverNamespaceMetadata` fetches labels and annotations for each
  referenced namespace; layout v2's `namespaceFromDiscovery` emits
  Namespaces with preserved metadata. Filters server-applied labels
  (`kubernetes.io/metadata.name`) and controller tracking annotations
  (`kustomize.toolkit.fluxcd.io/*`, `meta.helm.sh/*`,
  `kubectl.kubernetes.io/last-applied-configuration`).

These are not new design decisions — they apply the same fix pattern
the sealed-secrets HR CR name issue used. Recorded here so the ADR
chain shows the full picture.

### D4 — Layout: shared 3-tier canonical for both cluster types, with extensions for tenant kinds

The 3-tier canonical layout from ADR-016 (`infrastructure/controllers`
+ `infrastructure/configs` + `apps`) is the v1 export shape for
**both** mgmt and tenant. No per-cluster-type layout fork.

Extensions to the path table for tenant-relevant kinds:

| Kind | Output path |
|---|---|
| `ClusterIssuer` (cert-manager.io) | `infrastructure/configs/cluster-issuers/<name>.yaml` |
| `StorageClass` (storage.k8s.io) | `infrastructure/configs/storage-classes/<name>.yaml` |
| `Kafka`, `KafkaNodePool`, `KafkaTopic`, `KafkaUser` (kafka.strimzi.io) | `apps/<env>/workloads/strimzi/<kind>/<namespace>-<name>.yaml` |
| `ScaledObject`, `ScaledJob`, `TriggerAuthentication` (keda.sh) | `apps/<env>/workloads/keda/<kind>/<namespace>-<name>.yaml` |
| any other gitops-managed CRD instance discovered via Flux inventory | `apps/<env>/workloads/<group>/<kind>/<namespace>-<name>.yaml` (default bucket) |

The default bucket `apps/<env>/workloads/<group>/<kind>/<namespace>-<name>.yaml`
catches any kind not in the explicit table. New tenant patterns
produce files in the bucket without code changes; the coverage report
(D5) makes them visible.

#### Why one shape, not per-cluster-type fork

Operational consistency: tenants and mgmt under the same gitops
structure are easier to reason about, document, and review. The
multi-Kustomization per-component pattern observed on
observability-pipeline-prd is a valid Flux layout but not what the
export emits — tenants using it will see the export propose a
restructure, the operator decides whether to adopt it.

#### Tenant reference layout — defined here

No existing tenant reference repo. The canonical tenant export shape
is the 3-tier canonical plus the workloads/ subdir:

```
infrastructure/
  controllers/
    <name>.yaml              # CRD-installing operators + foundational controllers
    kustomization.yaml
  configs/
    cluster-issuers/<name>.yaml
    storage-classes/<name>.yaml
    identity-providers/<name>.yaml      # mgmt only in practice
    network-pools/<name>.yaml           # mgmt only in practice
    provider-configs/<name>.yaml        # mgmt only in practice
    cluster-creation-policies/<name>.yaml  # mgmt only in practice
    metallb/<name>.yaml
    sealed-secrets/<namespace>-<name>.yaml
    butler-gitops-config.yaml           # mgmt only in practice
    kustomization.yaml
apps/
  base/
    <name>/{repository,release,kustomization,optional namespace}.yaml
  <env>/
    <name>-values.yaml
    teams/<name>.yaml                   # mgmt only — tenants have no Teams
    workloads/<group>/<kind>/<namespace>-<name>.yaml
    kustomization.yaml
clusters/<cluster>/{flux-system, apps.yaml, infrastructure.yaml, kustomization.yaml}
```

"Mgmt only in practice" means the kind will simply not be discovered
on tenants because the CRD isn't registered — discovery skips
gracefully per ADR-016 design.

### D5 — Discovery-completeness coverage report

Emit `coverage.yaml` at the export tree root. Contents:

```yaml
captured:
  helmReleases: [...]
  helmRepositories: [...]
  <kind>: [{namespace, name, path}]
fluxSelfManagement:
  # explicitly-filtered inventory items, by Kustomization
  flux-system: [...]
inScopeUncaptured:
  # objects in Flux inventory that fell through the placement table
  # to the default bucket. Surfaces unknown kinds for operator review.
  - {kind, namespace, name, path: "apps/<env>/workloads/<group>/<kind>/<ns>-<name>.yaml"}
```

The coverage report aligns with the visibility goal from
butlerdotdev/butler-server#78 (originally scoped to non-Helm visibility,
generalized here to all-of-export visibility). The export tree itself
remains clean Flux YAML; coverage.yaml is metadata-about-the-export,
not part of the kustomize build.

### D6 — Implementation breakdown

Two PRs after ADR ratification. Order matters; the inventory-driven
discovery is prerequisite to extended layout placement.

**PR 3 — Tenant-scoped discovery + layout + classifier**

butler-server only. On the existing feature branch
`feat/gitops-export-v2` (continuation):

- `internal/gitops/inventory_discovery.go` (new): walks Flux
  Kustomizations cluster-wide, reads inventories, filters Flux-self-
  management, fetches live objects via dynamic client.
- `internal/gitops/native_discovery.go`: remove the fixed-kind table;
  the inventory-driven pass replaces it. Keep `DiscoverNativeResources`
  signature for compat; route through the new inventory pass.
- `internal/gitops/layout_paths.go`: extend `PathForNative` with
  ClusterIssuer, StorageClass, Strimzi kinds, KEDA kinds, default
  bucket path.
- `internal/gitops/layout_v2.go`: chart-CRD detection in
  `classifyUnmatchedRelease`; helper to inspect chart manifests for
  `kind: CustomResourceDefinition`.
- `internal/gitops/coverage.go` (new): synthesize coverage.yaml from
  the accumulator state + the filtered inventory.
- Tests: extend layout_paths_test.go + layout_v2_test.go with
  tenant fixtures. Add a chart-CRD-detection unit test. Update
  prune-safety property test to walk Flux inventory of test fixtures.

**PR 4 — Tenant validation loop**

Same shape as the mgmt loop (ADR-016 PR 2's local-against-live
process):

1. Run `-summary-only` against `observability-pipeline-prd` tenant.
2. Verify the produced tree matches the tenant reference layout (D4).
3. Re-run the prune-safety property test against tenant's actual Flux
   inventory; bar is now near-100% coverage of in-scope items (after
   subtracting Flux self-management).
4. Hold at Gate 1; surface scratch repo target.
5. Real scratch-MR run.
6. Record `testdata/observability-pipeline-prd/` golden fixtures.

The mgmt golden fixtures (`testdata/butler-crop-prd/`) should be
recorded in the same PR; the prune-safety property test in CI then
runs against both shapes without live-cluster access.

## Consequences

### Positive

- Export works correctly for both mgmt and tenant cluster types.
- Discovery generalizes to future tenant kinds without code changes
  (default bucket + coverage report).
- Chart-CRD classifier correctly tiers operators that install CRDs,
  improving Flux reconcile ordering for both cluster types.
- One layout shape across cluster types simplifies operator review.
- HelmRepository CR name + Namespace metadata fixes already landed
  under the same class principle the sealed-secrets fix established.

### Negative

- Tighter coupling to Flux inventory format. Mitigation: documented
  acceptance and a one-touch upgrade path for future Flux API versions.
- Tenants using multi-Kustomization per-component layouts will see
  the export propose a restructure to 3-tier. Operator review at the
  MR gate is the safety net.
- Default-bucket placement is less semantic than per-kind placement.
  Mitigation: the coverage report surfaces what's in the bucket so
  operators can request per-kind placement rules be added.
- Discovery output grows on tenants (more inventory items captured).

### Deferred

- ArgoCD inventory support. Different reader; same hybrid pattern.
  Out of scope until a Butler cluster uses ArgoCD.
- Per-cluster layout configurability (e.g., emit multi-Kustomization
  per-component instead of 3-tier). v2 ADR if operators request it.
- Chart-content-based classification beyond CRD detection (e.g.,
  Operator Lifecycle Manager detection, prometheus-operator
  ServiceMonitor detection). Add if heuristic misses appear.
- Helm chart `crds/` directory inspection for charts that bundle CRDs
  separately from `templates/`. v2 enhancement if needed.

## References

- ADR-016: original gitops export design (mgmt-focused)
- butlerdotdev/butler-server#78: out-of-scope visibility / coverage
  report follow-up — generalized in D5
- Local-against-live validation run on observability-pipeline-prd
  tenant, 2026-05-23
- Commit `5733616` on `feat/gitops-export-v2`: HelmRepository CR name
  + Namespace metadata fixes (D3)
- Flux Kustomization inventory format:
  `.status.inventory.entries[*].id` parses to
  `<namespace>_<name>_<group>_<kind>`
