# ADR-017: GitOps Export — Tenant Cluster Support

## Status

Proposed — revision 3 (2026-05-23, post-cross-check refinement)

## Date

2026-05-23

## Context

ADR-016 designed the gitops export against the management cluster
(mgmt-cluster-01) with the reference layout repository as the reference target
layout. The local-against-live validation loop confirmed the export
produces a correct tree for that one cluster shape.

Validating the same export against a real tenant cluster
(mature-tenant-prd) surfaced that the v1 design does not
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

### Evidence — local-against-live validation on mature-tenant-prd

Discovery counts:

| Source | Mgmt (mgmt-cluster-01) | Tenant (mature-tenant-prd) |
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

Seven sub-decisions. D1, D2, D4 require ratification; D3 records the
already-shipped correctness fixes; D5 specifies the coverage report;
D6 logs verification gates carried forward to PR 3; D7 is the
implementation breakdown.

### D1 — Discovery approach: Flux-inventory-driven with placement table

Replace the v1 fixed-kind discovery (`nativeKinds()` table in
`internal/gitops/native_discovery.go`) with a discovery pass that reads
what Flux is actually reconciling on the cluster.

Mechanism:

1. List every `kustomize.toolkit.fluxcd.io/v1` Kustomization cluster-wide.
2. For each, read `.status.inventory.entries` (each entry is
   `<namespace>_<name>_<group>_<kind>`).
3. Apply the Flux-self-management filter (specified below).
4. For each remaining entry, fetch the live object via the dynamic
   client and add it to discovery output.
5. Helm releases continue to be discovered via the existing
   `sh.helm.release.v1.*` secret-label path because the Helm release
   name + chart metadata + values are in those secrets, not directly
   in Flux inventory. The HR CR enrichment pass already cross-references
   these (commit 5733616).

#### Flux-self-management filter — explicit rules

A coverage bug in either direction is a prune bug: under-filtering ships
bootstrap noise into the export tree; over-filtering silently drops user
state. The filter is enumerated, not heuristic.

**Filter as Flux operational** (exclude from export):

- Any resource whose `group` is in the Flux GVR set: `helm.toolkit.fluxcd.io`,
  `source.toolkit.fluxcd.io`, `kustomize.toolkit.fluxcd.io`,
  `notification.toolkit.fluxcd.io`, `image.toolkit.fluxcd.io`. This
  catches HelmRelease, HelmRepository, GitRepository, OCIRepository,
  HelmChart, Bucket, Kustomization, ResourceSet, Alert, Provider,
  Receiver, ImagePolicy, ImageRepository, ImageUpdateAutomation.
- The corresponding CustomResourceDefinitions for those groups
  (`*.helm.toolkit.fluxcd.io`, `*.source.toolkit.fluxcd.io`, etc.).
- Any resource in the `flux-system` namespace whose `kind` is in the
  Flux runtime set: `ServiceAccount`, `Role`, `RoleBinding`,
  `ClusterRole`, `ClusterRoleBinding`, `Service`, `Deployment`,
  `ResourceQuota`, `NetworkPolicy` — AND whose name matches a Flux
  controller pattern (`source-controller`, `kustomize-controller`,
  `helm-controller`, `notification-controller`,
  `image-reflector-controller`, `image-automation-controller`,
  `webhook-receiver`, `crd-controller-flux-system`,
  `cluster-reconciler-flux-system`, `flux-edit-flux-system`,
  `flux-view-flux-system`, `critical-pods-flux-system`,
  `allow-egress|allow-scraping|allow-webhooks`).

The filter is by GROUP and KIND-plus-NAME-pattern, not by Kustomization
NAME. A user-created Kustomization that happens to be named "flux-system"
would still have its inventory items evaluated normally; Flux operational
objects in flux-system get filtered by their kind+name pattern; user
objects in flux-system that don't match a Flux controller name (rare —
imagine a user-deployed monitoring sidecar) pass through.

**Include in export** (re-emit, not filter):

- HelmRelease + HelmRepository — user-declared gitops state; D3 already
  enriches these from Flux inventory cross-reference.
- HelmRelease + HelmRepository sources Flux is reading from (e.g. a
  `OCIRepository` pointing at a chart registry) — also user-declared.

**User-defined Kustomization CRs — explicit rule:**

The user's per-component Kustomization CRs (e.g. observability-
pipeline-prd's `infra-keda`, `infra-reflector`, `infra-strimzi`,
`kafka-resources`, `scaledobjects`) are themselves
`kustomize.toolkit.fluxcd.io/v1` Kustomization CRs — same group as
Flux's own operational objects. They are **filtered as Flux operational**
under the GVR rule above (excluded from the export tree).

Rationale: the export emits its own cluster-pointer Kustomization CRs
(at `clusters/<cluster>/{infrastructure,apps}.yaml`) that organize the
3-tier shape. The user's existing per-component Kustomization CRs are
the OLD organizing layer being replaced by the v2 layout. Re-emitting
them would create two competing organizational structures in the same
tree.

What this means in practice: the export captures every RESOURCE the
user's Kustomization CRs were managing (HelmReleases, HelmRepositories,
Namespaces, ClusterIssuers, etc.) via the inventory walk; it does NOT
re-emit the user's organizing Kustomization CRs themselves. On the MR
the operator sees, the user's existing per-component Kustomizations
appear in the "to-be-removed" set — they're being replaced by the
v2 cluster-pointer files. The operator-review-at-MR gate (ADR-016 7.3)
is where this restructure is reviewed before merge.

Placement: per-kind table from ADR-016 (extended below in D4) routes
known kinds to specific paths. Kinds not in the table fall through to
a tiered default placement (see D4) AND get logged in the coverage
report (D5) so the operator can see what landed where.

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

#### Default placement for kinds not in the explicit table

A single default bucket is wrong: what falls through is not
homogeneous. capi-steward's hand-rolled raw-YAML inventory (CRDs +
cluster-scoped RBAC + a controller Deployment in `steward-system`) is
infrastructure, not user-workload. Routing it to `apps/<env>/workloads/`
ships a known misplacement.

Default placement is differentiated by scope and kind class:

| Inventory item shape | Default path |
|---|---|
| Cluster-scoped infrastructure kinds: `CustomResourceDefinition`, `ClusterRole`, `ClusterRoleBinding`, `ValidatingWebhookConfiguration`, `MutatingWebhookConfiguration`, `APIService`, `PriorityClass`, `RuntimeClass`, `IngressClass`, `MutatingAdmissionPolicy`, `ValidatingAdmissionPolicy`, plus any unknown CRD instance with cluster scope and group ending in `.cluster.x-k8s.io` or matching `*-system.io` patterns | `infrastructure/configs/<sanitized-group>/<kind>/<name>.yaml` |
| Namespaced infrastructure kinds in a known infra namespace (`flux-system` — handled by self-mgmt filter, so this row covers other infra namespaces from `infrastructureNamespaces`: `cert-manager`, `kube-system`, `longhorn-system`, `metallb-system`, `traefik`, `butler-system`, `steward-system`, `keda-system`, `strimzi-system`, `reflector`, `observability`): `Deployment`, `ServiceAccount`, `Role`, `RoleBinding`, `Service`, `ConfigMap`, `Secret`-class objects, `NetworkPolicy` | `infrastructure/configs/<sanitized-group>/<kind>/<namespace>-<name>.yaml` |
| Anything else (user workload-shaped — namespaced CRD instances in user namespaces) | `apps/<env>/workloads/<sanitized-group>/<kind>/<namespace>-<name>.yaml` |

The capi-steward case is the load-bearing test: it places under
`infrastructure/configs/...` for the CRDs / RBAC / Deployment (all 9
raw resources land in infra-tier subdirectories, grouped by group +
kind), not under `apps/<env>/workloads/`.

The `infrastructureNamespaces` set used for the namespaced-infra default
is the same set the unmatched-release classifier uses (ADR-016 D-A.1
extended in D2 below). The set is extended for tenant operator
namespaces (`keda-system`, `strimzi-system`, `reflector`,
`observability`) — surface in the implementation. New tenant patterns
discovered in other namespaces fall to the user-workload bucket and
the coverage report (D5) surfaces the placement decision for operator
review; per-kind placement rules then get added to the explicit table
in a follow-on.

#### Why one shape, not per-cluster-type fork

Operational consistency: tenants and mgmt under the same gitops
structure are easier to reason about, document, and review. The
multi-Kustomization per-component pattern observed on
mature-tenant-prd is a valid Flux layout but not what the
export emits — tenants using it will see the export propose a
restructure, the operator decides whether to adopt it.

#### Tenant reference layout — derived from butler-observability-pipeline-reference

A tenant reference repo exists and was confirmed during ADR
ratification by searching butlerdotdev's public repos plus the
butler-cli and butler-bootstrap codebases:
[**butler-observability-pipeline-reference**](https://github.com/butlerdotdev/butler-observability-pipeline-reference).
Its README labels it "Production-proven Vector aggregator pattern
packaged as a fork-and-deploy GitOps reference. The pipeline cluster
is itself a Butler-managed tenant cluster — it follows the same
lifecycle as any other tenant."

The reference's on-disk shape matches the layout this ADR defines:

| ADR-017 D4 path | butler-observability-pipeline-reference actual |
|---|---|
| `infrastructure/controllers/<name>.yaml` + `kustomization.yaml` | `infrastructure/controllers/prometheus-operator.yaml` + `kustomization.yaml` |
| `infrastructure/configs/` | present (README-only in the reference — minimal example covers no configs kinds) |
| `apps/base/<name>/{repository,release,namespace,kustomization}.yaml` | `apps/base/vector/{repository,release,namespace,kustomization}.yaml` |
| `apps/<env>/<name>-values.yaml` + `kustomization.yaml` | `apps/{prd,dev}/vector-values.yaml` + `kustomization.yaml` |
| `clusters/<cluster>/{flux-system, apps.yaml, infrastructure.yaml, kustomization.yaml}` | `clusters/{pipeline-dev,pipeline-prd}/{flux-system/, apps.yaml, infrastructure.yaml, kustomization.yaml}` |
| `apps/<env>/workloads/<group>/<kind>/...` | not present (reference scope is minimal — only Vector + prometheus-operator; the `workloads/` extension is consistent with the reference shape, not contradicted by it) |

The reference is minimal and does not exercise the
`infrastructure/configs/<subdir>/` placements (cluster-issuers,
storage-classes, etc.) or the `workloads/` extension. Those parts of
D4 extend the reference shape consistently for the broader tenant kinds
this ADR covers; they are not contradicted by anything in the reference.

**Observed divergence between the live tenant cluster
(mature-tenant-prd) and the reference shape:** the live
cluster has 9 Flux Kustomizations (`apps`, `flux-system`,
`infra-controllers`, `infra-keda`, `infra-reflector`, `infra-storage`,
`infra-strimzi`, `kafka-resources`, `scaledobjects`) — operators
evolved a per-component multi-Kustomization layout post-fork from the
reference's 3-tier shape. The export emits the reference shape, which
means tenants using the export are restored to the canonical the
reference establishes. The operator-review-at-MR gate is where this
restructure is reviewed before merge.

The canonical tenant export shape:

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

### D6 — Verification gates carried forward to implementation

Two items the ADR ratification gate logs for PR 3 to verify
empirically. Neither changes the design; both are correctness
checks where assertion-without-proof is too weak.

**V1 — Flux inventory reconcile-state handling**

`.status.inventory.entries` is updated as part of a Kustomization's
reconcile loop. The inventory can be stale (last successful reconcile),
empty (first reconcile in progress), or absent (`Ready: False`). The
discovery pass walks N Kustomizations sequentially, so the snapshot is
eventually-consistent across the walk, not atomic.

PR 3 must specify and document the behavior chosen:

- For each Kustomization, log its `Ready` condition + `lastAppliedRevision`
  at the moment its inventory is read so the export captures the
  consistency moment per Kustomization.
- Skip Kustomizations whose `Ready` is False AND whose
  `.status.inventory.entries` is empty — there's no consistent state
  to read.
- Surface snapshot-drift acknowledgment: discovery is eventually-consistent
  across the walk; the coverage report (D5) records each Kustomization's
  observed revision so the operator sees the snapshot moment.

These are correctness behaviors, not design decisions. They get
verified in PR 3's tenant validation loop by deliberately walking
during a Kustomization reconcile.

**V2 — D2 chart-CRD classifier doesn't regress mgmt tiering**

D2 asserts the chart-CRD detection signal doesn't change mgmt
behavior because mgmt's CRD-installing charts are matched via
AddonDefinition.Tier. The assertion is true for matched releases.
Mgmt also has 5 *unmatched* releases (`butler-crds`, `butler-controller`,
`butler-console`, `butler-addons`, `steward`). For each, PR 3 must:

- Run `chartInstallsCRDs` against its decoded Helm chart manifest.
- Confirm the resulting tier equals the tier the current namespace
  heuristic produces (all five currently classify as `infrastructure`
  via `infrastructureNamespaces[butler-system]` and
  `infrastructureNamespaces[steward-system]`).
- If any release transitions tier under the new classifier, surface
  before landing — a tier change for a mgmt release is a regression
  in the half already validated.

This is a 5-row spreadsheet to verify in PR 3 implementation. The
design holds regardless of the answer (a tier change is unlikely
because the namespace heuristic already places them correctly); the
verification protects against an unexpected divergence.

### D7 — Implementation breakdown

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

1. Run `-summary-only` against `mature-tenant-prd` tenant.
2. Verify the produced tree matches the tenant reference layout (D4).
3. Re-run the prune-safety property test against tenant's actual Flux
   inventory; bar is now near-100% coverage of in-scope items (after
   subtracting Flux self-management).
4. Hold at Gate 1; surface scratch repo target.
5. Real scratch-MR run.
6. Record `testdata/mature-tenant-prd/` golden fixtures.

The mgmt golden fixtures (`testdata/mature-tenant-prd/`) should be
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
- **Per-env controller value overrides applied as inline patches on
  Flux Kustomization CRs are not preserved as separate overlays.** The
  cross-check against butler-observability-pipeline-reference surfaced
  a convention this ADR does not model: per-env controller tweaks
  (kube-prometheus-stack replicas / retention / storage / externalLabels
  / remoteWrite) are applied via `spec.patches` on the per-cluster
  `clusters/<cluster>/infrastructure.yaml` Flux Kustomization. Per-env
  *app* values ARE modeled (the `apps/<env>/<name>-values.yaml` files
  + patches block on `apps/<env>/kustomization.yaml`); per-env
  *controller* values are not. v1 exports controllers as canonical
  base with the *effective* (post-patch) values from the live
  HelmRelease folded in — the base-vs-overlay split is lost. An
  operator who re-imports a v1 export back onto a cluster running
  the reference's convention would see the controller's per-env
  patches replaced by the export's flattened base values. Operators
  re-add per-env controller patches post-export. Modeling them is
  deferred (see Deferred). The coverage report (D5) MUST surface
  observed inline patches so this gap is operator-visible — see
  Deferred for the implementation note.

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
- **Per-env controller value overrides as separate overlay files.**
  butler-observability-pipeline-reference's convention applies
  per-env controller values as inline `spec.patches` on the per-cluster
  `clusters/<cluster>/infrastructure.yaml` Flux Kustomization (see
  Negative consequences above for the concrete example —
  kube-prometheus-stack replicas/retention/storage etc.). v2 would
  add a parallel pattern for controllers:
  `infrastructure/controllers/<env>/<name>-values.yaml` or inline
  patches captured directly in the emitted cluster-pointer
  `infrastructure.yaml`. v1 ships the canonical base only.

  **Visibility implication for the coverage report (D5):** inline
  patches on a Flux Kustomization's `spec.patches` field are NOT
  separate inventory items — they live in the Kustomization CR's spec,
  not in `.status.inventory.entries`. The inventory-walk discovery in
  D1 will not see them by reading inventory alone. PR 3's coverage
  report MUST additionally read `spec.patches` on each walked
  Kustomization and surface observed patches in `coverage.yaml`
  (e.g. `inlinePatchesObserved: [{kustomization: infra-controllers,
  target: {kind: HelmRelease, name: kube-prometheus-stack}, patchSize:
  N}]`) so the limitation is operator-visible per-export rather than
  silently dropped. Without this, an operator re-importing the export
  would see controller per-env tweaks flattened into base values with
  no warning that the source-organization was lost.

## References

- ADR-016: original gitops export design (mgmt-focused)
- butlerdotdev/butler-server#78: out-of-scope visibility / coverage
  report follow-up — generalized in D5
- [butlerdotdev/butler-observability-pipeline-reference](https://github.com/butlerdotdev/butler-observability-pipeline-reference):
  the existing tenant gitops reference repo D4's shape derives from
  (a Butler-managed tenant cluster running the Vector aggregator
  pattern; explicitly labeled "fork-and-deploy GitOps reference")
- Local-against-live validation run on mature-tenant-prd
  tenant, 2026-05-23 (note: live cluster has a 9-Kustomization
  per-component layout that diverged from butler-observability-pipeline-reference's
  3-tier shape post-fork; the export emits the reference shape)
- Commit `5733616` on `feat/gitops-export-v2`: HelmRepository CR name
  + Namespace metadata fixes (D3)
- Flux Kustomization inventory format:
  `.status.inventory.entries[*].id` parses to
  `<namespace>_<name>_<group>_<kind>`

## Revision history

- Revision 1 (initial, 2026-05-23): four ratifiable decisions (D1-D4),
  one already-shipped record (D3), one implementation breakdown (D5/D6).
- **Revision 2** (2026-05-23, this revision): three design-level
  tightenings landed before ratification —
  (a) **D1 filter precision**: explicit Flux GVR enumeration; replaced
      name-based "flux-system Kustomization" filter with group+kind+name-pattern
      rule; explicit answer to the user-defined Kustomization CR question
      (filter as Flux operational, since the v2 cluster-pointer files
      replace the user's organizing Kustomizations).
  (b) **D4 default-bucket differentiation**: single `apps/<env>/workloads/`
      bucket replaced with scope/kind-tiered placement so capi-steward's
      CRDs + ClusterRoles + Deployment land in `infrastructure/configs/...`
      (correct), not `apps/<env>/workloads/` (wrong).
  (c) **D4 tenant reference**: tenant-reference search performed across
      butler-bootstrap, butler-cli, and butlerdotdev's public repos.
      Found butler-observability-pipeline-reference, an existing
      reference repo whose 3-tier shape matches what this ADR proposed.
      Retracted the "no existing tenant reference repo" claim;
      D4 now derives from the existing reference rather than inventing
      a parallel shape.
  Plus a new **D6 (Verification gates carried forward to implementation)**
  logging two items the ADR-ratification gate hands to PR 3:
  reconcile-state handling for Flux inventory reads, and a 5-row check
  that the chart-CRD classifier doesn't transition any mgmt unmatched
  release's tier vs the current namespace heuristic. Original D6 renumbered
  to D7.
- **Revision 3** (2026-05-23, this revision): cross-check against
  butler-observability-pipeline-reference's actual on-disk shape held
  9/10 rows of D4's base table; one minor refinement folded into
  PR 3 (conditional `infra-configs` emission to match the reference);
  one new v1-scope limitation captured explicitly in Consequences/
  Deferred: per-env controller value overrides applied as inline
  `spec.patches` on the cluster's `infrastructure.yaml` Flux
  Kustomization are not preserved as separate overlays by v1 (per-env
  *app* values via `apps/<env>/<name>-values.yaml` ARE preserved;
  per-env *controller* values are not). The coverage report (D5)
  gains a requirement to read `spec.patches` on each walked
  Kustomization and surface observed patches so the limitation is
  operator-visible rather than silently flattened. Surfaced because
  butler-observability-pipeline-reference uses this convention for
  kube-prometheus-stack's per-env replicas/retention/storage.
