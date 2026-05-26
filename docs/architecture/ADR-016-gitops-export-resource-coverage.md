# ADR-016: GitOps Export Resource Coverage and Canonical Flux Layout

## Status

Proposed

## Date

2026-05-23

## Context

The gitops export endpoint snapshots a live cluster's state into a Flux-style
Git tree. Two structural gaps prevent the produced tree from sitting alongside
a production reference repo (butler-crop-live-infra) without hand-reshaping.

The first gap is resource coverage. `DiscoverHelmReleases()` in
`internal/gitops/discovery.go:78-156` enumerates Helm releases via Kubernetes
secrets labeled `owner=helm,status=deployed`. UI-configurable platform state
is not snapshotted: `IdentityProvider`, `NetworkPool`, `ProviderConfig`,
`Team` (multiple per cluster), `ClusterCreationPolicy` (ADR-018), the
`butler-gitops-config` ConfigMap, SealedSecrets (across all namespaces),
and MetalLB's `IPAddressPool` and `L2Advertisement`. A cluster exported
today is missing every piece of state that a platform admin configured
through the console.

The discovery set is restricted to kinds that are *declarative
desired-state* and that Flux is currently observed to reconcile on
Butler-managed clusters. Controller-owned runtime objects — kinds that
butler-controller, Steward, or other in-cluster controllers reconcile
from higher-level resources — are deliberately excluded. The principle
matters: a gitops export must carry the user's declared configuration,
not derived state. Exporting a runtime object would put Flux and the
owning controller in a fight over the same resource, with Flux
re-asserting the snapshotted desired-state against the controller's
ongoing reconciliation. See subsection 1 below for the kinds dropped
under this principle.

The second gap is output layout. `GenerateReleaseManifests()`
(`provider_flux.go:51-100`) emits a per-release subdirectory shape:

```
infrastructure/<name>/{helmrepository,helmrelease,namespace,kustomization}.yaml
apps/<name>/{helmrepository,helmrelease,namespace,kustomization}.yaml
```

`GenerateBootstrapStructure()` (`provider_flux.go:158-187`) emits a cluster
pointer pair (`clusters/<cluster>/{apps,infrastructure}.yaml`) plus empty
`infrastructure/kustomization.yaml` and `apps/kustomization.yaml` at repo root.
The target layout used by production Flux repos is different: controllers and
configs are split under `infrastructure/`, apps split between `apps/base` and
`apps/<env>` overlays, and the cluster pointer files reference Flux
`Kustomization` CRs with a `dependsOn` chain plus `wait: true`. The export's
output requires manual reshaping before it can be reconciled by Flux against
the same layout butler-crop-live-infra uses.

A third concern is a safety constraint, and it anchors the design. The export
runs against live clusters whose root Flux `Kustomization` may already be
reconciling `clusters/<cluster>`. Flux `prune: true` deletes any live resource
whose manifest is not in the rendered output. If the export emits a partial
tree (missing kinds), or a restructured tree where existing files move to new
paths, the next Flux reconcile prunes whatever isn't covered. Concretely: a
live `IdentityProvider` that the export does not emit, but that the rendered
`kustomization.yaml` files do not list as a resource, will be deleted from
the cluster on the next reconcile.

Prune safety is the primary design driver. Every other decision below is
constrained by it.

The classifier surface has partially shifted since ADR-015 added
`Tier` to `AddonDefinitionSpec`. For matched Helm releases, tier is
authoritative via `tierForAddon()`. The "infrastructure vs apps" decision
remains open for unmatched releases (user charts with no AddonDefinition,
e.g. `sealed-secrets-controller`, which is discovered today but falls into
the `Unmatched` bucket and is forced to `apps` at `discovery.go:147`) and
for the new native-resource kinds the discovery expansion adds.

CoreProvider (`coreproviders.operator.cluster.x-k8s.io`) is not registered
on Butler-managed clusters. Steward is delivered as a HelmRelease
(`steward-system/steward`) plus its own CRDs. Discovery does not need to
target CoreProvider in v1.

## Decision

Six pieces. Each is binding on the implementation.

### 1. Discovery expansion

Add `DiscoverNativeResources(ctx, kubeconfig) (*NativeDiscoveryResult, error)`
to `internal/gitops/discovery.go`. It uses the dynamic client to enumerate
the following GVRs in the order shown. Missing CRDs (operator not installed)
and RBAC denials are skipped, not fatal — discovery returns whatever it
finds and logs the rest.

| Kind | Group/Version | Scope | Notes |
|---|---|---|---|
| `IdentityProvider` | `butler.butlerlabs.dev/v1alpha1` | cluster | |
| `NetworkPool` | `butler.butlerlabs.dev/v1alpha1` | cluster | |
| `ProviderConfig` | `butler.butlerlabs.dev/v1alpha1` | cluster | |
| `Team` | `butler.butlerlabs.dev/v1alpha1` | cluster | Multiple per cluster. |
| `ClusterCreationPolicy` | `butler.butlerlabs.dev/v1alpha1` | cluster | ADR-018. Confirmed in Flux `apps` inventory on the live mgmt cluster. |
| `ConfigMap butler-gitops-config` | `core/v1` | `butler-system` namespace | Single named ConfigMap; lookup by name. |
| `SealedSecret` | `bitnami.com/v1alpha1` | namespaced | Enumerate across all namespaces. |
| `IPAddressPool` | `metallb.io/v1beta1` | `metallb-system` namespace | |
| `L2Advertisement` | `metallb.io/v1beta1` | `metallb-system` namespace | |

This discovery set is fixed for v1 and is sized to cover what Flux is
currently observed to manage on Butler-managed clusters (verified by reading
the cluster's `kustomization` inventories in `flux-system`). Adding a kind
to Butler that Flux later reconciles requires adding it to this table — see
the *Discovery completeness and prune safety* subsection below for why this
is load-bearing rather than incidental.

Kinds deliberately excluded under the declarative-desired-state-only
principle:

| Kind | Why excluded |
|---|---|
| `StewardControlPlane` | Runtime object reconciled by butler-controller from `TenantCluster` CRs. Exporting would put Flux in conflict with butler-controller over 19+ live tenant control planes on the observed mgmt cluster. |
| `StewardControlPlaneTemplate` | Template instances created by the Steward chart at install time; not user-declared. |

These are dropped on principle, not just by-observation. The principle
extends to any future kind: if butler-controller, Steward, or another
in-cluster controller creates and reconciles the resource from a
higher-level CR, the resource is runtime state and does not belong in the
export's discovery set. If a future cluster genuinely gitops-manages
tenant control planes (e.g. multi-cluster control-plane-as-config), the
v1 ADR is amended to add them under that explicit use case.

New types in `internal/gitops/types.go`:

```go
type DiscoveredNative struct {
    Kind       string
    APIVersion string
    Namespace  string
    Name       string
    Object     *unstructured.Unstructured
}

type NativeDiscoveryResult struct {
    IdentityProviders       []*DiscoveredNative
    NetworkPools            []*DiscoveredNative
    ProviderConfigs         []*DiscoveredNative
    Teams                   []*DiscoveredNative
    ClusterCreationPolicies []*DiscoveredNative
    ButlerGitOpsConfig      *DiscoveredNative
    SealedSecrets           []*DiscoveredNative
    MetalLBIPAddressPools   []*DiscoveredNative
    MetalLBL2Advertisements []*DiscoveredNative
}
```

The top-level export handler calls both `DiscoverHelmReleases()` and
`DiscoverNativeResources()` and merges into a single export bundle.

### 2. Output layout (target)

```
infrastructure/
  controllers/
    <name>.yaml              # Namespace + HelmRepository + HelmRelease joined by ---
    kustomization.yaml       # lists every <name>.yaml in this directory
  configs/
    identity-providers/<name>.yaml
    network-pools/<name>.yaml
    provider-configs/<name>.yaml
    cluster-creation-policies/<name>.yaml
    metallb/<name>.yaml
    sealed-secrets/<namespace>-<name>.yaml
    butler-gitops-config.yaml
    kustomization.yaml       # lists every file in this directory tree
apps/
  base/
    <name>/
      repository.yaml
      release.yaml
      namespace.yaml         # optional, only when createNamespace=true
      kustomization.yaml
  <env>/
    <name>-values.yaml       # HelmRelease patch via strategic merge; empty body in v1
    teams/
      <team-name>.yaml
      kustomization.yaml
    kustomization.yaml       # resources: ../base/<name> + teams + patches block
clusters/
  <cluster>/
    flux-system/             # written through unchanged from existing bootstrap
    infrastructure.yaml      # emits infra-controllers + infra-configs Flux Kustomizations
    apps.yaml                # dependsOn: infra-configs
    kustomization.yaml       # lists flux-system, infrastructure.yaml, apps.yaml
```

`clusters/<cluster>/infrastructure.yaml` contains two Flux Kustomization CRs:

- `infra-controllers` targeting `./infrastructure/controllers`, with
  `wait: true` so HelmReleases reconcile and CRDs are registered before
  downstream stages.
- `infra-configs` targeting `./infrastructure/configs`, with
  `dependsOn: [{name: infra-controllers}]`.

`clusters/<cluster>/apps.yaml` is one Flux Kustomization targeting
`./apps/<env>` with `dependsOn: [{name: infra-configs}]`.

### 3. Classifier rules

**3.1 Matched Helm releases** keep the ADR-015 path: `tierForAddon(addonDef)`
returns the addon's declared tier (or infers from `Platform`). No change.

**3.2 Unmatched Helm releases** are classified by a namespace heuristic:

```go
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

func classifyUnmatchedRelease(targetNamespace string) string {
    if infrastructureNamespaces[targetNamespace] {
        return "infrastructure-controllers"
    }
    return "apps"
}
```

A user-installed CRD provider in a custom namespace is mis-tiered to apps
under this rule. The mis-tier is recoverable (operator reviews the export
output before applying) and the namespace set is one-line-per-addition to
extend. A more robust signal — a `butler.butlerlabs.dev/tier` annotation
maintained by butler-bootstrap — is deferred. The annotation requires
cross-repo changes to butler-bootstrap plus a UI affordance for user-installed
charts; the heuristic is ~20 lines and easy to revisit.

**3.3 Native resources** are placed by a hard-coded per-kind table in a new
file `internal/gitops/layout_paths.go`:

| Kind | Output path |
|---|---|
| `IdentityProvider` | `infrastructure/configs/identity-providers/<name>.yaml` |
| `NetworkPool` | `infrastructure/configs/network-pools/<name>.yaml` |
| `ProviderConfig` | `infrastructure/configs/provider-configs/<name>.yaml` |
| `ClusterCreationPolicy` | `infrastructure/configs/cluster-creation-policies/<name>.yaml` |
| `MetalLB IPAddressPool` + `L2Advertisement` | `infrastructure/configs/metallb/<name>.yaml` |
| `SealedSecret` | `infrastructure/configs/sealed-secrets/<namespace>-<name>.yaml` |
| `ConfigMap butler-gitops-config` | `infrastructure/configs/butler-gitops-config.yaml` |
| `Team` | `apps/<env>/teams/<name>.yaml` |

Platform configuration objects (identity, network, provider, CCP, metallb,
sealed-secrets, gitops-config, steward) are prerequisites for apps and live
under `infrastructure/configs`. Teams are tenant-scoped and per-env in
multi-cluster repos; they live in `apps/<env>/teams/` to match
butler-crop-live-infra's `apps/prd/teams/` precedent.

### 4. Values splitter (base vs env)

Single-cluster in v1. Everything goes to `apps/base/<name>/release.yaml`.
An empty `apps/<env>/<name>-values.yaml` is written so the target layout's
path shape exists; downstream operators add overrides without restructuring.
The patches block in `apps/<env>/kustomization.yaml` is present but no-op
until populated.

Multi-cluster values splitting (paths that differ across clusters in the
same provider go to env, the rest stay base) is deferred. It cannot be
done from one cluster's values at export time; at minimum it needs to
read the existing target repo's other-env files to diff against. A future
ADR will design it. The single-cluster v1 shape is forward-compatible —
adding per-env values populates the existing `<name>-values.yaml` file
without restructure.

### 5. CoreProvider, Steward tenant CRs, raw-manifest controllers

Out of scope for v1. Three categories with related rationales:

- `coreproviders.operator.cluster.x-k8s.io` is not registered on
  Butler-managed clusters; Steward is installed as a HelmRelease. If a
  future cluster adopts the CAPI operator pattern, add `CoreProvider` to
  the discovery and layout-paths tables.
- `StewardControlPlane` and `StewardControlPlaneTemplate` are runtime
  objects reconciled by butler-controller from `TenantCluster` CRs. They
  are excluded from the discovery set on the declarative-desired-state
  principle stated in Context — a gitops export must carry user-declared
  configuration, not controller-derived state.
- **Raw-manifest controllers** — components delivered as hand-rolled
  Kubernetes manifests (CRDs + RBAC + Deployment) rather than as Helm
  releases. butler-crop-live-infra's `infrastructure/controllers/capi-steward.yaml`
  is the canonical instance: 9 raw docs that Flux applies directly. v1
  discovery only enumerates Helm releases and the named native CRDs, so
  raw-manifest components are neither captured nor pruned by the export
  — they persist under their existing management. This is safe (no churn
  against unmanaged resources) but invisible to an operator reading the
  exported tree. A separate coverage-report follow-up addresses the
  visibility gap; see Deferred section.

### 6. HelmRelease CR name preservation

The Helm release name (from the release secret's labels) is the chart's
installation identity and is what discovery returns as `DiscoveredRelease.Name`.
The Flux HelmRelease CR that owns the release can have a different
`metadata.name`: butler-crop-live-infra's `sealed-secrets` HelmRelease
sets `spec.releaseName: sealed-secrets-controller`, so the Helm release
name (`sealed-secrets-controller`) and the HR CR name (`sealed-secrets`)
diverge.

Without enrichment, the export would emit a new HelmRelease CR named
`sealed-secrets-controller` and prune the existing `sealed-secrets` HR
on the next reconcile of a Flux-watched target — Helm-controller would
briefly see two HRs reconciling the same release. To prevent this,
discovery walks all HelmRelease CRs on the cluster and back-fills each
`DiscoveredRelease` with its owning HR CR's `metadata.name` and
`metadata.namespace`. Layout v2 uses the HR CR name for the emitted
HR's `metadata.name` (and for the file basename / consolidated-file
name), and `spec.releaseName` carries the Helm release name so the
chart's installation identity is preserved. See
`internal/gitops/discovery.go:enrichWithHelmReleaseCRs`.

### 7. Prune-safety mechanism

Prune safety is layered. Three concerns; each closes a different failure mode.

**7.1 DirectoryAccumulator (mechanical, in-tree).** Every directory the
export writes contains a `kustomization.yaml` that lists every resource
file in it. Implementation: a `DirectoryAccumulator` tracks emitted files
per logical directory. After all layout code runs, the accumulator
synthesizes one `kustomization.yaml` per directory listing every file as
a resource. The synthesis is idempotent (same input produces identical
bytes) and orders entries lexicographically for stable diffs.

Kustomize ignores files not listed as resources. Without a complete
`kustomization.yaml` per directory, Flux's reconcile produces a manifest set
that omits any unlisted file — and prune deletes the corresponding live
resource. The accumulator closes the in-tree gap by construction: every
file emitted gets listed.

**7.2 Discovery completeness (load-bearing dependency).** The accumulator
only guarantees that emitted files appear in their directory's
`kustomization.yaml`. It does nothing about kinds discovery never finds.
A kind in Flux's inventory but not in the discovery set produces no file,
appears in no `kustomization.yaml`, and is pruned at the next reconcile
after merge.

The discovery set in subsection 1 is fixed at the kinds Flux is
currently observed to reconcile against Butler-managed clusters (verified
by reading the `apps` and `infra-configs` Kustomization inventories on the
live mgmt cluster, 2026-05-23). Adding a new Butler kind that Flux
reconciles requires extending the discovery table in lockstep — failing
to do so re-introduces the prune-safety gap for that kind.

This is the load-bearing dependency that closes Cooper-style "I added a
new CRD and the export silently dropped it" failures. The implementation
encodes it as:

- The discovery table is the single source of truth (one file, one table).
- The property test in subsection *Test strategy* enumerates the *live
  cluster's* resources, not just discovery output. A live resource with
  no covering `kustomization.yaml` entry fails the test, regardless of
  whether discovery returned it.
- Out-of-scope kinds (any `butler.butlerlabs.dev/v1alpha1` resource not
  in the table; CoreProvider; any user CRD applied imperatively that
  Flux later picks up) are acknowledged as un-handled in v1 and listed
  in *Deferred* below.

**7.3 Existing-tree detection and feature-branch flow (human review gate).**
Before writing, the export reads the target repo's existing tree under
`clusters/<cluster>` via `GitProvider.GetFileContent()`. The existing
shape is "v2 target" if both `clusters/<cluster>/apps.yaml` and
`apps/<env>/kustomization.yaml` exist; otherwise it is "different."

- Existing shape matches v2 target → direct push to default branch.
- Existing shape is different (or missing) → write to a feature branch
  named `butler-export/<cluster>-<unix-timestamp>`, open a PR/MR via
  `GitProvider.CreatePullRequest()` and `CreateBranch()`. The reconciled
  branch is not touched **until the operator merges the MR**.

This is a human review gate, not a mechanical prune-block. The MR moves
the moment-of-transition from the export run to the merge action,
giving the operator a chance to inspect the proposed tree before Flux
sees it. The mechanical guarantees against prune are 6.1 (in-tree) and
6.2 (discovery completeness); 6.3 adds a review step so a stale or
incomplete export tree doesn't auto-reconcile.

The `GitProvider` interface (`git_provider.go:25-38`) already exposes
`CreateBranch`, `CreatePullRequest`, and `CommitFiles`. No interface change.

## Implementation

Two PRs. The first ratifies the design; the second ships the feature
end-to-end.

### PR 1 — this ADR

butler-server only. Adds `docs/architecture/ADR-016-gitops-export-resource-coverage.md`.
No code change.

### PR 2 — feature, end-to-end

butler-server only. Built on a single feature branch and validated against
the live mgmt cluster before opening for review.

- Discovery expansion (`discovery.go`, `types.go`, `discovery_test.go`)
- Layout v2 method set (`provider.go`, `provider_flux.go`, new
  `layout_paths.go`)
- Classifier (namespace heuristic for unmatched, per-kind table for native)
- DirectoryAccumulator (new file under `internal/gitops/`)
- Existing-tree detection + feature-branch/MR flow wiring in the handler
- `gitopsExportV2` feature flag. v1 stays default until the v2 path is
  validated; flag flip is a separate follow-up commit.
- `compat.go` keeps v1 reachable for one release cycle.
- Tests: unit + golden-file scenarios (`minimal`, `butler-crop-prd`,
  `pre-existing-mismatch`) under `internal/gitops/testdata/`. The
  `butler-crop-prd` scenario is recorded from local-against-live runs.
- Prune-safety property test: enumerate the live cluster's resources
  across the in-scope namespaces and the cluster-scoped kinds in the
  discovery table; for each, assert the rendered tree contains a
  `kustomization.yaml` listing the file with that resource's manifest.
  A resource found on the cluster but not covered by an emitted
  `kustomization.yaml` fails the test — independent of whether discovery
  produced an entry for it. This catches both in-tree gaps (subsection
  7.1) and discovery-completeness gaps (subsection 7.2) in the same
  assertion.

The bar for opening PR 2: the export, run from the dev workstation against
the live mgmt cluster (read-only on cluster, write-only to a scratch git
repo, feature-branch+MR path), produces a tree that matches
butler-crop-live-infra's `apps/prd` + `infrastructure` shape AND the
prune-safety property test passes against the live cluster's actual
resource inventory. PR 2 may split if it grows unreviewable, but only
along boundaries where each resulting MR leaves the feature end-to-end
functional.

## Consequences

### Positive

- Exported tree round-trips against a Flux reference repo without
  hand-reshaping.
- All UI-configurable platform state is snapshotted: a `kubectl apply -k`
  of the exported tree against a fresh cluster reproduces identity
  providers, network pools, provider configs, sealed secrets, MetalLB
  pools, teams, and the gitops config.
- The DirectoryAccumulator closes the prune-safety gap by construction:
  every emitted directory has a complete kustomization.yaml.
- Feature-branch+MR flow on layout mismatch avoids direct-push to a
  reconciled branch when restructuring.
- Classifier table is one-file-one-table — auditable, extensible without
  cross-repo work.

### Negative

- Namespace heuristic for unmatched releases mis-tiers user-installed CRD
  providers in custom namespaces. Recoverable (operator reviews export
  output) and easy to extend (one line per namespace). Annotation-based
  classifier is the planned escape if mis-tiering shows up in practice.
- v1 is single-cluster. Multi-cluster repos need the values splitter,
  which is deferred to a future ADR.
- Existing exports remain in the old layout; operators re-export when
  they want v2. No automatic migration.

### Deferred

- Multi-cluster values splitter. Requires reading the existing target
  repo to diff against; out of scope here.
- HelmRelease `butler.butlerlabs.dev/tier` annotation maintained by
  butler-bootstrap. Replacement for the namespace heuristic if mis-tiering
  shows up.
- CoreProvider (`operator.cluster.x-k8s.io`) discovery. Not registered on
  Butler-managed clusters today.
- `StewardControlPlane` and `StewardControlPlaneTemplate` discovery.
  Excluded on the declarative-desired-state principle: these are runtime
  objects reconciled by butler-controller from `TenantCluster` CRs.
  Including them would put Flux and butler-controller in a fight over
  the same objects on every reconcile. If a future Butler topology
  declaratively manages tenant control planes through gitops, add them
  back under that explicit use case (and design a coordination mechanism
  between Flux and butler-controller for those objects).
- Namespace metadata preservation. The current export emits a bare
  `Namespace` synthesized from `TargetNamespace`; live labels/annotations
  on the cluster namespace are lost. Flagged for a follow-on; v2 layout
  inherits the same behavior.
- Migration tooling for previously exported repos in the v1 layout.
- Any `butler.butlerlabs.dev/v1alpha1` resource not listed in the discovery
  table (subsection 1). New CRDs that Flux reconciles must be added to the
  table before they can be safely exported (see subsection 7.2). Until
  added, they are treated the same as user-applied CRDs that Flux does not
  manage: they remain on the cluster, but if Flux IS reconciling them via
  some other path, prune deletes them.
- Raw-manifest controllers (e.g. butler-crop-live-infra's
  `infrastructure/controllers/capi-steward.yaml`, 9 raw docs delivered
  without a HelmRelease). v1 discovery only enumerates Helm releases and
  named native CRDs, so these are out of scope: the export does not
  capture them, but it also does not prune them — they persist under
  their existing management. The boundary is correct; the visibility is
  not (operators reading the exported tree cannot see what the export
  did not cover). Tracked separately in
  [butlerdotdev/butler-server#78](https://github.com/butlerdotdev/butler-server/issues/78)
  as a reporting follow-up; it does not change what v1 exports.

## References

- `internal/gitops/discovery.go:78-156` — `DiscoverHelmReleases()`
- `internal/gitops/discovery.go:144` — tier resolution call site (ADR-015)
- `internal/gitops/discovery.go:147` — unmatched-release `apps` fallback
- `internal/gitops/provider_flux.go:51-100` — `GenerateReleaseManifests()`
- `internal/gitops/provider_flux.go:158-187` — `GenerateBootstrapStructure()`
- `internal/gitops/provider.go:60-65` — `DirectoryLayout`
- `internal/gitops/provider.go:169-176` — `GetCategoryPath()`
- `internal/gitops/provider.go:178-181` — `GetReleasePath()`
- `internal/gitops/git_provider.go:25-38` — `GitProvider` interface
- `internal/gitops/types.go` — discovery types
- ADR-015: AddonDefinition GitOps Tier Field
- ADR-018 in butler-controller: ClusterCreationPolicy (kind added to
  discovery here)
- butlerdotdev/butler-server#76
- butler-crop-live-infra: reference target layout
- Flux Kustomization inventory format (status.inventory.entries) — used
  by the prune-safety property test to enumerate live state in the
  cluster's reconciliation scope
