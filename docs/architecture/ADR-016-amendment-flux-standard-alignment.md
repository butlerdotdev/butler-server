# ADR-016 Amendment — Flux2 standard alignment for tiering and namespace placement

- **Status**: Accepted
- **Date**: 2026-05-24
- **Supersedes**: ADR-016 "ratified" namespace special-case (Section *Decision A.2: Native-resource placement*); intermediate amendment introducing tier-aware standalone namespace placement
- **Scope**: tier classification for Helm releases and native resources, namespace placement, CR-instance placement
- **Anchored to**: fluxcd documented standard (see Sources)

## Purpose of this note

This amendment exists so the rule does not need to be re-derived each session. ADR-016's original classification was based on internal heuristics that drifted from the broader Flux community convention; subsequent sessions kept re-discovering the same divergence and patching it differently. The fix is to anchor the rule to the documented Flux2 standard with citations, and to record where Butler's interpretation extends the standard (since the standard does not cover every Butler-specific case directly).

Future sessions should read this note and re-verify against the cited sources rather than re-derive the rule from observed live repos. The live butler/seed deployment is one real-world data point — useful as a comparison, but not the authority. The standard is the authority. Where the live deployment diverges from the standard, this note records which direction Butler follows and why.

## Sources

1. **Official Flux docs — "Ways of structuring your repositories"**
   - Path in the website repo: `fluxcd/website/content/en/flux/guides/repository-structure.md`
   - Published URL: https://fluxcd.io/flux/guides/repository-structure/
   - Quoted passage:
     > *"The separation between apps and infrastructure makes it possible to define the order in which a cluster is reconciled, e.g. first the cluster addons and other Kubernetes controllers, then the applications."*

2. **fluxcd/flux2-kustomize-helm-example** (the canonical reference implementation the docs link to)
   - Repository: https://github.com/fluxcd/flux2-kustomize-helm-example
   - Quoted passages:
     > *"`apps` dir contains Helm releases with a custom configuration per cluster"*
     > *"`infrastructure` dir contains common infra tools such as Envoy Gateway and cert-manager"*
     > *"`infrastructure/controllers/` dir contains namespaces and Helm release definitions for Kubernetes controllers"*
     > *"`infrastructure/configs/` dir contains Kubernetes custom resources such as cert issuers and networks policies"*
     > *"`apps/base/` dir contains namespaces and Helm release definitions"*
   - Verified by direct inspection of the repo contents:
     - `apps/base/podinfo/namespace.yaml` is a separate file co-located with `release.yaml` + `repository.yaml`.
     - `infrastructure/controllers/cert-manager.yaml` contains the Namespace as the first YAML document in the same multi-doc file as the OCIRepository + HelmRelease.
     - `infrastructure/configs/cluster-issuers.yaml` carries a ClusterIssuer (a cert-manager operator CR instance), and `clusters/<env>/infrastructure.yaml` applies env-specific differences via Kustomize patches on the CR.

3. **fluxcd/flux2-multi-tenancy** (platform-admin / tenant separation)
   - Repository: https://github.com/fluxcd/flux2-multi-tenancy
   - Quoted passage:
     > *"Platform Admin ... Manages cluster wide resources (CRDs, controllers, cluster roles, etc) and policies to enforce tenant restrictions."*

## The load-bearing principle: owner-follows-tier

**A thing that belongs to an owner travels with that owner, not in a separate classifier bucket.**

This is the ONE principle the rule derives from. It has THREE applications — namespaces, app-scoped CRs, and the values patch. They are not three separate clauses to memorize; they are the same principle applied to three constructs.

If a future session questions a placement decision, check whether the construct in question is one of the three already covered. If yes, the principle decides; do not re-derive from flux2 sources. If a new construct appears that owner-follows-tier might govern, apply the principle by analogy and record the new application here — do not invent a separate rule.

### Three applications

| Application | Construct | What it looks like |
|---|---|---|
| 1 (Clause 4) | **Namespace** | Co-located with its owning HelmRelease. For controllers: inline as the first doc in `infrastructure/controllers/<release>.yaml`. For apps: separate file at `apps/base/<release>/namespace.yaml`. |
| 2 (Clause 5) | **App-scoped operator CR instances** | A SealedSecret, ServiceMonitor, IngressRoute, etc. owned by a specific HelmRelease (its namespace matches the HR's `targetNamespace`). Co-locates at `apps/<env>/<release>/<filename>.yaml`. |
| 3 (Clause 6) | **Strategic-merge values patch** | The `<release>-values.yaml` env overlay that patches the base HelmRelease. Co-locates at `apps/<env>/<release>/<release>-values.yaml` inside the same per-release env directory as the CRs. The per-release env kustomization carries the `patches:` block targeting the HelmRelease. |

### Cluster-wide vs app-scoped — the splitter

A construct that the principle says "co-locates with its owner" still needs an owner. The owner is either:
- **A specific app** (its HelmRelease's `targetNamespace` matches the construct's namespace) → all three applications above route the construct to `apps/`, co-located with the owning release.
- **The cluster itself** (no app owns it; it's a platform-level resource the cluster as a whole consumes) → routes to `infrastructure/configs/` per Clause 2.

| Case | Owner | Placement |
|---|---|---|
| cert-manager's `ClusterIssuer` | Cluster (one issuer for everything that needs certs) | `infrastructure/configs/cluster-issuers.yaml` |
| Envoy `Gateway` | Cluster (one gateway many apps share) | `infrastructure/configs/gateway.yaml` |
| airflow's `SealedSecret` for its DB password | airflow (it's airflow's secret) | `apps/<env>/airflow/sealedsecret-db.yaml` |
| airflow's `ServiceMonitor` | airflow (it monitors airflow) | `apps/<env>/airflow/servicemonitor.yaml` |
| airflow's CNPG `Cluster` (its database) | airflow (it IS airflow's database) | `apps/<env>/airflow/cluster.yaml` |
| airflow's `<release>-values.yaml` | airflow (env-specific override of airflow's HR) | `apps/<env>/airflow/airflow-values.yaml` |
| airflow's namespace | airflow (its target namespace) | `apps/base/airflow/namespace.yaml` |

The classifier identifies app-scope via the `namespace → owning apps-tier HelmRelease` map built by `helmAppsOwnerByNamespace`. When the map has an entry for a construct's namespace, the construct routes to the corresponding `apps/<env>/<owner>/` (or `apps/base/<owner>/` for the namespace itself). When the map has no entry AND the construct is cluster-scoped or in a platform namespace, it routes to `infrastructure/configs/`. When no entry AND not cluster-scoped (orphan app-scoped CR): falls back to `apps/<env>/<group>/<filename>.yaml` (the only place where vendor-grouping appears — for prune-safety, not for owned items).

### Edge case: multi-owner namespaces

A namespace can have MORE than one HelmRelease targeting it — in particular, on the mgmt cluster, `butler-system` has four (`butler-console` + `butler-addons` as apps-tier; `butler-controller` + `butler-crds` as infra-tier). Each of the CR instances in that namespace (e.g., `SealedSecret` files like `butler-console-tls`, `nutanix-credentials`, `entra-oidc`, `butler-git-credentials`) is INDIVIDUALLY OWNED by one of those releases — `nutanix-credentials` belongs to butler-controller, `butler-git-credentials` to butler-addons' gitops sync, `butler-console-tls` to butler-console — but the classifier can't see per-CR ownership from namespace alone.

What the current classifier does for these CRs:
- `classifyNativeTier` short-circuits to `nativeTierInfra` because `butler-system` is in the broader `infrastructureNamespaces` set.
- `PathForNative` routes to `infrastructure/configs/<group>/<filename>.yaml` (e.g., `infrastructure/configs/bitnami/sealedsecret-butler-system-<name>.yaml`).
- `helmAppsOwnerByNamespace` is bypassed (not consulted on the infra branch).

**This routing is correct as the principle's honest answer under unresolvable ownership — NOT because these are truly shared platform secrets.** They aren't. They're individually owned; the classifier just can't tell which release owns which CR with the signals it currently has. Routing all of them to a guessed single owner (e.g., the first apps-tier HR targeting the namespace, which is `helmAppsOwnerByNamespace`'s first-wins behavior) would fabricate ownership: `nutanix-credentials` would silently land under `apps/<env>/butler-console/` even though butler-console doesn't own it. That's worse than the conservative shared-tier fallback.

The `bitnami/` vendor-grouped subdir on these paths is the agnostic group-derived fallback (same fallback that fires for any CR whose owner the classifier can't resolve). It's the visible tell that the routing is fallback, not a deliberate semantic placement. Renaming it to `sealed-secrets/` (the controller name) would require a kind→controller map that we rejected for the same naming-A reason as before — derived/agnostic over hand-curated cosmetics.

**This is a known limitation, not a bug.** The principled fix is per-CR ownership signals (`metadata.annotations["helm.toolkit.fluxcd.io/name"]` set by Flux when a chart created the resource; `metadata.ownerReferences` for operator-created CRs; name-pattern heuristics as a last resort). Tracked as the per-CR-ownership follow-up. Note that even with the follow-up, some CRs will have no resolvable owner — hand-applied SealedSecrets sealed and applied directly (or committed into the gitops repo without an HR producing them) carry none of those signals. The follow-up will resolve MORE CRs, not all; the shared-tier fallback stays as the prune-safety floor for genuinely-unattributable CRs.

### Per-release env kustomization composition

Because Clause 6 puts the values patch inside `apps/<env>/<release>/`, that directory's `kustomization.yaml` carries:
- `resources:` — every app-scoped CR co-located there + `../../base/<release>` (the base release scaffolding) so the HelmRelease is in scope to be patched.
- `patches:` — `<release>-values.yaml` targeting the HelmRelease.

`apps/<env>/kustomization.yaml` becomes a pure composer: lists each `<release>` subdirectory as a resource, no `patches:`, no `../base/<name>` references. Verified by render: `kustomize build apps/<env>/<release>/` produces a HelmRelease with the patched values applied (base's `version: '*'` becomes the env's pinned version, base's empty values block becomes the env's full values).

## A finding worth remembering: the standard assumes chart-managed app-scoped CRs

In the canonical `flux2-kustomize-helm-example`, **app-scoped operator CRs never appear as separate files**. podinfo's `HTTPRoute` is produced by the podinfo chart's templates via `spec.values.httpRoute.enabled: true` on the HelmRelease — never a standalone `apps/base/podinfo/httproute.yaml`. The only operator CR instances in the entire reference repo are `ClusterIssuer` and `Gateway`, both cluster-wide, both in `infrastructure/configs/`.

The standard is therefore **silent** on placement of app-scoped operator CRs as separate files because it assumes those CRs come from the chart. Butler exports them as separate files because it captures **discovered on-cluster state** — including CRs that exist on the cluster but aren't templated by the app's chart (SealedSecrets that hold encrypted data, hand-written ServiceMonitors, hand-written IngressRoutes, hand-written CNPG `Cluster` CRs that an operator manages but didn't templatize). The chart-managed assumption breaks for that class of resource; the standard doesn't model it; Clause 5 fills that gap by extending owner-follows-tier.

## Butler's rule, derived from the standard

### Clause 1 — `infrastructure/controllers/`

Controller-shaped operators (reconcile CRDs, are cluster dependencies others rely on) AND CRD producers. Helm release lives here as a single multi-doc file containing the (optional) target namespace + the source (HelmRepository/OCIRepository) + the HelmRelease.

Butler's interpretation extends the standard to specifically include `butler-controller` (cert-manager-analogous: an operator that reconciles Butler's own CRDs) and `steward` (operator-shaped CAPI control-plane component). These are caught by the `controllerReleaseNames` set in `layout_paths.go`; the standard does not directly name them, but their structural role matches cert-manager's clearly enough to apply the same placement.

- Citation: flux2-kustomize-helm-example README, `infrastructure/controllers/` description (direct).
- Interpretation: butler-controller and steward placement (cert-manager-analogous, by structural role).

### Clause 2 — `infrastructure/configs/` (cluster-wide CR instances ONLY)

Operator CR instances and configurations owned by **the cluster**, not by any specific app. Examples from the canonical reference: cert-manager `ClusterIssuer`, Envoy `GatewayClass` + `Gateway` (one gateway used by many apps). Examples for Butler: `IdentityProvider`, `NetworkPool`, `ProviderConfig`, MetalLB `IPAddressPool` + `L2Advertisement`, `ClusterCreationPolicy`, `Team`, cluster-level RBAC for platform components.

**App-scoped operator CRs (SealedSecret for an app's DB, ServiceMonitor for an app, IngressRoute for an app, CNPG `Cluster` that IS an app's database) do NOT belong here — they go with their owning app per Clause 5.**

The classifier identifies "cluster-wide" by a native CR's namespace not matching any HelmRelease's `targetNamespace` (no owning app), or by living in a namespace that the broader `infrastructureNamespaces` set marks as platform-level.

The standard handles env-specific overrides on cluster-wide CRs via Kustomize patches in `clusters/<env>/infrastructure.yaml` (e.g. patching ClusterIssuer's ACME server per env), not by splitting them across `apps/<env>/`.

- Citation: flux2-kustomize-helm-example README + actual `infrastructure/configs/` contents (direct).
- Interpretation: cluster-wide-vs-app-scoped is the splitter between Clause 2 and Clause 5; the standard doesn't name this distinction but owner-follows-tier forces it.

### Clause 3 — `apps/base/` + `apps/<env>/`

Workloads that are not controllers — UIs, APIs, application stacks. For Butler this is butler-console, butler-server, butler-addons, and anything a tenant deploys. Each workload's `apps/base/<release>/` directory holds the source + release scaffolding + co-located namespace. `apps/<env>/<release>-values.yaml` carries the env-specific overlay (Kustomize strategic-merge patch on the HelmRelease).

The standard does not directly address UI/API components like butler-console; the live butler/seed deployment places them in `apps/base` and the placement is consistent with the "workloads, not controllers" reading of the standard.

- Citation: flux2-kustomize-helm-example README, `apps/base/` description (direct, including the podinfo example with co-located `namespace.yaml`).
- Interpretation: butler-console, butler-server, butler-addons are workloads; non-controllers default to apps under the rule.

### Clause 4 — Namespace placement: NEVER classified standalone

Namespaces travel with their owning HelmRelease. Two equivalent patterns from the canonical reference:
- **Co-located as a separate file**: `apps/base/podinfo/namespace.yaml` next to `release.yaml`.
- **Inline as the first YAML doc in the HR file**: `infrastructure/controllers/cert-manager.yaml` opens with the cert-manager Namespace, then OCIRepository, then HelmRelease.

Butler's emit path uses the co-located-file pattern for `apps/base/<release>/namespace.yaml` and the inline pattern for `infrastructure/controllers/<release>.yaml`, matching the canonical reference's actual structure in each tier.

**Orphan namespaces** (no HelmRelease claims them via `targetNamespace`): not emitted. The prior synthesized `apps/<env>/<name>-namespace.yaml` pattern was a Butler invention, not in the standard. Skipped namespaces surface in `coverage.yaml` under `omittedNamespaces` with a reason so the operator sees what wasn't emitted and can either link the namespace to an owning HelmRelease or manage it outside the export.

- Citation: flux2-kustomize-helm-example contents (direct verification of both patterns in the canonical repo).
- Supersedes: ADR-016's "one ratified kind special-case" (Namespace → `apps/<env>/<name>-namespace.yaml` unconditionally) AND the intermediate amendment (Namespace → `infrastructure/configs/` when name matched the broader infra-namespaces set). Both prior rules were classifying namespaces standalone — a frame the Flux2 standard does not use.

### Clause 5 — App-scoped operator CR instances co-locate with their owning release at the env layer

**Second application of owner-follows-tier.** A native operator CR (SealedSecret, ServiceMonitor, IngressRoute, CNPG `Cluster`, etc.) whose namespace matches some HelmRelease's `targetNamespace` is owned by that release. It travels with the release at the env layer:

```
apps/<env>/<owning-release>/<filename>.yaml
```

Mirroring `apps/base/<release>/` from Clause 4 but at the env layer because these CRs are typically env-specific (SealedSecret ciphertext, ServiceMonitor labels, CNPG `Cluster` storage class). Strict base co-location would be wrong; env-layer co-location is consistent with Clause 4 once the env-specific requirement is applied.

Filename derivation stays agnostic: `<kind-lowercase>-<name>.yaml`, with a `-<namespace>-` segment when disambiguation is needed. No kind→concept-name map (Butler keeps paths derived from cluster-resolvable signals).

When a native CR's namespace has no HelmRelease owner AND the CR isn't cluster-scoped, it falls back to `apps/<env>/<group>/<filename>.yaml` (vendor-grouped). That's the only place vendor-grouping appears now — for prune-safety, not for owned items.

- Citation: standard is silent (see the "chart-managed assumption" finding above). The two applications of owner-follows-tier — Clause 4 (namespaces) and Clause 5 (CRs) — are the consistent reading of the principle, not separate rules.
- Supersedes: the prior `apps/<env>/<operator-group>/<verbose-name>.yaml` shape that divorced CRs from their owning apps.

### Clause 6 — Strategic-merge values patch co-locates with its release at the env layer

**Third application of owner-follows-tier.** The `<release>-values.yaml` env overlay is owned by the HelmRelease it patches. It travels with the release at the env layer:

```
apps/<env>/<owning-release>/<release>-values.yaml
```

Same directory as Clause 5's CRs. The per-release env kustomization at `apps/<env>/<release>/kustomization.yaml` carries `resources: [<CRs>, ../../base/<release>]` and `patches: [{path: <release>-values.yaml, target: {kind: HelmRelease, name: <release>}}]`. The base reference brings the HelmRelease into scope so the strategic-merge patch can target it.

`apps/<env>/kustomization.yaml` becomes a pure composer: lists each `<release>` subdir as a resource, no `patches:` block, no `../base/<name>` references.

**Why this shape vs the standard's flat `apps/<env>/<release>-values.yaml`:** the canonical flux2 example has one app per env and a single env-root kustomization with all patches inline. That trivially works at small scale. For Butler exporting multi-app clusters, keeping the values patch at the env root (flat) while CRs co-locate (nested) created a visible inconsistency where two app-scoped things sat in different shapes. Applying owner-follows-tier uniformly to the patch construct removes the inconsistency. The patch lives where its applying kustomization lives (Kustomize's own resolution rule); the applying kustomization is now per-release at the env layer.

**Render-verified.** `kustomize build apps/<env>/<release>/` produces a HelmRelease whose `spec.chart.spec.version` is the env-pinned version (was `'*'` in base) and `spec.values` carries the live values block (was empty in base). The strategic-merge patch correctly applies to the HelmRelease loaded transitively from `../../base/<release>`. Both `kustomize build` and `kubectl kustomize` exit 0.

- Citation: standard is silent on multi-app env composition; the standard's flat-values pattern is what's shown in a single-app example. The patch-lives-with-its-kustomization mechanic is direct Kustomize semantics, not an interpretation.
- Interpretation: applying owner-follows-tier uniformly to the third construct, parallel to Clauses 4 and 5. Not a new principle.
- Supersedes: the prior flat `apps/<env>/<release>-values.yaml` shape with patches in `apps/<env>/kustomization.yaml`.

## Divergences from the live butler/seed deployment

The live `iocs-compute/butler/seed/live-infrastructure` repo at `clusters/butler/` is one real-world hand-maintained example. Comparing Butler's export to that repo as a check:

| Item | Standard / Butler export | Live butler/seed | Decision |
|---|---|---|---|
| `infra/controllers/` for cert-manager-shaped operators | ✓ | ✓ | Both agree |
| `infra/configs/` for operator CR instances | ✓ (IdentityProvider/NetworkPool/ClusterCreationPolicy land here) | Puts these in `apps/prd/` | **Follow the standard.** The live repo's placement is non-standard. |
| `apps/base/butler-console`, `apps/base/butler-server` (workloads) | ✓ | ✓ | Both agree |
| `apps/base/butler-addons` (workload-style, not a CRD-reconciling controller) | ✓ | ✓ | Both agree |
| `infra/controllers/butler-controller` (CRD-reconciling controller) | ✓ | Puts in `apps/base/butler-controller` | **Follow the standard.** butler-controller is structurally cert-manager-analogous. |
| `infra/controllers/steward` (operator-shaped CAPI component) | ✓ | Puts in `apps/base/steward` | **Follow the standard** (interpretation by analogy). |
| Namespace co-location with owner | ✓ | ✓ (`apps/base/butler-addons/namespace.yaml`, `apps/base/steward/namespace.yaml`) | Both agree |
| Synthesized standalone Namespace files in `apps/<env>/` | Not emitted | Not present | Both agree |

The divergences (butler-controller + steward placement; CR instances in apps vs infra/configs) reflect that the live butler/seed repo was hand-maintained against an earlier non-standard understanding. Butler's export is OSS and ships the standard-aligned structure so that any deployment receives a correct tree regardless of what one existing repo happens to have.

## Code anchors

Future sessions land here to find the load-bearing functions for each clause. Anchors match the post-B2 shape; if a future change moves any of these, update this section in the same commit so future-session lookup doesn't trip on a stale name.

- `internal/gitops/layout_paths.go`:
  - `classifyUnmatchedRelease` — three-signal classifier (ChartInstallsCRDs → infra; `controllerReleaseNames` → infra; `helmControllerNamespaces` → infra; else apps).
  - `classifyNativeTier` — two-tier classifier (cluster-scoped or infra-namespace → infra; else apps). Namespace kind is intentionally not classified here.
  - `PathForNative(n, env, helmOwnerByNamespace)` — single path-resolution function for native CRs. Takes the owner map as its third arg; app-tier branch consults it for Clause 5 co-location.
  - `controllerReleaseNames` — the named-controller set (Butler's interpretation extension): butler-controller, steward.
  - `helmControllerNamespaces` — the curated Helm-release namespace fallback set (excludes butler-system).
  - `infrastructureNamespaces` — the broader set used by `classifyNativeTier` for CR instances (includes butler-system as a multi-owner shared namespace).
- `internal/gitops/layout_v2.go`:
  - `emitInfrastructureRelease` — Clause 1 + Clause 4 inline pattern: namespace as first doc in the multi-doc HR file at `infrastructure/controllers/<release>.yaml`.
  - `emitAppRelease` — Clauses 3 + 4 + 6: writes `apps/base/<release>/{namespace,repository,release,kustomization}.yaml` and the values patch at `apps/<env>/<release>/<release>-values.yaml`.
  - `emitNativeResources` — runs `AnalyzeNativePathCollisions` with `helmAppsOwnerByNamespace(hr)` for owner-aware routing.
  - `AnalyzeNativePathCollisions(items, helmOwned, helmAppsOwner, env)` — single source of truth for path resolution + Namespace-skip + path collisions. Both emit (`emitNativeResources`) and coverage (`BuildCoverage`) consume the same analysis with the same args.
  - `helmOwnedNamespaces` — namespace-name set for HelmRelease target namespaces (any tier). Used by `BuildCoverage` to identify orphan namespaces for `OmittedNamespaces`.
  - `helmAppsOwnerByNamespace` — namespace → apps-tier owning-HR-name map. The Clause-5/6 load-bearing lookup: when present for a CR's namespace, the CR co-locates under `apps/<env>/<owner>/`. Infra-tier releases are intentionally NOT in this map (their namespaces' CRs route via `classifyNativeTier`'s infra-namespace check to `infra/configs/`).
  - `buildEnvKustomizationOverride` — apps/<env>/kustomization.yaml synthesis: PURE COMPOSER under B2. Lists each release subdir as a resource; no `patches:` block; no `../base/<name>` references. Those moved into the per-release env kustomization.
  - `buildEnvReleaseKustomizationOverride` — apps/<env>/<release>/kustomization.yaml synthesis: adds `../../base/<release>` to resources and the strategic-merge `patches:` block targeting the HelmRelease. Clause 6's per-release env unit.
- `internal/gitops/coverage.go`:
  - `CoverageReport.OmittedNamespaces` — the orphan-namespace surface (multi-owner-edge limitation documented above).
  - `BuildCoverage` — calls `AnalyzeNativePathCollisions` with the same `helmAppsOwnerByNamespace` map as emit; populates `OmittedNamespaces` from `helmOwnedNamespaces` diff against native Namespace items.
- Golden fixtures under `internal/gitops/testdata/{loki-dev,observability-pipeline-prd}/expected/` — the standard-aligned tree per the rule above. Regenerate via `cmd/gitops-fixture-dump` if a future legitimate rule change requires rebaselining; see `testdata/README.md`.

## Follow-up: per-CR ownership signals (resolves more, not all)

Scope: extend the classifier so per-CR ownership beats namespace-as-proxy when a real signal is available. Then a `SealedSecret` carrying `metadata.annotations["helm.toolkit.fluxcd.io/name"] = "butler-controller"` would route to butler-controller's directory regardless of where its namespace would otherwise fall, resolving the multi-owner-namespace ambiguity for CRs that have a signal.

Signals to consult, in priority order:

1. **Flux's ownership annotation**: `metadata.annotations["helm.toolkit.fluxcd.io/name"]` + `metadata.annotations["helm.toolkit.fluxcd.io/namespace"]` — set by the Helm controller on resources its HelmRelease's chart produced. Direct provenance from the cluster.
2. **`metadata.ownerReferences`**: set when an operator creates the CR (e.g., a cert-manager `Certificate` owned by a `CertificateRequest`). Walk owners to a root that maps to a HelmRelease.
3. **Name-pattern heuristic**: weak last resort. `<release-name>-*` patterns (e.g., `butler-console-tls` → butler-console). Surface in coverage as a heuristic match so operators can audit.

Discovery needs to capture (1) and (2) on each discovered native item; classifier needs to consult them BEFORE falling back to the namespace-based map; coverage report should surface the resolution path (annotation vs ownerRef vs heuristic vs namespace-map vs fallback).

**Eyes open on the gap.** Some CRs carry none of those signals — most notably hand-applied `SealedSecret`s that get sealed-and-applied directly or are committed in the gitops repo by an operator without an HR producing them. Those CRs will not gain ownership resolution from this follow-up; they'll still hit the shared-tier fallback (`infrastructure/configs/<group>/<filename>.yaml`) as the prune-safety floor. The follow-up resolves MORE CRs, not all. The fallback isn't going away; it's getting smaller.

Scope explicitly excludes:
- Maintaining a hand-curated kind→controller mapping for cosmetic subdir renaming (rejected for the same naming-A reasons; doesn't address ownership, just changes display).
- Inferring ownership from helm release secret discovery (already done by the Helm path for HelmReleases themselves; native CR resources don't carry the same labeling).

Out-of-scope for this amendment; tracked as a separate work item.

## Re-verifying this note in a future session

If a session questions any clause:
1. Open the cited Source file in the fluxcd repo at the cited path. Quote the passage. Diff against this note.
2. Pull the actual repo contents via `gh api repos/fluxcd/<repo>/contents/<path>` if the live source has moved or changed since this note was written.
3. If the standard has evolved, write a new amendment recording the source change. Do not silently update the rule.

The rule is the source-anchored interpretation, not the live deployment's choices. Re-derive only if the cited sources have changed; otherwise, the rule stands.
