# ADR-015: AddonDefinition GitOps Tier Field

## Status

Proposed

## Date

2026-04-29

## Context

Butler's GitOps export feature places addon manifests into either
`infrastructure/` or `apps/` within a tenant cluster's directory structure.
This two-directory layout matches the Flux community convention (documented
in `flux2-kustomize-helm-example`) where `infrastructure/` holds platform
prerequisites (CRD providers, storage, networking) and `apps/` holds
workloads. Flux Kustomization resources can enforce ordering between the
two tiers via `dependsOn`, ensuring CRDs exist before workloads that
create custom resources.

The export feature determines which directory to use via
`categoryFromPlatform()` in `internal/gitops/discovery.go:474-479`:

```go
func categoryFromPlatform(platform bool) string {
    if platform {
        return "infrastructure"
    }
    return "apps"
}
```

The `Platform` boolean on `AddonDefinitionSpec` was designed for a
different purpose: it marks addons that are installed during cluster
bootstrap and cannot be uninstalled via the UI. The six platform addons
(cilium, metallb, cert-manager, longhorn, traefik, metrics-server) happen
to be infrastructure, so the mapping works for them. But several non-platform
addons also belong in `infrastructure/` from a Flux ordering perspective:

| Addon | Platform? | Correct tier | Why infrastructure |
|-------|-----------|-------------|-------------------|
| prometheus-operator | false | infrastructure | Installs ServiceMonitor, PodMonitor, PrometheusRule CRDs. Charts enabling `serviceMonitor.enabled: true` fail on fresh deploy if these CRDs don't exist. |
| sealed-secrets | false | infrastructure | Installs SealedSecret CRD. Other addons reference SealedSecrets for credential distribution. Butler Labs' own live repos place sealed-secrets in infrastructure/. |
| external-secrets | false | infrastructure | Installs ExternalSecret, SecretStore CRDs. Same pattern as sealed-secrets. |
| cnpg | false | infrastructure | Installs Cluster, Backup, ScheduledBackup CRDs. Database workloads depend on these CRDs existing. |

These addons are not platform (they're optional, user-installable,
uninstallable) but they are infrastructure (they provide CRDs that other
addons depend on). The current code conflates these two concepts, causing
the export feature to place them in `apps/` where Flux cannot enforce
ordering relative to their consumers.

The `Category` field (14-value enum: cni, loadbalancer, storage, etc.)
is a UI grouping concept, not an ordering concept. It serves a different
purpose and should not be overloaded for directory placement.

Three call sites use the platform-to-category mapping:

1. **Discovery** (`discovery.go:144`): `categoryFromPlatform(addonDef.Spec.Platform)` sets `.Category` on matched releases.
2. **ExportAddon handler** (`gitops.go:601-604`): `if addonDef.Spec.Platform` selects infrastructure vs apps path.
3. **ExportRelease handler** (`gitops.go:864-867`): `if release.Category == "infrastructure"` selects path.

The migration handler (`gitops.go:1050-1051`) allows a `Category` override per release, but this is a per-request escape hatch, not a persistent declaration.

## Decision

Add an optional `Tier` field to `AddonDefinitionSpec` with enum values
`infrastructure` and `apps`. The export feature reads `Tier` first; if
unset, falls back to inferring from `Platform`.

### API surface

```go
// AddonTier defines the GitOps directory tier for export placement.
// +kubebuilder:validation:Enum=infrastructure;apps
type AddonTier string

const (
    AddonTierInfrastructure AddonTier = "infrastructure"
    AddonTierApps           AddonTier = "apps"
)
```

On `AddonDefinitionSpec`:

```go
// Tier controls which directory the addon is placed in during GitOps
// export: "infrastructure" or "apps". Infrastructure-tier addons are
// exported to the infrastructure/ directory, where Flux can enforce
// ordering before apps/ reconciles.
//
// If not set, inferred from Platform: platform addons default to
// "infrastructure", non-platform addons default to "apps".
// +optional
Tier AddonTier `json:"tier,omitempty"`
```

### Export logic change

Replace `categoryFromPlatform()` with `tierForAddon()`:

```go
func tierForAddon(ad *v1alpha1.AddonDefinition) string {
    if ad.Spec.Tier != "" {
        return string(ad.Spec.Tier)
    }
    if ad.Spec.Platform {
        return "infrastructure"
    }
    return "apps"
}
```

All three call sites switch from `categoryFromPlatform(ad.Spec.Platform)`
to `tierForAddon(ad)`. The handler in `gitops.go:601-604` switches from
checking `addonDef.Spec.Platform` to calling `tierForAddon(addonDef)`.

### Addon catalog changes

Four addons in `butler-addons/templates/optional.yaml` get
`tier: infrastructure` added to their spec:

- `prometheus-operator` (line 14)
- `sealed-secrets` (line 620)
- `external-secrets` (line 584)
- `cnpg` (line 763)

All other optional addons remain without a `tier` field (defaulting to
`apps` via the fallback logic).

Platform addons in `platform.yaml` remain without a `tier` field
(defaulting to `infrastructure` via the `Platform: true` fallback).

### Why not overload Platform

Making these addons `platform: true` would fix the directory placement but
break the UI and lifecycle semantics. Platform addons cannot be uninstalled
through the Butler UI, are installed during bootstrap, and appear in a
separate "Platform" section. prometheus-operator is genuinely optional on
a tenant cluster. A user should be able to install it, export it to
infrastructure/, and later uninstall it. `Platform` and `Tier` are
orthogonal.

### Why not overload Category

`Category` is a UI grouping enum with 14 values (cni, loadbalancer,
observability, etc.). Using it for directory placement would require
maintaining a mapping from 14 categories to 2 directories, and every
new category would need a placement decision. Categories group addons
for discovery; tiers group addons for ordering. Different axes.

### Why not a freeform string

The directory layout is binary: `infrastructure/` or `apps/`. A freeform
tier field invites values like "platform", "core", "prereqs" that have
no corresponding directory. The enum is intentionally narrow.

### Backwards compatibility

- `Tier` is optional with zero value. Existing AddonDefinition CRDs
  without `tier` continue to work via the `Platform` fallback.
- Existing export output changes only for the four addons that gain
  `tier: infrastructure`. Their manifests move from `apps/` to
  `infrastructure/` in newly exported repos. Previously exported repos
  are not modified.
- The `Platform` field is unchanged. No deprecation.
- `categoryFromPlatform()` is removed. Any code importing it gets a
  compile error pointing to `tierForAddon()`.

## Implementation

Four PRs, merged in order:

### PR 1: butler-api

- Add `AddonTier` type and constants to `addondefinition_types.go`
- Add `Tier AddonTier` field to `AddonDefinitionSpec`
- Run `make generate` to update deepcopy and CRD manifests
- Unit test: verify zero-value Tier passes CRD validation

### PR 2: butler-server

- Add `tierForAddon()` to `internal/gitops/discovery.go`
- Replace `categoryFromPlatform()` call at line 144 with `tierForAddon()`
- Update `ExportAddon` handler (`gitops.go:601-604`) to use `tierForAddon()`
- Update `ExportRelease` handler (`gitops.go:864-867`) to use tier logic
- Remove `categoryFromPlatform()`
- Unit tests: verify tier resolution (explicit tier, platform fallback, default)
- Integration test: verify export places prometheus-operator in infrastructure/

Depends on PR 1 (butler-api module version bump).

### PR 3: butler-charts

- Add `tier: infrastructure` to prometheus-operator, sealed-secrets,
  external-secrets, cnpg in `optional.yaml`
- Sync CRD from butler-api (includes new `tier` field in CRD manifest)
- Bump butler-addons chart version

Depends on PR 1 (CRD schema).

### PR 4: butler-console (optional, can follow later)

- Display tier in addon detail view if present
- No functional change; informational only

Independent of PRs 1-3.

## Consequences

### Positive

- Export feature places CRD-providing addons in `infrastructure/` where
  Flux ordering can enforce CRD-before-consumer sequencing.
- Tenant owners who export to self-managed GitOps get a correct
  three-tier layout without manual directory moves.
- `Platform` retains its original lifecycle meaning. No semantic overload.
- Four-line server change. Minimal blast radius.

### Negative

- A new field on the CRD requires a CRD sync to butler-charts and a
  chart version bump. This is mechanical but adds a PR to the chain.
- Operators with existing exported repos see no automatic migration.
  Previously exported prometheus-operator directories remain in `apps/`
  until manually moved or re-exported.

### Deferred

- **Three-tier layout with explicit Flux Kustomization dependsOn.**
  The Flux reference repo uses `infrastructure.yaml` and `apps.yaml`
  Kustomizations with `dependsOn` between them. Butler's bootstrap
  structure generator could emit these. Deferred because the tier
  field is prerequisite; without correct directory placement, the
  Kustomization dependsOn has nothing to order. Tracked in
  butlerdotdev/butler-controller#79.
- **UI for tier selection.** Custom AddonDefinitions could expose a
  tier dropdown. Deferred until demand exists.
- **Validation webhook.** Reject `tier: infrastructure` on addons
  that depend on other addons (circular ordering risk). Not needed
  at current scale.

## References

- `butler-api/api/v1alpha1/addondefinition_types.go`: AddonDefinitionSpec schema
- `butler-server/internal/gitops/discovery.go:474-479`: `categoryFromPlatform()` being replaced
- `butler-server/internal/gitops/provider.go:169-176`: `GetCategoryPath()` that consumes the category string
- `butler-server/internal/api/handlers/gitops.go:601-604`: ExportAddon handler
- `butler-server/internal/api/handlers/gitops.go:864-867`: ExportRelease handler
- `butler-charts/charts/butler-addons/templates/optional.yaml`: Addon catalog
- `flux2-kustomize-helm-example`: Flux reference repo structure
- butlerdotdev/butler-controller#79: Broader categorization discussion
