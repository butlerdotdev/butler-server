# ADR-018: ArgoCD Support

## Status

Proposed (2026-05-24, awaiting ratification). This ADR's foundation depends on ADR-017 (gitops-export tenant cluster support, currently on `feat/adr-017-gitops-export-tenant-support`); ratification anticipates ADR-017 landing first.

## Date

2026-05-24

## Context

Butler is gitops-native and Flux-based. The gitops-export feature (ADR-016 resource coverage, ADR-017 tenant cluster support) reads a cluster's Flux-managed state and emits a canonical repo: `clusters/<cluster>/`, `infrastructure/{controllers,configs}/`, `apps/{base,<env>}/`. Discovery is agnostic (read what's on the cluster). Placement is opinionated by tier (infra vs app, namespaced vs cluster-scoped). DirectoryAccumulator synthesizes per-directory `kustomization.yaml` so prune-safety holds. Coverage report surfaces captured, filtered, and defaulted resources.

We are adding ArgoCD as a supported gitops engine alongside Flux. Two coupled questions:

1. **Deployment model.** How does Argo run in a Butler-managed environment?
2. **gitops-export additions.** What Argo-equivalent artifacts does the export emit?

The first is load-bearing; the second follows from it.

The Argo ecosystem assumes a central control plane by default. Akuity (the company founded by Argo CD's creators) frames hub-and-spoke as Argo's primary topology and recommends multiple hubs as the scaling answer. The Flux ecosystem assumes per-cluster. Butler users picking Argo can legitimately want either; the platform should expose the choice rather than impose one.

### Topology landscape

Three production deployment patterns are documented in the Argo ecosystem (sources in §References):

- **Standalone (per-cluster).** Argo on every cluster, managing only that cluster. Closest to how Butler runs Flux today. Small blast radius; N instances to operate; no single dashboard.
- **Hub-and-spoke (centralized).** One Argo on a hub cluster registers N workload clusters via cluster Secrets. Single pane of glass; hub holds privileged credentials for the fleet; controller OOMs past ~600 to 700 applications and ~100 clusters without sharding (industry-reported numbers, per CNOE and OneUptime writeups).
- **Agent-based (split control/data plane).** Application-controller runs on the workload cluster; a lightweight agent calls home to a "principal" for visibility. Maturity is `argoproj-labs/argocd-agent`, not core argoproj. Red Hat ships it as Technology Preview in OpenShift GitOps 1.19.

### What Argo gives us that Flux does not

Flux gives no topology choice (controller-on-the-cluster, full stop). Argo gives the choice. Different Butler users have different legitimate needs:

- Platform teams running gitops for a fleet of clusters want centralized: one console, one RBAC surface, one place to enforce policy.
- Single-team autonomous clusters want standalone: per-cluster isolation, no fleet-level dependency, the same shape as Flux today.

Forcing either onto users who want the other is a design failure. Supporting both well, in one shared implementation, is what this ADR commits to.

## Decision

### Load-bearing invariant: one Argo provider, two deployment modes

Butler adds one Argo provider to the gitops-export pipeline. That provider supports two deployment modes, **standalone** and **centralized**. The modes diverge at exactly two boundaries:

1. **Read-source.** Where the export reads Argo state from.
2. **Bootstrap.** What Butler installs or registers at cluster provision time.

Everything else (discovery contract, object mapping, placement rules, export machinery, self-management filtering) is shared.

Any future change proposing a third differentiator is challenged against this invariant. The cost of "support both" stays bounded only if the diverge surface stays small. If a proposed change cannot be expressed as a parameter to the shared provider, it does not belong in the Argo provider as a mode-specific code path; either lift it into the shared layer with parameterization, or reject it.

This invariant is the single most important thing this ADR commits to.

### Shared provider surface

The Argo provider lives alongside the Flux provider in `internal/gitops/`. Across both modes it shares:

- **Discovery contract.** Agnostic enumeration of `Application`, `AppProject`, `ApplicationSet`, and Argo `repository`-secret resources. The kubeconfig the discovery uses differs per mode; the discovery code is one piece, parameterized by source-cluster.
- **Object mapping.** Application maps to a directory tree (Helm source via `release.yaml` + `repository.yaml` shape; Kustomize source via directory reference; plain source via directory reference). AppProject maps to a cluster-tier file. Repository Secrets map to the cluster-tier, deduplicated by URL.
- **Placement rules.** Same tier rules as Flux (ADR-016): infra-namespace membership routes to `infrastructure/`; everything else routes to `apps/`. Same agnostic-where-Flux-taught-us principle: derive from cluster-resolvable fields, no per-kind hardcoded table.
- **Export machinery.** DirectoryAccumulator, coverage report, prune-safety. Designed to be engine-agnostic: the intent is that they operate on the rendered directory tree without knowing whether the source CR was Flux or Argo, standalone or centralized. This is an architectural bet, calibrated in §Consequences / What gets built.
- **Self-management filtering.** The Argo-managing-Argo Application (the bootstrap Application that points at the manifests installing Argo itself) is filtered out of the export, analogous to how the export filters `flux-system` Kustomizations today. The exact filter predicate (Application name, label, namespace, or source-path) is TBD at implementation: Flux's filter is namespace-based, but the Argo-managing-Argo Application may not live in a privileged namespace, so the predicate cannot be inherited directly.

If "support both" is cheap, it is cheap because most of the Argo provider is one codebase shared between the two modes.

### Mode (a): centralized (Butler-run hub)

Butler operates an Argo control plane on a designated hub cluster. Workload clusters are registered as cluster Secrets on the hub. All Applications, AppProjects, and ApplicationSets for the registered fleet live in the hub's `argocd` namespace.

- **Read-source for export of cluster X:** the hub. The export reads Applications whose `spec.destination.server` (or `spec.destination.name`) resolves to cluster X, plus the AppProjects referenced by those Applications and any repository Secrets they use.
- **Bootstrap at provision time:**
  - On the hub cluster: install Argo (if not already there) and the self-management Application.
  - On the workload cluster: create a service account / kubeconfig with appropriate scope, materialize a cluster Secret on the hub.
- **Butler operational scope:** running the Argo control plane on the hub. Monitoring, upgrades, sharding when the fleet grows, backup of hub state, recovery if the hub is lost.

The hub-location sub-choice is decided below (§Hub location for centralized mode).

### Mode (b): standalone (per-cluster)

Argo runs on each workload cluster, managing only that cluster. Same shape as Flux today.

- **Read-source for export of cluster X:** cluster X itself. The export reads Applications and AppProjects from cluster X's `argocd` namespace directly.
- **Bootstrap at provision time:** install Argo on the workload cluster, plus the self-management Application that lets Argo update itself from git.
- **Butler operational scope:** the per-cluster Argo install lifecycle. Same shape as Butler's per-cluster Flux today.

### Default mode and selection guidance

**Default is standalone.**

Selection guidance Butler surfaces to operators:

- **Platform team running gitops for a fleet of clusters:** centralized.
- **Single-team autonomous cluster wanting Argo instead of Flux:** standalone.

Default matches the existing Flux experience (one cluster, one controller, no fleet-level dependencies) and biases the unopinionated user toward the lower-overhead choice.

### Mode mobility

Supported, but deliberate, not transparent. Mode is set at provision time and not changed accidentally.

- **Standalone to centralized:** uninstall on-cluster Argo, register the cluster into a hub, re-create Applications on the hub (export the on-cluster state, then re-apply against the hub).
- **Centralized to standalone:** install Argo on the workload cluster, materialize Applications targeting `https://kubernetes.default.svc`, deregister from the hub.

Both directions are scriptable; both require a documented migration. This ADR does not commit to in-place migration tooling for v1.

### Hub location for centralized mode

**Default: tenant-as-hub.** Within a tenant's fleet, one workload cluster is designated as the gitops hub for that tenant. Tenant-scoped Argo; each tenant has their own hub.

This default rests on two **independent** grounds. An operator could discount either and the other still recommends tenant-as-hub.

**Axis 1: blast radius (security).** Mgmt-hub puts every tenant's Application CRs and hub-side credentials to every tenant cluster on Butler's mgmt cluster. A mgmt-hub compromise is every tenant compromised. Tenant-as-hub keeps a tenant's Applications and creds within that tenant's blast radius. For multi-company / multi-tenant Butler instances this is the dominant concern. For single-tenant instances the delta is smaller (mgmt already has tenant hooks by design via capi-steward / provisioning), so this axis alone does not condemn mgmt-hub.

**Axis 2: operational load and state locality.** Independent of trust. The mgmt cluster is already state-heavy: capi-steward state, butler-controller state, provisioning records, the management plane itself. Adding an Argo control plane there piles fleet Application CRs, Argo's own state, controller load, and scaling/sharding burden as the fleet grows onto the cluster that already carries the most critical state in the system. Tenant-as-hub keeps that load off the already-loaded mgmt cluster and distributes it to where it is used. Operational, not security; holds for any operator regardless of trust assumptions.

**Mgmt-hub remains available with stated fit-conditions** (the rejected-default-but-available option):

- **Single-tenant / single-company Butler instances** where the blast-radius delta is small.
- **Operators who accept the added load on the mgmt cluster** and prefer one Argo to operate instead of one per tenant.
- Reuses existing connectivity. Mgmt already has kubeconfigs to tenant workload clusters from provisioning; little new wiring.

The platform documents both locations against both axes so the choice is reasoned per deployment, defaults to tenant-as-hub, and presents mgmt-hub as the documented option with its fit-conditions stated.

### External-hub-registration scope

A third scenario (the customer has a pre-existing corporate Argo hub operated outside Butler and wants Butler clusters registered into it) is **out of scope for v1**, but doored open architecturally.

The Argo provider's read-source is pluggable. The centralized provider is "kubeconfig-to-hub + destination filter." The design intent is for an external-hub provider to slot in the same way. v1 does not ship that mode; a future ADR may add it, and should preserve the load-bearing invariant when doing so. The export-semantic question below hints that mode (c) may pressure the invariant in ways modes (a) and (b) do not, which is one reason to defer the decision rather than commit to a clean slot-in here.

The export semantic question (read Applications from the external hub, or read what Argo has rendered onto the workload cluster under Argo's tracking label) is deferred to the future ADR that adds the mode.

### AppProject derivation

**Tenant maps to project.** One AppProject per Butler tenant, derived from cluster state. No hardcoded per-tenant table.

AppProject has no Flux analog. This is a new product-model decision about how Butler tenancy maps onto Argo's RBAC primitive, not a fallback inherited from the Flux design. The mapping is the natural one (tenant identity is already the boundary Butler enforces elsewhere) but the call is deliberate.

Derivation per mode:

- **Standalone mode:** the export reads tenant identity from cluster labels/annotations on the workload cluster (the same fields Butler already uses for tenancy resolution) and emits one AppProject per tenant.
- **Centralized mode:** the AppProject is already present on the hub (the hub is where tenancy is enforced). The export reads the AppProjects whose `spec.destinations` match cluster X.

The same agnostic-where-Flux-taught-us principle holds: derive from cluster-resolvable fields, no per-kind / per-tenant hardcoded table.

### ApplicationSet posture

**v1 emits bare Applications. ApplicationSets are deferred.**

ApplicationSets are a templating layer that pays off mostly when one logical workload fans out across labeled clusters (the cluster generator). For per-cluster standalone Argo, ApplicationSets do not add much. For centralized mode they become more interesting but require Butler to take an opinion on the generator topology (list vs cluster vs git vs matrix) that we do not have evidence to make yet.

Deferred, not rejected. A future ADR may add ApplicationSet emission when the centralized-mode patterns settle.

### argocd-agent posture

**v1 does not depend on argocd-agent.**

Both supported modes use vanilla Argo. `argocd-agent` is argoproj-labs (incubation), not core argoproj; Red Hat ships it as Technology Preview. argocd-agent autonomous mode is a future enhancement that adds optional principal-mirroring to either Butler mode without changing the export read-source for standalone (Application CRs still live on the workload cluster).

When and if argocd-agent graduates, a follow-up ADR may add optional agent-based topology as a third deployment shape. Until then, vanilla Argo is the supported runtime.

### Bootstrap mechanic

**Hand-rolled Argo install + self-management Application.** Matches how Butler installs other controllers (Flux, sealed-secrets, etc.).

`argocd-autopilot` is taken as a guide for the repo structure (its directory layout informs what the export emits), not a runtime dependency. Butler does not invoke autopilot during provisioning; Butler emits the layout autopilot would have produced.

The bootstrap installs Argo into a Butler-managed namespace and creates the self-management Application pointing at the gitops repo's `clusters/<cluster>/argocd/` directory: the cluster-tier slot Butler already uses for engine-managed config, parallel to where Flux's `flux-system/` lives in the existing layout. From that point forward Argo manages its own configuration from git.

### Export interaction, per mode

Discovery read-source is the only piece of the export pipeline intended to change per mode. The design holds everything downstream (placement, file rendering, DirectoryAccumulator, coverage, prune-safety, repo write) identical across modes. Whether that intent survives contact with Argo's object model is the architectural bet called out in §Consequences; implementation will prove or disprove it the same way ADR-016 and ADR-017 did.

| Mode | Discovery kubeconfig | Discovery filter | Cluster identity resolution |
|---|---|---|---|
| Standalone | Workload kubeconfig (X itself) | All Applications/AppProjects in X's `argocd` namespace | X knows itself; no reverse-lookup |
| Centralized | Hub kubeconfig | Applications/AppProjects whose `spec.destination` resolves to cluster X | Hub's cluster Secret naming for X may differ from Butler's name for X; reverse-lookup needed |

The reverse-lookup for centralized mode is the one piece of net-new logic. Butler already knows the workload cluster identity from CAPI / provisioning state; the hub may use a different name. The cluster Secret has both `name` and `server` fields; the export resolves X by matching `server` to the workload cluster's API endpoint, then reads the slice of the hub catalog whose `destination.server` (or `destination.name`) matches.

## Consequences

### What gets built

An `argocd_provider.go` (or equivalent) parallel to the Flux provider in `internal/gitops/`. The provider implements:

- Discovery against a kubeconfig + namespace, returning `Application`, `AppProject`, `ApplicationSet`, repository Secrets.
- Cluster-identity reverse-lookup for centralized mode.
- Object-to-tree mapping: Helm source renders to `release.yaml` + `repository.yaml`; Kustomize source renders as a directory reference; plain source renders as a directory reference.
- Bootstrap wiring (install Argo + self-management Application) for both modes.

DirectoryAccumulator, coverage, prune-safety, layout_v2 are **designed to be reused unchanged**. This is an architectural bet on engine-agnostic export machinery, not a verified fact. The bet gets validated at implementation time against the same local-against-live + prune-safety property tests ADR-016 and ADR-017 used. Where the reuse does not hold, the provider takes the path those ADRs did: lift the divergence into the shared layer with parameterization, or document it as a deliberate engine-specific case. The decision to ship "one provider, two modes" rests on this bet being good in expectation, not on it being pre-validated; implementation surfaces any place it isn't.

### What Butler is on the hook for, per mode

- **Standalone:** per-cluster Argo install lifecycle (install, upgrade, uninstall). Same shape as Flux today.
- **Centralized:** per-tenant hub Argo install lifecycle on the designated tenant-as-hub cluster (default) or on the mgmt cluster (opt-in). Plus hub-side state hygiene (cluster Secrets, AppProjects, repository Secrets) and scaling guidance as the registered fleet grows.

### Tenancy

- **Standalone:** tenancy boundary is the cluster, as today.
- **Centralized (tenant-as-hub):** tenancy boundary is the tenant hub. One tenant's hub cannot see another tenant's Applications.
- **Centralized (mgmt-hub):** tenancy boundary is the AppProject. All tenants' Applications co-exist on the mgmt cluster, isolated by AppProject role policies and destination allowlists. Real but weaker than tenant-as-hub.

### Migration from Flux

Out of scope for this ADR. A separate ADR may add Flux to Argo migration tooling (export Flux state, render as Argo Applications, apply, uninstall Flux). The export pipeline this ADR builds is the building block.

### Invariant erosion risk

The one-provider-two-modes invariant is the main risk vector. If a future change adds mode-specific behavior beyond read-source + bootstrap (mode-specific placement, mode-specific object mapping, mode-specific filtering), the cost of "support both" doubles instead of staying bounded. Reviewers reject such changes or propose lifting the new behavior into the shared provider with parameterization.

## Alternatives Considered

### Per-mode separate implementations

Two separate Argo providers, one per mode, with their own discovery / mapping / placement code paths. Rejected: doubles surface area for no benefit. The two modes share discovery contract, object mapping, placement, and export machinery. The invariant exists to prevent this drift.

### Add a third differentiator beyond read-source + bootstrap

Naming the proposed differentiators so the rejection is explicit:

- **Mode-specific placement rules** (centralized mode emits to a different repo layout). Rejected: the export's value is consistency; the repo layout is a property of the workload cluster, not of the gitops engine's deployment shape.
- **Mode-specific filtering** (centralized mode hides certain Application kinds). Rejected: filtering should be derived from cluster state, not mode.
- **Mode-specific object mapping** (centralized mode renders Helm sources differently). Rejected: an Application's Helm source has one canonical rendering regardless of where the Application CR lives.

Keeping the diverge surface bounded is what makes "support both" cheaper than "pick one and explain the rejection."

### Mgmt-hub as default for centralized mode

Rejected on two independent grounds (Axis 1: blast radius; Axis 2: operational load on the already-state-heavy mgmt cluster). Kept as a called-out option with stated fit-conditions (single-tenant Butler instances; operators who accept the added load on mgmt). Documented above (§Hub location for centralized mode).

### argocd-agent as a v1 dependency

Rejected for v1. argoproj-labs maturity; Red Hat ships it as Technology Preview. Autonomous mode is additive: it does not change the export read-source for standalone (Application CRs still live on the workload cluster) and is a clean future addition without violating the load-bearing invariant.

### Hub-and-spoke as Butler's only mode

Rejected. Imposes the Argo ecosystem default on Butler users who want per-cluster autonomy. The platform's value is exposing the choice Argo offers, not narrowing it.

### Standalone as Butler's only mode

Rejected. Ignores the platform-team-running-fleet use case Argo serves well. A Butler that only supports standalone Argo would force fleet operators to operate their own hub outside Butler, recreating the external-hub-registration shape this ADR defers.

### ApplicationSets in v1

Deferred (§ApplicationSet posture). Not rejected on principle; deferred on evidence-not-yet-in.

### External-hub-registration in v1

Deferred (§External-hub-registration scope). Doored open via the pluggable read-source.

### argocd-autopilot as runtime dependency

Rejected. Butler emits the layout autopilot would have produced, without depending on the tool. Hand-rolled install matches how Butler treats other controllers.

## References

ADRs this builds on:

- ADR-016: GitOps Export Resource Coverage (this repo, on main).
- ADR-017: GitOps Export Tenant Cluster Support (this repo, on `feat/adr-017-gitops-export-tenant-support`, awaiting merge).

Argo CD documentation:

- [Application Specification Reference](https://argo-cd.readthedocs.io/en/latest/user-guide/application-specification/)
- [Cluster Bootstrapping (App of Apps)](https://argo-cd.readthedocs.io/en/stable/operator-manual/cluster-bootstrapping/)
- [Cluster Generator (ApplicationSet)](https://argo-cd.readthedocs.io/en/stable/operator-manual/applicationset/Generators-Cluster/)
- [Declarative Setup: cluster + repo secrets](https://argo-cd.readthedocs.io/en/stable/operator-manual/declarative-setup/)
- [Helm source: multi-source valueFiles](https://argo-cd.readthedocs.io/en/stable/user-guide/helm/)

Deployment topology landscape:

- [Akuity: 3 Most Common Argo CD Architectures](https://akuity.io/blog/argo-cd-architectures-explained)
- [Red Hat: multi-cluster GitOps with Argo CD Agent](https://www.redhat.com/en/blog/multi-cluster-gitops-argo-cd-agent-openshift-gitops)
- [CNOE: Argo CD benchmarking and sharding](https://cnoe.io/blog/argo-cd-application-scalability)
- [OneUptime: Scale ArgoCD for 1000+ Applications](https://oneuptime.com/blog/post/2026-02-26-scale-argocd-1000-applications/view)
- [OneUptime: How Many ArgoCD Instances Should I Run?](https://oneuptime.com/blog/post/2026-02-26-argocd-how-many-instances/view)
- [Centralized vs. Cluster-Located ArgoCD (Medium / PlanB)](https://medium.com/@PlanB./centralized-vs-cluster-located-argocd-whats-the-best-approach-for-your-kubernetes-environment-c6c40aa5c8a6)

Agent-based architecture:

- [argoproj-labs/argocd-agent](https://github.com/argoproj-labs/argocd-agent)
- [Argo CD Agent: Managing Applications](https://argocd-agent.readthedocs.io/latest/user-guide/applications/)
- [Argo CD Agent: General architecture](https://argocd-agent.readthedocs.io/latest/concepts/architecture/)
- [Red Hat OpenShift GitOps 1.19: Argo CD Agent architecture](https://docs.redhat.com/en/documentation/red_hat_openshift_gitops/1.19/html/argo_cd_agent_architecture/argocd-agent-architecture)
- [Akuity Platform Architecture](https://docs.akuity.io/overview/architecture/)

Repo-layout patterns:

- [Structuring Argo CD Repositories (Octopus)](https://octopus.com/blog/how-to-structure-your-argo-cd-repositories-using-application-sets)
- [App of Apps pattern (CNCF blog)](https://www.cncf.io/blog/2025/10/07/managing-kubernetes-workloads-using-the-app-of-apps-pattern-in-argocd-2/)
- [argocd-autopilot: Getting Started](https://argocd-autopilot.readthedocs.io/en/stable/Getting-Started/)
- [Multi-repo setup (OneUptime)](https://oneuptime.com/blog/post/2026-02-26-structure-multi-repo-setup-argocd/view)
