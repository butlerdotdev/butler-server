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
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"strings"

	butlerv1alpha1 "github.com/butlerdotdev/butler-api/api/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// Helm 3 stores releases as Secrets in the namespace where the release is
// installed. The secrets have label owner=helm and status=deployed.
// This approach is how production tools like Rancher, Lens, and Helm Dashboard
// discover releases without shelling out to the helm CLI.

// DiscoveryResult contains the results of Helm release discovery.
type DiscoveryResult struct {
	Matched      []*DiscoveredRelease `json:"matched"`
	Unmatched    []*DiscoveredRelease `json:"unmatched"`
	GitOpsEngine *GitOpsEngineStatus  `json:"gitopsEngine,omitempty"`
}

// GitOpsEngineStatus reports the status of GitOps tooling on a cluster.
type GitOpsEngineStatus struct {
	Provider   string   `json:"provider,omitempty"`
	Installed  bool     `json:"installed"`
	Ready      bool     `json:"ready"`
	Version    string   `json:"version,omitempty"`
	Components []string `json:"components,omitempty"`
	Repository string   `json:"repository,omitempty"`
	Branch     string   `json:"branch,omitempty"`
	Path       string   `json:"path,omitempty"`
}

// DiscoveredRelease represents a Helm release discovered on a cluster.
//
// Name is the Helm release name (from the release secret's labels), which
// is the chart's installation identity. The HelmRelease and HelmRepository
// CR fields identify the Flux custom resources that own this release on
// the cluster, when they exist — they are populated by an enrichment pass
// that walks all HR CRs and reads their metadata.{name,namespace} plus
// spec.chart.sourceRef.{name,namespace}.
//
// These are tracked separately because mgmt and tenant clusters diverge:
//   - HR CR vs Helm release name diverges when spec.releaseName is set
//     (mgmt's sealed-secrets HR has releaseName: sealed-secrets-controller).
//   - HelmRepository CR name diverges when chart publishers use names
//     differing from the release name (tenant's kube-prometheus-stack HR
//     references HelmRepository "prometheus-community", reflector references
//     "emberstack", strimzi-kafka-operator references "strimzi", etc.).
//
// Layout v2 sources its emitted CR names/namespaces from these fields so
// the export round-trips against the existing tree without collision.
// When unset (release has no Flux HR CR — e.g. helm-installed directly),
// layout v2 falls back to sanitized release-name reconstruction.
type DiscoveredRelease struct {
	Name                      string                 `json:"name"`
	Namespace                 string                 `json:"namespace"`
	Chart                     string                 `json:"chart"`
	ChartVersion              string                 `json:"chartVersion"`
	AppVersion                string                 `json:"appVersion,omitempty"`
	Status                    string                 `json:"status"`
	Revision                  int                    `json:"revision"`
	Values                    map[string]interface{} `json:"values,omitempty"`
	RepoURL                   string                 `json:"repoUrl,omitempty"`
	Category                  string                 `json:"category,omitempty"`
	AddonDefinition           string                 `json:"addonDefinition,omitempty"`
	Platform                  bool                   `json:"platform,omitempty"`
	HelmReleaseCRName         string                 `json:"helmReleaseCRName,omitempty"`
	HelmReleaseCRNamespace    string                 `json:"helmReleaseCRNamespace,omitempty"`
	HelmRepositoryCRName      string                 `json:"helmRepositoryCRName,omitempty"`
	HelmRepositoryCRNamespace string                 `json:"helmRepositoryCRNamespace,omitempty"`
	// ChartInstallsCRDs is true when the chart installs CRDs — either via
	// files in the chart's crds/ directory (helmChartData.CRDs non-empty)
	// or via any template containing `kind: CustomResourceDefinition`.
	// Used by classifyUnmatchedRelease (ADR-017 D2) to tier CRD-installing
	// charts as infrastructure regardless of namespace. Populated by
	// discovery for every release; unmatched releases consult it before
	// falling through to the namespace heuristic.
	ChartInstallsCRDs bool `json:"chartInstallsCRDs,omitempty"`
}

// DiscoverHelmReleases discovers all Helm releases on a cluster via the
// Kubernetes API and matches them against known AddonDefinitions.
func DiscoverHelmReleases(ctx context.Context, kubeconfig []byte, addonDefs []butlerv1alpha1.AddonDefinition) (*DiscoveryResult, error) {
	config, err := clientcmd.RESTConfigFromKubeConfig(kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse kubeconfig: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create clientset: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	addonLookup := buildAddonLookup(addonDefs)

	secrets, err := clientset.CoreV1().Secrets("").List(ctx, metav1.ListOptions{
		LabelSelector: "owner=helm,status=deployed",
	})
	if err != nil {
		return nil, fmt.Errorf("failed to list Helm secrets: %w", err)
	}

	latestReleases := make(map[string]*helmReleaseData)

	for _, secret := range secrets.Items {
		releaseData, err := decodeHelmRelease(secret.Data["release"])
		if err != nil {
			continue
		}

		key := fmt.Sprintf("%s/%s", releaseData.Namespace, releaseData.Name)
		if existing, ok := latestReleases[key]; ok {
			if releaseData.Version > existing.Version {
				latestReleases[key] = releaseData
			}
		} else {
			latestReleases[key] = releaseData
		}
	}

	result := &DiscoveryResult{
		Matched:   make([]*DiscoveredRelease, 0),
		Unmatched: make([]*DiscoveredRelease, 0),
	}

	for _, rd := range latestReleases {
		release := &DiscoveredRelease{
			Name:              rd.Name,
			Namespace:         rd.Namespace,
			Chart:             rd.Chart.Metadata.Name,
			ChartVersion:      rd.Chart.Metadata.Version,
			AppVersion:        rd.Chart.Metadata.AppVersion,
			Status:            rd.Info.Status,
			Revision:          rd.Version,
			Values:            rd.Config,
			ChartInstallsCRDs: chartInstallsCRDs(&rd.Chart),
		}

		if addonDef, found := matchAddonDefinition(release.Chart, addonLookup); found {
			release.AddonDefinition = addonDef.Name
			release.RepoURL = addonDef.Spec.Chart.Repository
			release.Platform = addonDef.Spec.Platform
			release.Category = addonDef.GetEffectiveTier()
			result.Matched = append(result.Matched, release)
		} else {
			release.Category = "apps"
			release.RepoURL = extractRepoURLFromChartMetadata(rd.Chart.Metadata)
			result.Unmatched = append(result.Unmatched, release)
		}
	}

	result.GitOpsEngine = detectGitOpsEngine(ctx, clientset, dynClient)

	enrichWithHelmReleaseCRs(ctx, dynClient, result)

	return result, nil
}

// enrichWithHelmReleaseCRs walks all Flux HelmRelease custom resources on
// the cluster and back-fills HelmReleaseCRName / HelmReleaseCRNamespace
// on every DiscoveredRelease whose Helm release name matches an HR CR's
// spec.releaseName (or metadata.name when releaseName is unset).
//
// Required because Helm-release-secret-based discovery loses the Flux HR
// CR's identity: a HR CR named X with spec.releaseName=Y produces a Helm
// secret labeled name=Y. Without this enrichment, the export emits a new
// HR CR named Y, colliding with the existing HR CR named X.
//
// Read-only: List only. Failures degrade gracefully — when the CRD is
// not registered (no Flux) or the call fails, releases stay with empty
// HR CR fields and layout v2 falls back to using the Helm release name.
func enrichWithHelmReleaseCRs(ctx context.Context, dynClient dynamic.Interface, result *DiscoveryResult) {
	hrGVR := schema.GroupVersionResource{
		Group:    "helm.toolkit.fluxcd.io",
		Version:  "v2",
		Resource: "helmreleases",
	}
	list, err := dynClient.Resource(hrGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		slog.Debug("HR CR enrichment skipped", "error", err)
		return
	}

	type hrCRRef struct {
		name             string
		namespace        string
		sourceRefName    string
		sourceRefNS      string
	}
	byReleaseName := map[string]hrCRRef{}
	for _, item := range list.Items {
		crName := item.GetName()
		crNS := item.GetNamespace()
		releaseName := crName
		var srcName, srcNS string
		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if rn, ok := spec["releaseName"].(string); ok && rn != "" {
				releaseName = rn
			}
			// spec.chart.spec.sourceRef.{name,namespace} identifies the
			// HelmRepository this release points at. Sourcing the
			// HelmRepository CR name from here (rather than reconstructing
			// from the release name) is required for charts whose publisher
			// name differs from the release name — tenant clusters expose
			// this routinely (kedacore, prometheus-community, emberstack,
			// strimzi, vector-repo all diverge from their HR's name).
			if chart, ok := spec["chart"].(map[string]interface{}); ok {
				if chartSpec, ok := chart["spec"].(map[string]interface{}); ok {
					if srcRef, ok := chartSpec["sourceRef"].(map[string]interface{}); ok {
						if n, ok := srcRef["name"].(string); ok {
							srcName = n
						}
						if ns, ok := srcRef["namespace"].(string); ok {
							srcNS = ns
						}
					}
				}
			}
		}
		byReleaseName[releaseName] = hrCRRef{
			name:          crName,
			namespace:     crNS,
			sourceRefName: srcName,
			sourceRefNS:   srcNS,
		}
	}

	apply := func(rel *DiscoveredRelease) {
		ref, ok := byReleaseName[rel.Name]
		if !ok {
			return
		}
		rel.HelmReleaseCRName = ref.name
		rel.HelmReleaseCRNamespace = ref.namespace
		rel.HelmRepositoryCRName = ref.sourceRefName
		// Flux defaults sourceRef.namespace to the HR CR's namespace when
		// unspecified — match that behavior so the export emits a
		// non-empty namespace consistently.
		if ref.sourceRefNS != "" {
			rel.HelmRepositoryCRNamespace = ref.sourceRefNS
		} else {
			rel.HelmRepositoryCRNamespace = ref.namespace
		}
	}
	for _, rel := range result.Matched {
		apply(rel)
	}
	for _, rel := range result.Unmatched {
		apply(rel)
	}
}

func detectGitOpsEngine(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) *GitOpsEngineStatus {
	if fluxStatus := detectFlux(ctx, clientset, dynClient); fluxStatus != nil {
		return fluxStatus
	}

	if argoStatus := detectArgoCD(ctx, clientset); argoStatus != nil {
		return argoStatus
	}

	return nil
}

func detectFlux(ctx context.Context, clientset kubernetes.Interface, dynClient dynamic.Interface) *GitOpsEngineStatus {
	// Shared detector: Installed = >=1 recognized gotk controller present;
	// Ready = all present controllers ready. Returning nil only when the engine
	// is absent keeps the export/preview gate (GitOpsEngine == nil || !Installed)
	// gating on engine presence, not on readiness -- a partial-but-installed
	// Flux is exportable because the export path reads API data, not controllers.
	engine, err := detectFluxEngine(ctx, clientset)
	if err != nil || !engine.Installed {
		return nil
	}

	status := &GitOpsEngineStatus{
		Provider:   "flux",
		Installed:  true,
		Ready:      engine.Ready,
		Version:    engine.Version,
		Components: engine.readyComponentNames(),
	}

	// Populate Repository/Branch/Path from the Flux bootstrap CRs when
	// readable. Failures here must not regress Flux detection itself:
	// logged at debug level and the engine status still returns with
	// Installed=true so the UI shows GitOps is enabled even if the
	// bootstrap-config lookup partial-fails.
	enrichFluxFromBootstrapCRs(ctx, dynClient, status)

	return status
}

// enrichFluxFromBootstrapCRs reads the Flux-created GitRepository and
// Kustomization in flux-system to populate Repository/Branch/Path on
// status. `flux bootstrap` names both "flux-system" so the lookup is
// deterministic; falls back to the first GitRepository in the namespace
// for out-of-band installs that chose a different name.
func enrichFluxFromBootstrapCRs(ctx context.Context, dynClient dynamic.Interface, status *GitOpsEngineStatus) {
	if dynClient == nil {
		return
	}

	gitRepoGVR := schema.GroupVersionResource{
		Group:    "source.toolkit.fluxcd.io",
		Version:  "v1",
		Resource: "gitrepositories",
	}
	list, err := dynClient.Resource(gitRepoGVR).Namespace("flux-system").List(ctx, metav1.ListOptions{})
	if err != nil {
		slog.Debug("flux: list GitRepositories failed", "namespace", "flux-system", "error", err)
		return
	}
	if len(list.Items) == 0 {
		slog.Debug("flux: no GitRepository in flux-system")
		return
	}

	gitRepo := list.Items[0]
	for i := range list.Items {
		if list.Items[i].GetName() == "flux-system" {
			gitRepo = list.Items[i]
			break
		}
	}

	spec, ok := gitRepo.Object["spec"].(map[string]interface{})
	if !ok {
		slog.Debug("flux: GitRepository spec missing or malformed", "name", gitRepo.GetName())
		return
	}
	if rawURL, ok := spec["url"].(string); ok && rawURL != "" {
		if owner, repo, err := ParseRepoURL(rawURL); err == nil {
			status.Repository = fmt.Sprintf("%s/%s", owner, repo)
		} else {
			status.Repository = rawURL
		}
	}
	// Branch is the primary ref; fall back to tag then commit so the UI
	// surfaces whatever pin is actually driving reconciliation.
	if ref, ok := spec["ref"].(map[string]interface{}); ok {
		if b, ok := ref["branch"].(string); ok && b != "" {
			status.Branch = b
		} else if t, ok := ref["tag"].(string); ok && t != "" {
			status.Branch = t
		} else if c, ok := ref["commit"].(string); ok && c != "" {
			status.Branch = c
		}
	}

	kustomizationGVR := schema.GroupVersionResource{
		Group:    "kustomize.toolkit.fluxcd.io",
		Version:  "v1",
		Resource: "kustomizations",
	}
	ks, err := dynClient.Resource(kustomizationGVR).Namespace("flux-system").Get(ctx, "flux-system", metav1.GetOptions{})
	if err != nil {
		slog.Debug("flux: get Kustomization/flux-system failed", "error", err)
		return
	}
	if ksSpec, ok := ks.Object["spec"].(map[string]interface{}); ok {
		if p, ok := ksSpec["path"].(string); ok {
			status.Path = p
		}
	}
}

func detectArgoCD(ctx context.Context, clientset kubernetes.Interface) *GitOpsEngineStatus {
	argoComponents := []string{
		"argocd-server",
		"argocd-repo-server",
		"argocd-application-controller",
	}

	var readyComponents []string
	var version string

	for _, component := range argoComponents {
		deployment, err := clientset.AppsV1().Deployments("argocd").Get(ctx, component, metav1.GetOptions{})
		if err != nil {
			continue
		}

		if deployment.Status.ReadyReplicas > 0 {
			readyComponents = append(readyComponents, component)

			if version == "" && len(deployment.Spec.Template.Spec.Containers) > 0 {
				image := deployment.Spec.Template.Spec.Containers[0].Image
				if parts := strings.Split(image, ":"); len(parts) > 1 {
					version = parts[len(parts)-1]
				}
			}
		}
	}

	if len(readyComponents) >= 2 {
		return &GitOpsEngineStatus{
			Provider:   "argocd",
			Installed:  true,
			Ready:      len(readyComponents) >= 3,
			Version:    version,
			Components: readyComponents,
		}
	}

	return nil
}

func extractRepoURLFromChartMetadata(metadata helmChartMetadata) string {
	knownRepos := map[string]string{
		"butler-addons":     "oci://ghcr.io/butlerdotdev/charts",
		"butler-console":    "oci://ghcr.io/butlerdotdev/charts",
		"butler-controller": "oci://ghcr.io/butlerdotdev/charts",
		"butler-crds":       "oci://ghcr.io/butlerdotdev/charts",
		"steward":           "oci://ghcr.io/butlerdotdev/charts",
	}

	if url, ok := knownRepos[metadata.Name]; ok {
		return url
	}

	if metadata.Home != "" {
		if strings.Contains(metadata.Home, "charts") ||
			strings.HasPrefix(metadata.Home, "https://") && strings.Contains(metadata.Home, "helm") {
			return metadata.Home
		}
	}

	for _, source := range metadata.Sources {
		if strings.HasPrefix(source, "oci://") {
			return source
		}
		if strings.Contains(source, "charts") || strings.Contains(source, "helm") {
			return source
		}
	}

	if metadata.Home != "" && strings.HasPrefix(metadata.Home, "https://") {
		return metadata.Home
	}

	return ""
}

// Helm release decoding types

type helmReleaseData struct {
	Name      string                 `json:"name"`
	Namespace string                 `json:"namespace"`
	Version   int                    `json:"version"`
	Info      helmReleaseInfo        `json:"info"`
	Chart     helmChartData          `json:"chart"`
	Config    map[string]interface{} `json:"config"`
}

type helmReleaseInfo struct {
	Status        string `json:"status"`
	Description   string `json:"description"`
	FirstDeployed string `json:"first_deployed"`
	LastDeployed  string `json:"last_deployed"`
}

type helmChartData struct {
	Metadata helmChartMetadata `json:"metadata"`
	// Templates contains every file rendered from the chart's templates/
	// directory. Used by chart-CRD detection (ADR-017 D2): if any template
	// has kind: CustomResourceDefinition, the chart installs CRDs and the
	// release tiers as infrastructure.
	Templates []helmChartFile `json:"templates"`
	// CRDs contains files from the chart's crds/ directory. Helm separates
	// these from templates because they install pre-templating. Any entry
	// here is by definition a CRD bundle and means the chart installs CRDs
	// — closes the bundle-vs-reference gap ADR-017 D2 originally deferred.
	CRDs []helmChartFile `json:"crds"`
}

// helmChartFile is one file from a Helm chart's templates/ or crds/
// directory as stored in the release secret. Data is the raw bytes of
// the rendered manifest content (YAML or templated YAML).
type helmChartFile struct {
	Name string `json:"name"`
	Data []byte `json:"data"`
}

type helmChartMetadata struct {
	Name        string   `json:"name"`
	Version     string   `json:"version"`
	AppVersion  string   `json:"appVersion"`
	Home        string   `json:"home"`
	Description string   `json:"description"`
	Sources     []string `json:"sources"`
}

// decodeHelmRelease decodes a Helm release from its stored format.
// Helm stores releases as: base64(gzip(base64(json)))
func decodeHelmRelease(data []byte) (*helmReleaseData, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty release data")
	}

	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		decoded = data
	}

	gzReader, err := gzip.NewReader(bytes.NewReader(decoded))
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer gzReader.Close()

	decompressed, err := io.ReadAll(gzReader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}

	jsonData, err := base64.StdEncoding.DecodeString(string(decompressed))
	if err != nil {
		jsonData = decompressed
	}

	var release helmReleaseData
	if err := json.Unmarshal(jsonData, &release); err != nil {
		return nil, fmt.Errorf("failed to unmarshal release: %w", err)
	}

	return &release, nil
}

// chartInstallsCRDs returns true when the chart bundles CustomResourceDefinitions
// — either via files in the chart's crds/ directory (Helm's pre-template
// CRD bundle path) or via any template containing
// `kind: CustomResourceDefinition`. ADR-017 D2's classifier uses this to
// tier CRD-installing charts as infrastructure regardless of namespace.
//
// The crds/ check is exact: any entry in chart.CRDs is by definition a
// CustomResourceDefinition file. The templates/ check is a substring scan
// for `kind: CustomResourceDefinition` — fast, no YAML parse, accurate
// for the common case where the kind line appears verbatim. Charts that
// use Helm template logic to conditionally emit CRDs (e.g.
// `{{- if .Values.crds.install }}`) are caught when the rendered template
// contains the kind line.
func chartInstallsCRDs(chart *helmChartData) bool {
	if chart == nil {
		return false
	}
	if len(chart.CRDs) > 0 {
		return true
	}
	for _, t := range chart.Templates {
		if bytes.Contains(t.Data, []byte("kind: CustomResourceDefinition")) {
			return true
		}
	}
	return false
}

// AddonDefinition matching

func buildAddonLookup(addonDefs []butlerv1alpha1.AddonDefinition) map[string]*butlerv1alpha1.AddonDefinition {
	lookup := make(map[string]*butlerv1alpha1.AddonDefinition)
	for i := range addonDefs {
		ad := &addonDefs[i]
		chartName := strings.ToLower(ad.Spec.Chart.Name)
		lookup[chartName] = ad

		addonName := strings.ToLower(ad.Name)
		if _, exists := lookup[addonName]; !exists {
			lookup[addonName] = ad
		}
	}
	return lookup
}

func matchAddonDefinition(chartName string, lookup map[string]*butlerv1alpha1.AddonDefinition) (*butlerv1alpha1.AddonDefinition, bool) {
	chartLower := strings.ToLower(chartName)

	if ad, found := lookup[chartLower]; found {
		return ad, true
	}

	variants := []string{
		strings.TrimSuffix(chartLower, "-operator"),
		strings.TrimSuffix(chartLower, "-controller"),
		strings.TrimSuffix(chartLower, "-helm"),
		strings.TrimPrefix(chartLower, "helm-"),
	}

	for _, variant := range variants {
		if variant != chartLower {
			if ad, found := lookup[variant]; found {
				return ad, true
			}
		}
	}

	return nil, false
}

// Migration types

// MigrationRequest defines a request to migrate releases to GitOps.
type MigrationRequest struct {
	Releases   []MigrationRelease `json:"releases"`
	CreatePR   bool               `json:"createPR,omitempty"`
	Repository string             `json:"repository,omitempty"`
	Branch     string             `json:"branch,omitempty"`
	BasePath   string             `json:"basePath,omitempty"`
	PRTitle    string             `json:"prTitle,omitempty"`
}

// MigrationRelease defines a release to migrate.
type MigrationRelease struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Category  string `json:"category,omitempty"`
	RepoURL   string `json:"repoUrl,omitempty"`
}

// MigrationResult contains the results of a migration operation.
type MigrationResult struct {
	Success       bool     `json:"success"`
	Message       string   `json:"message"`
	MigratedCount int      `json:"migratedCount"`
	Files         []string `json:"files"`
	CommitSHA     string   `json:"commitSha,omitempty"`
	PRURL         string   `json:"prUrl,omitempty"`
}
