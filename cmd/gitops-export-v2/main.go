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

// Command gitops-export-v2 is a development tool that drives the v2 GitOps
// export pipeline against a live cluster. It is the CLI used in the
// local-against-live testing loop from ADR-016's PR 2 plan.
//
// Safety properties this binary enforces:
//
//   - Cluster operations are READ-ONLY. Discovery only calls List/Get; this
//     binary never invokes any Create/Update/Patch/Delete on the cluster.
//
//   - Direct push is DISABLED. The export always uses the feature-branch+MR
//     flow regardless of existing-tree shape, by setting ForceMRPath=true.
//     This is structural — the flag cannot be disabled without recompiling
//     a non-default codepath.
//
//   - The target repo URL is required as an explicit argument. There is no
//     fallback to "the cluster's configured gitops repo" — the user must
//     supply the scratch repo URL by name.
//
// Usage:
//
//	gitops-export-v2 \
//	  -kubeconfig ~/.butler/usini2kpbtlrkn-kubeconfig \
//	  -cluster usini2kpbtlrkn \
//	  -env prd \
//	  -git-type gitlab \
//	  -git-url https://gitlab.research.corteva.com \
//	  -git-owner <scratch-namespace> \
//	  -git-repo <scratch-project> \
//	  -git-branch main \
//	  -git-token-env BUTLER_EXPORT_TEST_TOKEN
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	butlerv1alpha1 "github.com/butlerdotdev/butler-api/api/v1alpha1"
	"github.com/butlerdotdev/butler-server/internal/gitops"
	"github.com/butlerdotdev/butler-server/internal/k8s"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		kubeconfigPath = flag.String("kubeconfig", "", "path to kubeconfig for the source cluster (read-only)")
		clusterName    = flag.String("cluster", "", "cluster name used in clusters/<name>/ tree")
		env            = flag.String("env", "prd", "apps overlay env name")
		gitType        = flag.String("git-type", "", "git provider type: gitlab or github")
		gitURL         = flag.String("git-url", "", "git provider base URL (e.g. https://gitlab.research.corteva.com)")
		gitOwner       = flag.String("git-owner", "", "git owner / group / namespace")
		gitRepo        = flag.String("git-repo", "", "git repo name (NEVER butler-crop-live-infra)")
		gitBranch      = flag.String("git-branch", "main", "git default branch")
		gitTokenEnv    = flag.String("git-token-env", "", "env var holding the git provider token")
		summaryOnly    = flag.Bool("summary-only", false, "print the layout file list and exit, do not push to git")
	)
	flag.Parse()

	if *kubeconfigPath == "" || *clusterName == "" {
		return fmt.Errorf("required flags: -kubeconfig, -cluster")
	}
	if !*summaryOnly {
		if *gitType == "" || *gitOwner == "" || *gitRepo == "" || *gitTokenEnv == "" {
			return fmt.Errorf("required flags: -git-type, -git-owner, -git-repo, -git-token-env (unless -summary-only)")
		}
	}

	// Safety stop: refuse to push to any repo whose name resembles the
	// production live-infra repos.
	if strings.Contains(*gitRepo, "live-infra") || strings.Contains(*gitOwner, "live-infra") {
		return fmt.Errorf("target repo %s/%s looks like a live-infra repo — refusing. Use a scratch repo.", *gitOwner, *gitRepo)
	}

	ctx := context.Background()
	kubeconfig, err := os.ReadFile(*kubeconfigPath)
	if err != nil {
		return fmt.Errorf("read kubeconfig: %w", err)
	}

	slog.Info("discovering Helm releases (read-only on cluster)")
	addonDefs, err := loadAddonDefinitions(ctx, kubeconfig)
	if err != nil {
		slog.Warn("failed to load AddonDefinitions; matched bucket will be empty", "error", err)
	}
	hr, err := gitops.DiscoverHelmReleases(ctx, kubeconfig, addonDefs)
	if err != nil {
		return fmt.Errorf("DiscoverHelmReleases: %w", err)
	}
	slog.Info("Helm discovery complete",
		"matched", len(hr.Matched),
		"unmatched", len(hr.Unmatched))

	slog.Info("discovering native resources (read-only on cluster)")
	nat, err := gitops.DiscoverNativeResources(ctx, kubeconfig)
	if err != nil {
		return fmt.Errorf("DiscoverNativeResources: %w", err)
	}
	slog.Info("native discovery complete",
		"identityProviders", len(nat.IdentityProviders),
		"networkPools", len(nat.NetworkPools),
		"providerConfigs", len(nat.ProviderConfigs),
		"teams", len(nat.Teams),
		"clusterCreationPolicies", len(nat.ClusterCreationPolicies),
		"sealedSecrets", len(nat.SealedSecrets),
		"metallbIPPools", len(nat.MetalLBIPAddressPools),
		"metallbL2", len(nat.MetalLBL2Advertisements),
		"stewardCP", len(nat.StewardControlPlanes),
		"stewardCPT", len(nat.StewardControlPlaneTemplates),
		"butlerGitopsConfig", nat.ButlerGitOpsConfig != nil)

	tree, err := gitops.GenerateLayoutV2(gitops.ExportInput{
		ClusterName: *clusterName,
		Env:         *env,
		Helm:        hr,
		Native:      nat,
	})
	if err != nil {
		return fmt.Errorf("GenerateLayoutV2: %w", err)
	}

	fmt.Printf("layout tree: %d files\n", len(tree))
	for _, path := range sortedKeys(tree) {
		fmt.Printf("  %s\n", path)
	}

	if *summaryOnly {
		return nil
	}

	token := os.Getenv(*gitTokenEnv)
	if token == "" {
		return fmt.Errorf("git token env %s is empty", *gitTokenEnv)
	}

	gp, err := gitops.NewGitProvider(gitops.GitProviderConfig{
		Type:         *gitType,
		Token:        token,
		URL:          *gitURL,
		Organization: *gitOwner,
	})
	if err != nil {
		return fmt.Errorf("create git provider: %w", err)
	}

	slog.Info("running export — direct push DISABLED (ForceMRPath=true)")
	res, err := gitops.RunExportV2(ctx, gp, gitops.ExportV2Request{
		ClusterName:   *clusterName,
		Env:           *env,
		Helm:          hr,
		Native:        nat,
		Owner:         *gitOwner,
		Repo:          *gitRepo,
		Branch:        *gitBranch,
		CommitMessage: fmt.Sprintf("export cluster %s (dev v2 pipeline)", *clusterName),
		PRTitle:       fmt.Sprintf("Export cluster %s — v2 dev run", *clusterName),
		ForceMRPath:   true, // dev-loop hardcoded; ADR-016 subsection 6.3
	})
	if err != nil {
		return fmt.Errorf("RunExportV2: %w", err)
	}

	fmt.Printf("\n=== export result ===\n")
	fmt.Printf("mode: %s\n", res.Mode)
	fmt.Printf("branch: %s\n", res.Branch)
	fmt.Printf("commit: %s\n", res.CommitSHA)
	if res.PRURL != "" {
		fmt.Printf("PR: %s\n", res.PRURL)
	}
	fmt.Printf("files: %d\n", res.FilesCount)
	return nil
}

func loadAddonDefinitions(ctx context.Context, kubeconfig []byte) ([]butlerv1alpha1.AddonDefinition, error) {
	client, err := k8s.NewClientFromKubeconfig(string(kubeconfig))
	if err != nil {
		return nil, err
	}
	list, err := client.ListAddonDefinitionsTyped(ctx)
	if err != nil {
		return nil, err
	}
	return list.Items, nil
}

func sortedKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sortStrings(keys)
	return keys
}

func sortStrings(s []string) {
	// Local helper instead of importing sort for a one-line use.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}
