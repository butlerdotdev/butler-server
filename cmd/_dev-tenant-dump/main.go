package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"sigs.k8s.io/yaml"

	"github.com/butlerdotdev/butler-server/internal/gitops"
	"github.com/butlerdotdev/butler-server/internal/k8s"
)

func main() {
	// DEV_DUMP_KUBECONFIG / DEV_DUMP_CLUSTER / DEV_DUMP_ENV / DEV_DUMP_OUT
	// override defaults so this tool can target any tenant without recompiling.
	kcPath := os.Getenv("DEV_DUMP_KUBECONFIG")
	if kcPath == "" {
		kcPath = os.Getenv("HOME") + "/.butler/observability-pipeline-prd-kubeconfig"
	}
	clusterName := os.Getenv("DEV_DUMP_CLUSTER")
	if clusterName == "" {
		clusterName = "observability-pipeline-prd"
	}
	env := os.Getenv("DEV_DUMP_ENV")
	if env == "" {
		env = "prd"
	}
	outDir := os.Getenv("DEV_DUMP_OUT")
	if outDir == "" {
		outDir = "/tmp/tenant-export-tree"
	}

	kc, err := os.ReadFile(kcPath)
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	client, _ := k8s.NewClientFromKubeconfig(string(kc))
	adList, _ := client.ListAddonDefinitionsTyped(ctx)
	var addonItems = []interface{}{}
	_ = addonItems

	var hr *gitops.DiscoveryResult
	if adList != nil {
		hr, err = gitops.DiscoverHelmReleases(ctx, kc, adList.Items)
	} else {
		hr, err = gitops.DiscoverHelmReleases(ctx, kc, nil)
	}
	if err != nil {
		log.Fatal(err)
	}
	nat, err := gitops.DiscoverNativeResources(ctx, kc)
	if err != nil {
		log.Fatal(err)
	}

	nsNames := map[string]bool{}
	for _, r := range hr.Matched {
		if r.Namespace != "" {
			nsNames[r.Namespace] = true
		}
	}
	for _, r := range hr.Unmatched {
		if r.Namespace != "" {
			nsNames[r.Namespace] = true
		}
	}
	nsMeta, err := gitops.DiscoverNamespaceMetadata(ctx, kc, nsNames)
	if err != nil {
		log.Printf("namespace metadata discovery failed: %v", err)
	}

	tree, err := gitops.GenerateLayoutV2(gitops.ExportInput{
		ClusterName:   clusterName,
		Env:           env,
		Helm:          hr,
		Native:        nat,
		NamespaceMeta: nsMeta,
	})
	if err != nil {
		log.Fatal(err)
	}

	// Synthesize coverage.yaml (ADR-017 D5) the same way RunExportV2 does,
	// so the dumped tree includes the visibility surface — operator can
	// inspect inlinePatches / inScopeUncaptured / kustomizationObservations /
	// discoveryFailures from the live tenant without going through a git push.
	report := gitops.BuildCoverage(gitops.CoverageInput{
		ClusterName:   clusterName,
		Env:           env,
		EmittedFiles:  tree,
		Helm:          hr,
		Inventory:     nat.InventoryWalk,
		NativeResults: nat.Items,
		NamespaceMeta: nsMeta,
	})
	covYAML, err := gitops.MarshalCoverage(report)
	if err != nil {
		log.Fatal(err)
	}
	tree["coverage.yaml"] = covYAML

	for path, content := range tree {
		full := filepath.Join(outDir, path)
		_ = os.MkdirAll(filepath.Dir(full), 0755)
		os.WriteFile(full, content, 0644)
	}
	fmt.Printf("wrote %d files to %s (including coverage.yaml)\n", len(tree), outDir)

	// Optional: record fixture pair (input + expected) from THIS single
	// invocation when DEV_DUMP_FIXTURE_OUT is set. Both halves come from
	// the same discovery+layout pass so the input fixtures can't carry a
	// state different from what produced the expected tree.
	fixtureOut := os.Getenv("DEV_DUMP_FIXTURE_OUT")
	if fixtureOut == "" {
		return
	}
	inputDir := filepath.Join(fixtureOut, "input")
	expectedDir := filepath.Join(fixtureOut, "expected")
	if err := os.MkdirAll(inputDir, 0755); err != nil {
		log.Fatal(err)
	}
	writeYAML := func(name string, v interface{}) {
		b, err := yaml.Marshal(v)
		if err != nil {
			log.Fatalf("marshal %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(inputDir, name), b, 0644); err != nil {
			log.Fatalf("write %s: %v", name, err)
		}
	}
	writeYAML("helm-discovery.yaml", hr)
	writeYAML("native-discovery.yaml", nat)
	writeYAML("namespace-metadata.yaml", nsMeta)
	// expected: the produced tree from THIS invocation (same in-memory
	// tree we just wrote to outDir, written again under expected/ so the
	// fixture is self-contained and pinned to the same run).
	for path, content := range tree {
		full := filepath.Join(expectedDir, path)
		_ = os.MkdirAll(filepath.Dir(full), 0755)
		os.WriteFile(full, content, 0644)
	}
	fmt.Printf("recorded fixture (input + expected) to %s\n", fixtureOut)
}
