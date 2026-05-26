// Command gitops-fixture-dump runs a golden-fixture input through
// GenerateLayoutV2 + BuildCoverage and writes the produced tree to a
// target directory for inspection or fixture refresh. Dev-only.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/butlerdotdev/butler-server/internal/gitops"
	"sigs.k8s.io/yaml"
)

func main() {
	var (
		fixtureRoot = flag.String("fixture", "", "Path to fixture root (must contain input/)")
		cluster     = flag.String("cluster", "", "Cluster name to pass to GenerateLayoutV2")
		env         = flag.String("env", "prd", "Env name to pass to GenerateLayoutV2")
		out         = flag.String("out", "/tmp/fixture-dump", "Output directory to write the produced tree")
	)
	flag.Parse()
	if *fixtureRoot == "" || *cluster == "" {
		fmt.Fprintln(os.Stderr, "--fixture and --cluster required")
		os.Exit(2)
	}

	helm := &gitops.DiscoveryResult{}
	if err := readYAML(filepath.Join(*fixtureRoot, "input", "helm-discovery.yaml"), helm); err != nil {
		fmt.Fprintf(os.Stderr, "load helm: %v\n", err)
		os.Exit(1)
	}
	native := &gitops.NativeDiscoveryResult{}
	if err := readYAML(filepath.Join(*fixtureRoot, "input", "native-discovery.yaml"), native); err != nil {
		fmt.Fprintf(os.Stderr, "load native: %v\n", err)
		os.Exit(1)
	}
	nsMeta := gitops.NamespaceMetadataMap{}
	_ = readYAML(filepath.Join(*fixtureRoot, "input", "namespace-metadata.yaml"), &nsMeta)

	tree, err := gitops.GenerateLayoutV2(gitops.ExportInput{
		ClusterName:   *cluster,
		Env:           *env,
		Helm:          helm,
		Native:        native,
		NamespaceMeta: nsMeta,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "GenerateLayoutV2: %v\n", err)
		os.Exit(1)
	}
	report := gitops.BuildCoverage(gitops.CoverageInput{
		ClusterName:   *cluster,
		Env:           *env,
		EmittedFiles:  tree,
		Helm:          helm,
		Inventory:     native.InventoryWalk,
		NativeResults: native.Items,
		NamespaceMeta: nsMeta,
	})
	cov, err := gitops.MarshalCoverage(report)
	if err != nil {
		fmt.Fprintf(os.Stderr, "MarshalCoverage: %v\n", err)
		os.Exit(1)
	}
	tree["coverage.yaml"] = cov

	_ = os.RemoveAll(*out)
	for path, content := range tree {
		full := filepath.Join(*out, path)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
			os.Exit(1)
		}
		if err := os.WriteFile(full, content, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			os.Exit(1)
		}
	}
	paths := make([]string, 0, len(tree))
	for p := range tree {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	fmt.Printf("wrote %d files to %s\n", len(tree), *out)
	for _, p := range paths {
		fmt.Printf("  %s\n", p)
	}
}

func readYAML(path string, into interface{}) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(data, into)
}
