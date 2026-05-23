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
	"context"
	"fmt"
	"sort"
	"time"
)

// ExportV2Request is the top-level configuration for a v2 GitOps export.
type ExportV2Request struct {
	ClusterName string
	Env         string

	Helm   *DiscoveryResult
	Native *NativeDiscoveryResult

	// Repository targets.
	Owner  string
	Repo   string
	Branch string // default branch of the target repo

	// CommitMessage is used when direct-pushing. PRTitle is used when
	// opening a PR/MR on the feature branch.
	CommitMessage string
	PRTitle       string
	PRBody        string

	// ForceMRPath disables direct-push and always uses the feature-branch+MR
	// flow regardless of the existing-tree shape. The dev loop sets this
	// true so the local-against-live runs never direct-push (ADR-016
	// subsection 6.3 — the gate that holds direct-push to scratch repos
	// only during development).
	ForceMRPath bool
}

// ExportV2Result reports the outcome of the export.
type ExportV2Result struct {
	Mode       string // "direct-push" or "feature-branch-mr"
	Branch     string // branch the export wrote to
	CommitSHA  string
	PRURL      string // empty for direct-push
	PRNumber   int
	FilesCount int
	Files      []string // sorted list of file paths written (for surface/log)
}

// RunExportV2 is the top-level orchestrator for the v2 export. Flow:
//   1. Generate the layout tree from discovered state (LayoutV2).
//   2. Detect the target repo's existing shape at clusters/<cluster>/.
//   3. If shape matches v2 target AND ForceMRPath is false → direct push
//      to the configured branch.
//   4. Otherwise → create feature branch butler-export/<cluster>-<unix-ts>,
//      commit the tree, open PR/MR.
//
// The function does not write to the source cluster (discovery is the only
// cluster interaction and already happened before this call). The only
// writes are to the configured target Git repo.
func RunExportV2(ctx context.Context, gp GitProvider, req ExportV2Request) (*ExportV2Result, error) {
	if gp == nil {
		return nil, fmt.Errorf("export v2: GitProvider required")
	}
	if req.Owner == "" || req.Repo == "" {
		return nil, fmt.Errorf("export v2: Owner and Repo required")
	}
	if req.Branch == "" {
		return nil, fmt.Errorf("export v2: Branch required")
	}

	tree, err := GenerateLayoutV2(ExportInput{
		ClusterName: req.ClusterName,
		Env:         req.Env,
		Helm:        req.Helm,
		Native:      req.Native,
	})
	if err != nil {
		return nil, fmt.Errorf("generate layout: %w", err)
	}

	matches := req.ForceMRPath == false && existingTreeMatchesV2(ctx, gp, req.Owner, req.Repo, req.Branch, req.ClusterName, req.Env)

	mode := "feature-branch-mr"
	if matches {
		mode = "direct-push"
	}

	files := flattenTree(tree)
	commitMessage := req.CommitMessage
	if commitMessage == "" {
		commitMessage = fmt.Sprintf("export cluster %s", req.ClusterName)
	}

	if mode == "direct-push" {
		commit, err := gp.CommitFiles(ctx, req.Owner, req.Repo, req.Branch, commitMessage, files)
		if err != nil {
			return nil, fmt.Errorf("direct push: %w", err)
		}
		return &ExportV2Result{
			Mode:       "direct-push",
			Branch:     req.Branch,
			CommitSHA:  commit.SHA,
			FilesCount: len(files),
			Files:      sortedFileNames(files),
		}, nil
	}

	branchName := fmt.Sprintf("butler-export/%s-%d", req.ClusterName, time.Now().Unix())
	baseSHA, err := gp.GetBranchSHA(ctx, req.Owner, req.Repo, req.Branch)
	if err != nil {
		return nil, fmt.Errorf("get base branch sha: %w", err)
	}
	if err := gp.CreateBranch(ctx, req.Owner, req.Repo, branchName, baseSHA); err != nil {
		return nil, fmt.Errorf("create feature branch: %w", err)
	}

	commit, err := gp.CommitFiles(ctx, req.Owner, req.Repo, branchName, commitMessage, files)
	if err != nil {
		return nil, fmt.Errorf("commit to feature branch: %w", err)
	}

	prTitle := req.PRTitle
	if prTitle == "" {
		prTitle = fmt.Sprintf("Export from cluster %s", req.ClusterName)
	}
	pr, err := gp.CreatePullRequest(ctx, req.Owner, req.Repo, prTitle, req.PRBody, branchName, req.Branch)
	if err != nil {
		return nil, fmt.Errorf("create PR: %w", err)
	}

	return &ExportV2Result{
		Mode:       "feature-branch-mr",
		Branch:     branchName,
		CommitSHA:  commit.SHA,
		PRURL:      pr.URL,
		PRNumber:   pr.Number,
		FilesCount: len(files),
		Files:      sortedFileNames(files),
	}, nil
}

// existingTreeMatchesV2 returns true if the target repo already has the v2
// layout shape — concretely, clusters/<cluster>/apps.yaml and
// apps/<env>/kustomization.yaml both exist. The check is the trigger for
// direct-push vs feature-branch+MR (ADR-016 subsection 6.3): a mismatch
// means the operator should review before reconciling, so we route through
// an MR.
//
// On any read error (file not found, RBAC, network) the function returns
// false — the safer default is "shape differs" which routes to MR.
func existingTreeMatchesV2(ctx context.Context, gp GitProvider, owner, repo, branch, cluster, env string) bool {
	clusterFile := fmt.Sprintf("clusters/%s/apps.yaml", cluster)
	envFile := fmt.Sprintf("apps/%s/kustomization.yaml", env)

	if _, err := gp.GetFileContent(ctx, owner, repo, clusterFile, branch); err != nil {
		return false
	}
	if _, err := gp.GetFileContent(ctx, owner, repo, envFile, branch); err != nil {
		return false
	}
	return true
}

func flattenTree(tree map[string][]byte) []FileCommit {
	paths := make([]string, 0, len(tree))
	for p := range tree {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	files := make([]FileCommit, 0, len(paths))
	for _, p := range paths {
		files = append(files, FileCommit{Path: p, Content: tree[p]})
	}
	return files
}

func sortedFileNames(files []FileCommit) []string {
	out := make([]string, 0, len(files))
	for _, f := range files {
		out = append(out, f.Path)
	}
	sort.Strings(out)
	return out
}
