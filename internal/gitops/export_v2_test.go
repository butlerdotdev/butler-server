/*
Copyright 2026 The Butler Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
*/

package gitops

import (
	"context"
	"fmt"
	"testing"
)

func TestExportV2DirectPushWhenShapeMatches(t *testing.T) {
	gp := &fakeGitProvider{
		existing: map[string][]byte{
			"clusters/test-cluster/apps.yaml":   []byte("placeholder"),
			"apps/prd/kustomization.yaml":       []byte("placeholder"),
		},
	}

	res, err := RunExportV2(context.Background(), gp, ExportV2Request{
		ClusterName: "test-cluster",
		Env:         "prd",
		Helm:        &DiscoveryResult{},
		Native:      &NativeDiscoveryResult{},
		Owner:       "ns",
		Repo:        "scratch",
		Branch:      "main",
	})
	if err != nil {
		t.Fatalf("RunExportV2: %v", err)
	}
	if res.Mode != "direct-push" {
		t.Errorf("expected direct-push when shape matches, got %s", res.Mode)
	}
	if res.Branch != "main" {
		t.Errorf("direct-push branch should be main, got %s", res.Branch)
	}
	if gp.commits == 0 {
		t.Errorf("CommitFiles should have been called")
	}
	if gp.prs != 0 {
		t.Errorf("CreatePullRequest should not be called on direct-push, was called %d times", gp.prs)
	}
}

func TestExportV2FeatureBranchWhenShapeMismatch(t *testing.T) {
	gp := &fakeGitProvider{
		existing: map[string][]byte{}, // empty repo — no existing shape
	}

	res, err := RunExportV2(context.Background(), gp, ExportV2Request{
		ClusterName: "test-cluster",
		Env:         "prd",
		Helm:        &DiscoveryResult{},
		Native:      &NativeDiscoveryResult{},
		Owner:       "ns",
		Repo:        "scratch",
		Branch:      "main",
	})
	if err != nil {
		t.Fatalf("RunExportV2: %v", err)
	}
	if res.Mode != "feature-branch-mr" {
		t.Errorf("expected feature-branch-mr on empty repo, got %s", res.Mode)
	}
	if res.Branch == "main" {
		t.Errorf("feature branch must not equal default branch")
	}
	if gp.prs != 1 {
		t.Errorf("CreatePullRequest should have been called once, was %d", gp.prs)
	}
}

func TestExportV2ForceMRPathAlwaysOpensPR(t *testing.T) {
	gp := &fakeGitProvider{
		existing: map[string][]byte{
			"clusters/test-cluster/apps.yaml": []byte("p"),
			"apps/prd/kustomization.yaml":     []byte("p"),
		},
	}

	res, err := RunExportV2(context.Background(), gp, ExportV2Request{
		ClusterName: "test-cluster",
		Env:         "prd",
		Helm:        &DiscoveryResult{},
		Native:      &NativeDiscoveryResult{},
		Owner:       "ns",
		Repo:        "scratch",
		Branch:      "main",
		ForceMRPath: true,
	})
	if err != nil {
		t.Fatalf("RunExportV2: %v", err)
	}
	if res.Mode != "feature-branch-mr" {
		t.Errorf("ForceMRPath should force feature-branch-mr, got %s", res.Mode)
	}
	if gp.prs != 1 {
		t.Errorf("PR should have been opened, was %d", gp.prs)
	}
}

// fakeGitProvider implements just enough of the GitProvider interface for
// export_v2 orchestration tests. No network, no live calls.
type fakeGitProvider struct {
	existing map[string][]byte
	commits  int
	prs      int
	branches int
}

func (f *fakeGitProvider) Name() string { return "fake" }
func (f *fakeGitProvider) ValidateToken(ctx context.Context) (*TokenValidation, error) {
	return &TokenValidation{Valid: true}, nil
}
func (f *fakeGitProvider) ListRepositories(ctx context.Context) ([]*Repository, error) {
	return nil, nil
}
func (f *fakeGitProvider) GetRepository(ctx context.Context, owner, repo string) (*Repository, error) {
	return &Repository{Name: repo, DefaultBranch: "main"}, nil
}
func (f *fakeGitProvider) ListBranches(ctx context.Context, owner, repo string) ([]*Branch, error) {
	return nil, nil
}
func (f *fakeGitProvider) GetBranchSHA(ctx context.Context, owner, repo, branch string) (string, error) {
	return "deadbeef", nil
}
func (f *fakeGitProvider) GetFileContent(ctx context.Context, owner, repo, path, branch string) ([]byte, error) {
	if content, ok := f.existing[path]; ok {
		return content, nil
	}
	return nil, fmt.Errorf("not found: %s", path)
}
func (f *fakeGitProvider) CreateOrUpdateFile(ctx context.Context, owner, repo, path, branch, message string, content []byte) (*CommitResult, error) {
	return &CommitResult{SHA: "sha"}, nil
}
func (f *fakeGitProvider) CreateOrUpdateFiles(ctx context.Context, owner, repo, branch, message string, files []FileCommit) (*CommitResult, error) {
	return f.CommitFiles(ctx, owner, repo, branch, message, files)
}
func (f *fakeGitProvider) CommitFiles(ctx context.Context, owner, repo, branch, message string, files []FileCommit) (*CommitResult, error) {
	f.commits++
	return &CommitResult{SHA: fmt.Sprintf("sha-%d", f.commits)}, nil
}
func (f *fakeGitProvider) CreateBranch(ctx context.Context, owner, repo, branch, baseSHA string) error {
	f.branches++
	return nil
}
func (f *fakeGitProvider) CreatePullRequest(ctx context.Context, owner, repo, title, body, head, base string) (*PullRequestResult, error) {
	f.prs++
	return &PullRequestResult{Number: f.prs, URL: fmt.Sprintf("https://example/pr/%d", f.prs)}, nil
}
