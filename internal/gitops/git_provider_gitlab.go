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
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	gitlab "gitlab.com/gitlab-org/api/client-go"
)

func init() {
	RegisterGitProvider("gitlab", NewGitLabProvider)
}

// GitLabProvider implements GitProvider for GitLab, including self-hosted instances.
type GitLabProvider struct {
	client       *gitlab.Client
	organization string
}

var _ GitProvider = (*GitLabProvider)(nil)

func NewGitLabProvider(cfg GitProviderConfig) (GitProvider, error) {
	if cfg.Token == "" {
		return nil, &AuthenticationError{Message: "token is required"}
	}

	baseURL := normalizeGitLabURL(cfg.URL)

	client, err := gitlab.NewClient(cfg.Token, gitlab.WithBaseURL(baseURL))
	if err != nil {
		return nil, fmt.Errorf("failed to create GitLab client: %w", err)
	}

	return &GitLabProvider{
		client:       client,
		organization: cfg.Organization,
	}, nil
}

func (p *GitLabProvider) Name() string {
	return "gitlab"
}

func (p *GitLabProvider) ValidateToken(ctx context.Context) (*TokenValidation, error) {
	user, resp, err := p.client.Users.CurrentUser(gitlab.WithContext(ctx))
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return &TokenValidation{Valid: false}, nil
		}
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	validation := &TokenValidation{
		Valid:    true,
		Name:     user.Name,
		Username: user.Username,
		Email:    user.Email,
	}

	// Retrieve PAT scopes via self-introspection endpoint.
	pat, _, patErr := p.client.PersonalAccessTokens.GetSinglePersonalAccessToken(gitlab.WithContext(ctx))
	if patErr == nil && pat != nil {
		validation.Scopes = pat.Scopes
	}

	return validation, nil
}

func (p *GitLabProvider) ListRepositories(ctx context.Context) ([]*Repository, error) {
	const maxRepos = 200

	if p.organization != "" {
		return p.listGroupProjects(ctx, maxRepos)
	}
	return p.listAllProjects(ctx, maxRepos)
}

// listGroupProjects uses the Groups API to list projects scoped to a group.
func (p *GitLabProvider) listGroupProjects(ctx context.Context, maxRepos int) ([]*Repository, error) {
	var allRepos []*Repository
	opts := &gitlab.ListGroupProjectsOptions{
		IncludeSubGroups: gitlab.Ptr(true),
		OrderBy:          gitlab.Ptr("updated_at"),
		Sort:             gitlab.Ptr("desc"),
		ListOptions:      gitlab.ListOptions{PerPage: 100},
	}

	for {
		projects, resp, err := p.client.Groups.ListGroupProjects(p.organization, opts, gitlab.WithContext(ctx))
		if err != nil {
			return nil, p.wrapError(err, resp)
		}

		for _, proj := range projects {
			allRepos = append(allRepos, projectToRepository(proj))
			if len(allRepos) >= maxRepos {
				return allRepos, nil
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

// listAllProjects lists all projects the token has access to.
func (p *GitLabProvider) listAllProjects(ctx context.Context, maxRepos int) ([]*Repository, error) {
	var allRepos []*Repository
	opts := &gitlab.ListProjectsOptions{
		Membership: gitlab.Ptr(true),
		OrderBy:    gitlab.Ptr("updated_at"),
		Sort:       gitlab.Ptr("desc"),
		ListOptions: gitlab.ListOptions{
			PerPage: 100,
		},
	}

	for {
		projects, resp, err := p.client.Projects.ListProjects(opts, gitlab.WithContext(ctx))
		if err != nil {
			return nil, p.wrapError(err, resp)
		}

		for _, proj := range projects {
			allRepos = append(allRepos, projectToRepository(proj))
			if len(allRepos) >= maxRepos {
				return allRepos, nil
			}
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

func (p *GitLabProvider) GetRepository(ctx context.Context, owner, repo string) (*Repository, error) {
	pid := owner + "/" + repo
	proj, resp, err := p.client.Projects.GetProject(pid, nil, gitlab.WithContext(ctx))
	if err != nil {
		return nil, p.wrapError(err, resp)
	}

	return projectToRepository(proj), nil
}

func (p *GitLabProvider) ListBranches(ctx context.Context, owner, repo string) ([]*Branch, error) {
	pid := owner + "/" + repo

	proj, resp, err := p.client.Projects.GetProject(pid, nil, gitlab.WithContext(ctx))
	if err != nil {
		return nil, p.wrapError(err, resp)
	}
	defaultBranch := proj.DefaultBranch

	var allBranches []*Branch
	opts := &gitlab.ListBranchesOptions{
		ListOptions: gitlab.ListOptions{PerPage: 100},
	}

	for {
		branches, resp, err := p.client.Branches.ListBranches(pid, opts, gitlab.WithContext(ctx))
		if err != nil {
			return nil, p.wrapError(err, resp)
		}

		for _, b := range branches {
			allBranches = append(allBranches, &Branch{
				Name:      b.Name,
				Protected: b.Protected,
				Default:   b.Name == defaultBranch,
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allBranches, nil
}

func (p *GitLabProvider) GetBranchSHA(ctx context.Context, owner, repo, branch string) (string, error) {
	pid := owner + "/" + repo

	// Use the Commits API with ref_name as a query parameter instead of
	// Branches.GetBranch which embeds the branch in the URL path. Self-hosted
	// GitLab instances behind reverse proxies (nginx) often decode %2F in
	// path segments, breaking branch names that contain slashes.
	commits, resp, err := p.client.Commits.ListCommits(pid, &gitlab.ListCommitsOptions{
		RefName:     gitlab.Ptr(branch),
		ListOptions: gitlab.ListOptions{PerPage: 1},
	}, gitlab.WithContext(ctx))
	if err != nil {
		return "", fmt.Errorf("GetBranchSHA(project=%q, branch=%q): %w", pid, branch, p.wrapError(err, resp))
	}
	if len(commits) == 0 {
		return "", fmt.Errorf("branch %q has no commits", branch)
	}
	return commits[0].ID, nil
}

func (p *GitLabProvider) GetFileContent(ctx context.Context, owner, repo, path, branch string) ([]byte, error) {
	pid := owner + "/" + repo
	opts := &gitlab.GetFileOptions{Ref: gitlab.Ptr(branch)}
	f, resp, err := p.client.RepositoryFiles.GetFile(pid, path, opts, gitlab.WithContext(ctx))
	if err != nil {
		return nil, p.wrapError(err, resp)
	}

	decoded, err := base64.StdEncoding.DecodeString(f.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to decode file content: %w", err)
	}

	return decoded, nil
}

func (p *GitLabProvider) CreateOrUpdateFile(ctx context.Context, owner, repo, path, branch, message string, content []byte) (*CommitResult, error) {
	return p.commitActions(ctx, owner, repo, branch, message, []FileCommit{
		{Path: path, Content: content},
	})
}

func (p *GitLabProvider) CreateOrUpdateFiles(ctx context.Context, owner, repo, branch, message string, files []FileCommit) (*CommitResult, error) {
	return p.commitActions(ctx, owner, repo, branch, message, files)
}

func (p *GitLabProvider) CommitFiles(ctx context.Context, owner, repo, branch, message string, files []FileCommit) (*CommitResult, error) {
	return p.commitActions(ctx, owner, repo, branch, message, files)
}

// commitActions uses GitLab's native multi-file commit endpoint. A single tree
// listing determines which files exist so we can choose create vs update.
func (p *GitLabProvider) commitActions(ctx context.Context, owner, repo, branch, message string, files []FileCommit) (*CommitResult, error) {
	pid := owner + "/" + repo

	// Build a set of existing file paths with a single API call.
	existing := make(map[string]bool)
	opts := &gitlab.ListTreeOptions{
		Ref:       gitlab.Ptr(branch),
		Recursive: gitlab.Ptr(true),
		ListOptions: gitlab.ListOptions{PerPage: 100},
	}
	for {
		nodes, resp, err := p.client.Repositories.ListTree(pid, opts, gitlab.WithContext(ctx))
		if err != nil {
			// If the branch is empty or repo is new, treat all files as creates.
			break
		}
		for _, n := range nodes {
			if n.Type == "blob" {
				existing[n.Path] = true
			}
		}
		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	actions := make([]*gitlab.CommitActionOptions, len(files))
	for i, f := range files {
		action := gitlab.FileCreate
		if existing[f.Path] {
			action = gitlab.FileUpdate
		}

		content := string(f.Content)
		actions[i] = &gitlab.CommitActionOptions{
			Action:   gitlab.Ptr(action),
			FilePath: gitlab.Ptr(f.Path),
			Content:  gitlab.Ptr(content),
		}
	}

	commit, resp, err := p.client.Commits.CreateCommit(pid, &gitlab.CreateCommitOptions{
		Branch:        gitlab.Ptr(branch),
		CommitMessage: gitlab.Ptr(message),
		Actions:        actions,
	}, gitlab.WithContext(ctx))
	if err != nil {
		return nil, p.wrapError(err, resp)
	}

	return &CommitResult{
		SHA:     commit.ID,
		URL:     commit.WebURL,
		Message: commit.Message,
	}, nil
}

func (p *GitLabProvider) CreateBranch(ctx context.Context, owner, repo, branch, baseSHA string) error {
	pid := owner + "/" + repo
	_, resp, err := p.client.Branches.CreateBranch(pid, &gitlab.CreateBranchOptions{
		Branch: gitlab.Ptr(branch),
		Ref:    gitlab.Ptr(baseSHA),
	}, gitlab.WithContext(ctx))
	if err != nil {
		return p.wrapError(err, resp)
	}
	return nil
}

func (p *GitLabProvider) CreatePullRequest(ctx context.Context, owner, repo, title, body, head, base string) (*PullRequestResult, error) {
	pid := owner + "/" + repo
	mr, resp, err := p.client.MergeRequests.CreateMergeRequest(pid, &gitlab.CreateMergeRequestOptions{
		Title:        gitlab.Ptr(title),
		Description:  gitlab.Ptr(body),
		SourceBranch: gitlab.Ptr(head),
		TargetBranch: gitlab.Ptr(base),
	}, gitlab.WithContext(ctx))
	if err != nil {
		return nil, p.wrapError(err, resp)
	}

	return &PullRequestResult{
		Number:  int(mr.IID),
		URL:     mr.WebURL,
		HTMLURL: mr.WebURL,
		Title:   mr.Title,
	}, nil
}

func (p *GitLabProvider) wrapError(err error, resp *gitlab.Response) error {
	if resp == nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return &AuthenticationError{Message: "invalid or expired token"}
	case http.StatusForbidden:
		return fmt.Errorf("forbidden: %w", err)
	case http.StatusNotFound:
		return fmt.Errorf("not found: %w", err)
	case http.StatusTooManyRequests:
		retryAfter := resp.Header.Get("Retry-After")
		return &RateLimitError{ResetTime: retryAfter}
	default:
		return err
	}
}

func projectToRepository(proj *gitlab.Project) *Repository {
	r := &Repository{
		Name:          proj.Path,
		FullName:      proj.PathWithNamespace,
		Description:   proj.Description,
		DefaultBranch: proj.DefaultBranch,
		CloneURL:      proj.HTTPURLToRepo,
		SSHURL:        proj.SSHURLToRepo,
		HTMLURL:       proj.WebURL,
	}
	if proj.Visibility == gitlab.PrivateVisibility || proj.Visibility == gitlab.InternalVisibility {
		r.Private = true
	}
	if proj.LastActivityAt != nil {
		r.UpdatedAt = proj.LastActivityAt.Format("2006-01-02T15:04:05Z")
	}
	return r
}

// normalizeGitLabURL ensures the URL ends with /api/v4 for the client.
func normalizeGitLabURL(rawURL string) string {
	if rawURL == "" {
		return "https://gitlab.com/api/v4"
	}
	u := strings.TrimSuffix(rawURL, "/")
	if !strings.HasSuffix(u, "/api/v4") {
		u += "/api/v4"
	}
	return u
}
