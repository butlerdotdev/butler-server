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
	"net/http"
	"strings"

	"github.com/google/go-github/v60/github"
	"golang.org/x/oauth2"
)

func init() {
	RegisterGitProvider("github", NewGitHubProvider)
}

// GitHubProvider implements GitProvider for GitHub.
type GitHubProvider struct {
	client       *github.Client
	organization string
}

var _ GitProvider = (*GitHubProvider)(nil)

// NewGitHubProvider creates a new GitHub provider.
func NewGitHubProvider(cfg GitProviderConfig) (GitProvider, error) {
	if cfg.Token == "" {
		return nil, &AuthenticationError{Message: "token is required"}
	}

	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: cfg.Token})
	tc := oauth2.NewClient(context.Background(), ts)

	var client *github.Client
	var err error

	if cfg.URL != "" && cfg.URL != "https://api.github.com" {
		baseURL := strings.TrimSuffix(cfg.URL, "/")
		if !strings.HasSuffix(baseURL, "/api/v3") {
			baseURL += "/api/v3/"
		}
		client, err = github.NewClient(tc).WithEnterpriseURLs(baseURL, baseURL)
		if err != nil {
			return nil, fmt.Errorf("failed to create GitHub Enterprise client: %w", err)
		}
	} else {
		client = github.NewClient(tc)
	}

	return &GitHubProvider{
		client:       client,
		organization: cfg.Organization,
	}, nil
}

// Name returns the provider identifier.
func (p *GitHubProvider) Name() string {
	return "github"
}

// ValidateToken validates the token and returns user info.
func (p *GitHubProvider) ValidateToken(ctx context.Context) (*TokenValidation, error) {
	user, resp, err := p.client.Users.Get(ctx, "")
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return &TokenValidation{Valid: false}, nil
		}
		return nil, fmt.Errorf("failed to validate token: %w", err)
	}

	validation := &TokenValidation{
		Valid:    true,
		Username: user.GetLogin(),
		Email:    user.GetEmail(),
	}

	if scopes := resp.Header.Get("X-OAuth-Scopes"); scopes != "" {
		validation.Scopes = strings.Split(scopes, ", ")
	}

	return validation, nil
}

// ListRepositories returns repositories accessible to the user.
func (p *GitHubProvider) ListRepositories(ctx context.Context) ([]*Repository, error) {
	var allRepos []*Repository
	opts := &github.RepositoryListOptions{
		Sort:        "updated",
		Direction:   "desc",
		ListOptions: github.ListOptions{PerPage: 100},
	}

	for {
		repos, resp, err := p.client.Repositories.List(ctx, "", opts)
		if err != nil {
			return nil, p.wrapError(err, resp)
		}

		for _, r := range repos {
			if p.organization != "" && r.GetOwner().GetLogin() != p.organization {
				continue
			}

			allRepos = append(allRepos, &Repository{
				Name:          r.GetName(),
				FullName:      r.GetFullName(),
				Description:   r.GetDescription(),
				DefaultBranch: r.GetDefaultBranch(),
				Private:       r.GetPrivate(),
				CloneURL:      r.GetCloneURL(),
				SSHURL:        r.GetSSHURL(),
				HTMLURL:       r.GetHTMLURL(),
				UpdatedAt:     r.GetUpdatedAt().Format("2006-01-02T15:04:05Z"),
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allRepos, nil
}

// GetRepository returns a specific repository.
func (p *GitHubProvider) GetRepository(ctx context.Context, owner, repo string) (*Repository, error) {
	r, resp, err := p.client.Repositories.Get(ctx, owner, repo)
	if err != nil {
		return nil, p.wrapError(err, resp)
	}

	return &Repository{
		Name:          r.GetName(),
		FullName:      r.GetFullName(),
		Description:   r.GetDescription(),
		DefaultBranch: r.GetDefaultBranch(),
		Private:       r.GetPrivate(),
		CloneURL:      r.GetCloneURL(),
		SSHURL:        r.GetSSHURL(),
		HTMLURL:       r.GetHTMLURL(),
		UpdatedAt:     r.GetUpdatedAt().Format("2006-01-02T15:04:05Z"),
	}, nil
}

// ListBranches returns branches for a repository.
func (p *GitHubProvider) ListBranches(ctx context.Context, owner, repo string) ([]*Branch, error) {
	var allBranches []*Branch
	opts := &github.BranchListOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}

	repoInfo, _, _ := p.client.Repositories.Get(ctx, owner, repo)
	defaultBranch := ""
	if repoInfo != nil {
		defaultBranch = repoInfo.GetDefaultBranch()
	}

	for {
		branches, resp, err := p.client.Repositories.ListBranches(ctx, owner, repo, opts)
		if err != nil {
			return nil, p.wrapError(err, resp)
		}

		for _, b := range branches {
			allBranches = append(allBranches, &Branch{
				Name:      b.GetName(),
				Protected: b.GetProtected(),
				Default:   b.GetName() == defaultBranch,
			})
		}

		if resp.NextPage == 0 {
			break
		}
		opts.Page = resp.NextPage
	}

	return allBranches, nil
}

// GetBranchSHA returns the SHA of a branch's HEAD.
func (p *GitHubProvider) GetBranchSHA(ctx context.Context, owner, repo, branch string) (string, error) {
	ref, resp, err := p.client.Git.GetRef(ctx, owner, repo, "refs/heads/"+branch)
	if err != nil {
		return "", p.wrapError(err, resp)
	}
	return ref.GetObject().GetSHA(), nil
}

// GetFileContent returns the content of a file.
func (p *GitHubProvider) GetFileContent(ctx context.Context, owner, repo, path, branch string) ([]byte, error) {
	opts := &github.RepositoryContentGetOptions{Ref: branch}
	content, _, resp, err := p.client.Repositories.GetContents(ctx, owner, repo, path, opts)
	if err != nil {
		return nil, p.wrapError(err, resp)
	}

	if content == nil {
		return nil, fmt.Errorf("path is a directory, not a file")
	}

	decoded, err := content.GetContent()
	if err != nil {
		return nil, fmt.Errorf("failed to decode content: %w", err)
	}

	return []byte(decoded), nil
}

// CreateOrUpdateFile creates or updates a single file.
func (p *GitHubProvider) CreateOrUpdateFile(ctx context.Context, owner, repo, path, branch, message string, content []byte) (*CommitResult, error) {
	opts := &github.RepositoryContentFileOptions{
		Message: github.String(message),
		Content: content,
		Branch:  github.String(branch),
	}

	existing, _, _, _ := p.client.Repositories.GetContents(ctx, owner, repo, path, &github.RepositoryContentGetOptions{Ref: branch})
	if existing != nil {
		opts.SHA = existing.SHA
	}

	response, resp, err := p.client.Repositories.CreateFile(ctx, owner, repo, path, opts)
	if err != nil {
		return nil, p.wrapError(err, resp)
	}

	return &CommitResult{
		SHA:     response.Commit.GetSHA(),
		URL:     response.Commit.GetHTMLURL(),
		Message: message,
	}, nil
}

// CommitFiles commits multiple files atomically using Git Tree API.
func (p *GitHubProvider) CommitFiles(ctx context.Context, owner, repo, branch, message string, files []FileCommit) (*CommitResult, error) {
	ref, resp, err := p.client.Git.GetRef(ctx, owner, repo, "refs/heads/"+branch)
	if err != nil {
		return nil, p.wrapError(err, resp)
	}
	baseSHA := ref.GetObject().GetSHA()

	baseCommit, resp, err := p.client.Git.GetCommit(ctx, owner, repo, baseSHA)
	if err != nil {
		return nil, p.wrapError(err, resp)
	}
	baseTreeSHA := baseCommit.GetTree().GetSHA()

	entries := make([]*github.TreeEntry, len(files))
	for i, f := range files {
		mode := f.Mode
		if mode == "" {
			mode = "100644"
		}
		content := string(f.Content)
		entries[i] = &github.TreeEntry{
			Path:    github.String(f.Path),
			Mode:    github.String(mode),
			Type:    github.String("blob"),
			Content: github.String(content),
		}
	}

	newTree, resp, err := p.client.Git.CreateTree(ctx, owner, repo, baseTreeSHA, entries)
	if err != nil {
		return nil, p.wrapError(err, resp)
	}

	commit := &github.Commit{
		Message: github.String(message),
		Tree:    newTree,
		Parents: []*github.Commit{{SHA: github.String(baseSHA)}},
	}

	newCommit, resp, err := p.client.Git.CreateCommit(ctx, owner, repo, commit, nil)
	if err != nil {
		return nil, p.wrapError(err, resp)
	}

	ref.Object.SHA = newCommit.SHA
	_, resp, err = p.client.Git.UpdateRef(ctx, owner, repo, ref, false)
	if err != nil {
		return nil, p.wrapError(err, resp)
	}

	return &CommitResult{
		SHA:     newCommit.GetSHA(),
		URL:     newCommit.GetHTMLURL(),
		Message: message,
	}, nil
}

// CreateOrUpdateFiles creates or updates multiple files atomically.
func (p *GitHubProvider) CreateOrUpdateFiles(ctx context.Context, owner, repo, branch, message string, files []FileCommit) (*CommitResult, error) {
	return p.CommitFiles(ctx, owner, repo, branch, message, files)
}

// CreateBranch creates a new branch from a base SHA.
func (p *GitHubProvider) CreateBranch(ctx context.Context, owner, repo, branch, baseSHA string) error {
	ref := &github.Reference{
		Ref:    github.String("refs/heads/" + branch),
		Object: &github.GitObject{SHA: github.String(baseSHA)},
	}

	_, resp, err := p.client.Git.CreateRef(ctx, owner, repo, ref)
	if err != nil {
		return p.wrapError(err, resp)
	}

	return nil
}

// CreatePullRequest creates a pull request.
func (p *GitHubProvider) CreatePullRequest(ctx context.Context, owner, repo, title, body, head, base string) (*PullRequestResult, error) {
	pr := &github.NewPullRequest{
		Title: github.String(title),
		Body:  github.String(body),
		Head:  github.String(head),
		Base:  github.String(base),
	}

	created, resp, err := p.client.PullRequests.Create(ctx, owner, repo, pr)
	if err != nil {
		return nil, p.wrapError(err, resp)
	}

	htmlURL := created.GetHTMLURL()
	return &PullRequestResult{
		Number:  created.GetNumber(),
		URL:     htmlURL,
		HTMLURL: htmlURL,
		Title:   created.GetTitle(),
	}, nil
}

func (p *GitHubProvider) wrapError(err error, resp *github.Response) error {
	if resp == nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		return &AuthenticationError{Message: "invalid or expired token"}
	case http.StatusForbidden:
		if resp.Rate.Remaining == 0 {
			return &RateLimitError{ResetTime: resp.Rate.Reset.String()}
		}
		return fmt.Errorf("forbidden: %w", err)
	case http.StatusNotFound:
		return fmt.Errorf("not found: %w", err)
	default:
		return err
	}
}
