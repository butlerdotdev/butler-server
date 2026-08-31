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
)

// GitProvider defines the interface for Git hosting providers (GitHub, GitLab, etc.).
// This is separate from the Provider interface which handles GitOps tools (Flux, ArgoCD).
type GitProvider interface {
	Name() string
	ValidateToken(ctx context.Context) (*TokenValidation, error)
	ListRepositories(ctx context.Context) ([]*Repository, error)
	GetRepository(ctx context.Context, owner, repo string) (*Repository, error)
	ListBranches(ctx context.Context, owner, repo string) ([]*Branch, error)
	GetBranchSHA(ctx context.Context, owner, repo, branch string) (string, error)
	GetFileContent(ctx context.Context, owner, repo, path, branch string) ([]byte, error)
	CreateOrUpdateFile(ctx context.Context, owner, repo, path, branch, message string, content []byte) (*CommitResult, error)
	CreateOrUpdateFiles(ctx context.Context, owner, repo, branch, message string, files []FileCommit) (*CommitResult, error)
	CommitFiles(ctx context.Context, owner, repo, branch, message string, files []FileCommit) (*CommitResult, error)
	CreateBranch(ctx context.Context, owner, repo, branch, baseSHA string) error
	CreatePullRequest(ctx context.Context, owner, repo, title, body, head, base string) (*PullRequestResult, error)
}

// TokenValidation contains the result of token validation.
type TokenValidation struct {
	Valid    bool
	Name     string // Display name from the git provider
	Username string
	Email    string
	Scopes   []string
}

// GitProviderConfig contains configuration for a Git provider.
type GitProviderConfig struct {
	Type         string
	Token        string
	URL          string
	Organization string
}

var gitProviderRegistry = make(map[string]func(cfg GitProviderConfig) (GitProvider, error))

// RegisterGitProvider registers a Git provider factory function.
func RegisterGitProvider(name string, factory func(cfg GitProviderConfig) (GitProvider, error)) {
	gitProviderRegistry[name] = factory
}

// NewGitProvider creates a Git provider instance from configuration.
func NewGitProvider(cfg GitProviderConfig) (GitProvider, error) {
	factory, ok := gitProviderRegistry[cfg.Type]
	if !ok {
		return nil, &UnsupportedProviderError{Provider: cfg.Type}
	}
	return factory(cfg)
}

// UnsupportedProviderError indicates an unknown provider type.
type UnsupportedProviderError struct {
	Provider string
}

func (e *UnsupportedProviderError) Error() string {
	return "unsupported git provider: " + e.Provider
}

// AuthenticationError indicates an authentication failure.
type AuthenticationError struct {
	Message string
}

func (e *AuthenticationError) Error() string {
	return "authentication failed: " + e.Message
}

// RateLimitError indicates a rate limit was hit.
type RateLimitError struct {
	ResetTime string
}

func (e *RateLimitError) Error() string {
	return "rate limit exceeded, resets at: " + e.ResetTime
}

// Repository listing walks every page of the provider's API. These bound the
// walk so a pathological or looping response cannot spin forever, without
// silently returning a partial universe: exceeding the bound is an error.
const (
	repositoryPageSize = 100
	maxRepositoryPages = 200
)

// RepositoryListTooLargeError reports that a repository listing did not
// terminate within the page bound. It is returned instead of a truncated list,
// because a caller cannot tell a short list from a complete one.
type RepositoryListTooLargeError struct {
	Scope    string
	Pages    int
	PageSize int
}

func (e *RepositoryListTooLargeError) Error() string {
	scope := e.Scope
	if scope == "" {
		scope = "the configured provider"
	}
	return fmt.Sprintf(
		"repository listing for %s did not finish within %d pages of %d; refusing to return a partial list",
		scope, e.Pages, e.PageSize)
}
