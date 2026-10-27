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
	"fmt"
	"net/url"
	"strings"
)

// Repository identity helpers.
//
// Butler holds one Git provider per install. Two things follow from that and
// both are enforced here rather than at each call site:
//
//  1. A repository URL recorded for a cluster must be derived from the
//     configured provider, never assembled from a hardcoded host. A GitLab
//     install must not record github.com URLs.
//
//  2. A repository URL that was recorded earlier must be checked against the
//     currently configured provider before Butler writes to it. If the host
//     does not match, Butler refuses. Writing to the same path on a different
//     host is never the right recovery: that path either does not exist, or it
//     belongs to somebody else.

// ProviderHostMismatchError reports that a stored repository lives on a
// different Git host than the one Butler is configured for. Butler fails
// closed on this rather than addressing the same path on the configured host.
type ProviderHostMismatchError struct {
	RepositoryURL  string
	RepositoryHost string
	ProviderHost   string
}

func (e *ProviderHostMismatchError) Error() string {
	return fmt.Sprintf(
		"repository %q is hosted on %q but Butler is configured for %q; "+
			"Butler will not write to a different host. Migrate the repository or "+
			"update the cluster's recorded repository URL first.",
		e.RepositoryURL, e.RepositoryHost, e.ProviderHost)
}

// ProviderWebBaseURL returns the browser/clone base URL for a provider, given
// the provider type and the API URL stored in the GitOps configuration.
//
// The stored URL is an API URL for GitHub (https://api.github.com, or
// https://github.example.com/api/v3 for Enterprise) and an instance URL for
// GitLab (https://gitlab.com, or a self-hosted instance). Callers need the
// web base in both cases.
func ProviderWebBaseURL(providerType, providerURL string) (string, error) {
	switch providerType {
	case "github":
		if providerURL == "" {
			return "https://github.com", nil
		}
		u, err := url.Parse(providerURL)
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("invalid github provider URL %q", providerURL)
		}
		// Public GitHub is configured by its API host; the web host differs.
		if strings.EqualFold(u.Hostname(), "api.github.com") || strings.EqualFold(u.Hostname(), "github.com") {
			return "https://github.com", nil
		}
		// GitHub Enterprise: the API lives under /api/v3 on the web host.
		return strings.TrimSuffix(u.Scheme+"://"+u.Host, "/"), nil
	case "gitlab":
		if providerURL == "" {
			return "https://gitlab.com", nil
		}
		u, err := url.Parse(strings.TrimSuffix(providerURL, "/api/v4"))
		if err != nil || u.Host == "" {
			return "", fmt.Errorf("invalid gitlab provider URL %q", providerURL)
		}
		return u.Scheme + "://" + u.Host, nil
	case "":
		return "", fmt.Errorf("git provider type is not configured")
	default:
		return "", &UnsupportedProviderError{Provider: providerType}
	}
}

// RepositoryWebURL builds the canonical repository URL for a full repository
// name (owner/repo, where owner may be a nested GitLab group path) against the
// configured provider. It never falls back to a hardcoded host.
func RepositoryWebURL(providerType, providerURL, fullName string) (string, error) {
	base, err := ProviderWebBaseURL(providerType, providerURL)
	if err != nil {
		return "", err
	}
	fullName = strings.Trim(strings.TrimSuffix(fullName, ".git"), "/")
	if _, _, err := ParseRepoFullName(fullName); err != nil {
		return "", err
	}
	return base + "/" + fullName, nil
}

// SplitRepoURL splits a repository URL into its host and its full repository
// path. It accepts https URLs and scp-style SSH remotes. Unlike ParseRepoURL it
// keeps the host, so the caller can check which provider the repository
// belongs to.
func SplitRepoURL(repoURL string) (host, fullName string, err error) {
	raw := strings.TrimSpace(repoURL)
	if raw == "" {
		return "", "", fmt.Errorf("empty repository URL")
	}
	raw = strings.TrimSuffix(raw, ".git")

	if strings.HasPrefix(raw, "git@") || (!strings.Contains(raw, "://") && strings.Contains(raw, ":")) {
		// scp-style: git@host:group/sub/repo
		trimmed := strings.TrimPrefix(raw, "git@")
		parts := strings.SplitN(trimmed, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", fmt.Errorf("invalid SSH repository URL %q", repoURL)
		}
		return parts[0], strings.Trim(parts[1], "/"), nil
	}

	u, parseErr := url.Parse(raw)
	if parseErr != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid repository URL %q", repoURL)
	}
	path := strings.Trim(u.Path, "/")
	if path == "" {
		return "", "", fmt.Errorf("repository URL %q has no repository path", repoURL)
	}
	return u.Hostname(), path, nil
}

// ResolveRepoForProvider takes a repository URL recorded for a cluster and the
// currently configured provider, and returns the owner and repository to
// address through the provider's API.
//
// The full path is preserved, so nested GitLab group paths
// (group/subgroup/service/repo) resolve to owner "group/subgroup/service" and
// repository "repo", which is what the GitLab API expects as a project ID.
//
// It returns a ProviderHostMismatchError when the repository belongs to a
// different host than the configured provider. That is the transition-safety
// case: a cluster whose repository has not been migrated yet must fail closed
// instead of having Butler write to the same path on the new host.
func ResolveRepoForProvider(repoURL, providerType, providerURL string) (owner, repo string, err error) {
	host, fullName, err := SplitRepoURL(repoURL)
	if err != nil {
		return "", "", err
	}

	base, err := ProviderWebBaseURL(providerType, providerURL)
	if err != nil {
		return "", "", err
	}
	providerHost, _, err := hostOf(base)
	if err != nil {
		return "", "", err
	}

	if !strings.EqualFold(host, providerHost) {
		return "", "", &ProviderHostMismatchError{
			RepositoryURL:  repoURL,
			RepositoryHost: host,
			ProviderHost:   providerHost,
		}
	}

	return ParseRepoFullName(fullName)
}

func hostOf(rawURL string) (host, scheme string, err error) {
	u, parseErr := url.Parse(rawURL)
	if parseErr != nil || u.Host == "" {
		return "", "", fmt.Errorf("invalid URL %q", rawURL)
	}
	return u.Hostname(), u.Scheme, nil
}
