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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// fakeGitLab serves the group projects endpoint with GitLab's pagination
// headers so listing behaviour can be tested without a live instance.
type fakeGitLab struct {
	total     int
	failAfter int // if > 0, the page with this 1-based number returns 500
	pageHits  []int
}

func (f *fakeGitLab) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/groups/", func(w http.ResponseWriter, r *http.Request) {
		perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		if perPage <= 0 {
			perPage = 20
		}
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		if page <= 0 {
			page = 1
		}
		f.pageHits = append(f.pageHits, page)

		if f.failAfter > 0 && page == f.failAfter {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"upstream failure"}`))
			return
		}

		start := (page - 1) * perPage
		end := start + perPage
		if start > f.total {
			start = f.total
		}
		if end > f.total {
			end = f.total
		}
		items := make([]map[string]any, 0, end-start)
		for i := start; i < end; i++ {
			items = append(items, map[string]any{
				"id":                  i + 1,
				"path":                fmt.Sprintf("repo-%d", i+1),
				"path_with_namespace": fmt.Sprintf("group/sub/repo-%d", i+1),
				"default_branch":      "main",
				"visibility":          "internal",
			})
		}

		totalPages := (f.total + perPage - 1) / perPage
		if totalPages == 0 {
			totalPages = 1
		}
		w.Header().Set("X-Total", strconv.Itoa(f.total))
		w.Header().Set("X-Total-Pages", strconv.Itoa(totalPages))
		w.Header().Set("X-Page", strconv.Itoa(page))
		w.Header().Set("X-Per-Page", strconv.Itoa(perPage))
		if page < totalPages {
			w.Header().Set("X-Next-Page", strconv.Itoa(page+1))
		} else {
			w.Header().Set("X-Next-Page", "")
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(items)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func providerAgainst(t *testing.T, srv *httptest.Server, org string) GitProvider {
	t.Helper()
	p, err := NewGitLabProvider(GitProviderConfig{
		Type: "gitlab", URL: srv.URL, Token: "test-token", Organization: org,
	})
	if err != nil {
		t.Fatalf("NewGitLabProvider: %v", err)
	}
	return p
}

// The listing used to stop at an arbitrary 200 and return a short list that
// callers could not distinguish from a complete one.
func TestListRepositoriesReturnsEveryPage(t *testing.T) {
	for _, total := range []int{0, 1, 99, 100, 101, 200, 201, 272, 1000} {
		t.Run(fmt.Sprintf("total=%d", total), func(t *testing.T) {
			f := &fakeGitLab{total: total}
			p := providerAgainst(t, f.server(t), "group")

			repos, err := p.ListRepositories(context.Background())
			if err != nil {
				t.Fatalf("ListRepositories: %v", err)
			}
			if len(repos) != total {
				t.Fatalf("got %d repositories, want %d", len(repos), total)
			}
			if total > 0 {
				if repos[0].FullName != "group/sub/repo-1" {
					t.Fatalf("first repository = %q", repos[0].FullName)
				}
				want := fmt.Sprintf("group/sub/repo-%d", total)
				if repos[total-1].FullName != want {
					t.Fatalf("last repository = %q, want %q", repos[total-1].FullName, want)
				}
			}
		})
	}
}

// The count that matters for the estate this was found on.
func TestListRepositoriesCrossesTheOldCap(t *testing.T) {
	f := &fakeGitLab{total: 272}
	p := providerAgainst(t, f.server(t), "group")
	repos, err := p.ListRepositories(context.Background())
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) <= 200 {
		t.Fatalf("got %d repositories; the listing is still capped", len(repos))
	}
	if len(repos) != 272 {
		t.Fatalf("got %d repositories, want 272", len(repos))
	}
	if len(f.pageHits) != 3 {
		t.Fatalf("requested pages %v, want three pages at 100 per page", f.pageHits)
	}
}

// A failure on a later page must surface, not silently shorten the result.
func TestListRepositoriesFailsRatherThanTruncating(t *testing.T) {
	f := &fakeGitLab{total: 272, failAfter: 3}
	p := providerAgainst(t, f.server(t), "group")
	repos, err := p.ListRepositories(context.Background())
	if err == nil {
		t.Fatalf("expected an error, got %d repositories", len(repos))
	}
	if repos != nil {
		t.Fatalf("expected no partial result, got %d repositories", len(repos))
	}
}

func TestRepositoryListTooLargeErrorMessage(t *testing.T) {
	err := &RepositoryListTooLargeError{Scope: "group", Pages: maxRepositoryPages, PageSize: repositoryPageSize}
	var target *RepositoryListTooLargeError
	if !errors.As(error(err), &target) {
		t.Fatal("error type is not matchable")
	}
	if got := err.Error(); got == "" {
		t.Fatal("empty error message")
	}
}

// Page size and bound are the contract this listing relies on.
func TestRepositoryPaginationConstants(t *testing.T) {
	if repositoryPageSize != 100 {
		t.Fatalf("repositoryPageSize = %d, want the GitLab and GitHub maximum of 100", repositoryPageSize)
	}
	if maxRepositoryPages*repositoryPageSize < 20000 {
		t.Fatalf("page bound of %d pages is too tight for a large instance", maxRepositoryPages)
	}
}
