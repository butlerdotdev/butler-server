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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewGitLabProvider_EmptyToken(t *testing.T) {
	_, err := NewGitLabProvider(GitProviderConfig{
		Type:  "gitlab",
		Token: "",
		URL:   "https://gitlab.example.com",
	})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if _, ok := err.(*AuthenticationError); !ok {
		t.Errorf("expected AuthenticationError, got %T: %v", err, err)
	}
}

func TestNewGitLabProvider_ValidToken(t *testing.T) {
	p, err := NewGitLabProvider(GitProviderConfig{
		Type:  "gitlab",
		Token: "glpat-test",
		URL:   "https://gitlab.example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if p.Name() != "gitlab" {
		t.Errorf("Name() = %q, want %q", p.Name(), "gitlab")
	}
}

func TestNormalizeGitLabURL(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", "https://gitlab.com/api/v4"},
		{"https://gitlab.example.com", "https://gitlab.example.com/api/v4"},
		{"https://gitlab.example.com/", "https://gitlab.example.com/api/v4"},
		{"https://gitlab.example.com/api/v4", "https://gitlab.example.com/api/v4"},
		{"https://gitlab.example.com/api/v4/", "https://gitlab.example.com/api/v4"},
	}
	for _, tt := range tests {
		got := normalizeGitLabURL(tt.in)
		if got != tt.want {
			t.Errorf("normalizeGitLabURL(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestGitLabProvider_ValidateToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Private-Token") == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"username": "testuser",
			"email":    "test@example.com",
			"id":       1,
		})
	})
	mux.HandleFunc("/api/v4/personal_access_tokens/self", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":     1,
			"scopes": []string{"api", "read_repository"},
			"active": true,
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, err := NewGitLabProvider(GitProviderConfig{
		Token: "glpat-test",
		URL:   srv.URL,
	})
	if err != nil {
		t.Fatalf("NewGitLabProvider: %v", err)
	}

	v, err := p.ValidateToken(t.Context())
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if !v.Valid {
		t.Error("expected Valid=true")
	}
	if v.Username != "testuser" {
		t.Errorf("Username = %q, want %q", v.Username, "testuser")
	}
	if v.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", v.Email, "test@example.com")
	}
	if len(v.Scopes) != 2 || v.Scopes[0] != "api" {
		t.Errorf("Scopes = %v, want [api read_repository]", v.Scopes)
	}
}

func TestGitLabProvider_ListRepositories(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{
				"id":                   1,
				"path":                 "myrepo",
				"path_with_namespace":  "mygroup/myrepo",
				"description":          "test repo",
				"default_branch":       "main",
				"http_url_to_repo":     "https://gitlab.example.com/mygroup/myrepo.git",
				"ssh_url_to_repo":      "git@gitlab.example.com:mygroup/myrepo.git",
				"web_url":              "https://gitlab.example.com/mygroup/myrepo",
				"visibility":           "private",
				"last_activity_at":     "2026-01-01T00:00:00Z",
				"namespace":            map[string]interface{}{"path": "mygroup"},
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, _ := NewGitLabProvider(GitProviderConfig{Token: "test", URL: srv.URL})
	repos, err := p.ListRepositories(t.Context())
	if err != nil {
		t.Fatalf("ListRepositories: %v", err)
	}
	if len(repos) != 1 {
		t.Fatalf("got %d repos, want 1", len(repos))
	}
	if repos[0].FullName != "mygroup/myrepo" {
		t.Errorf("FullName = %q, want %q", repos[0].FullName, "mygroup/myrepo")
	}
	if !repos[0].Private {
		t.Error("expected Private=true for private visibility")
	}
}

func TestGitLabProvider_GetBranchSHA(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/mygroup%2Fmyrepo/repository/branches/main", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name": "main",
			"commit": map[string]interface{}{
				"id": "abc123def456",
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, _ := NewGitLabProvider(GitProviderConfig{Token: "test", URL: srv.URL})
	sha, err := p.GetBranchSHA(t.Context(), "mygroup", "myrepo", "main")
	if err != nil {
		t.Fatalf("GetBranchSHA: %v", err)
	}
	if sha != "abc123def456" {
		t.Errorf("SHA = %q, want %q", sha, "abc123def456")
	}
}

func TestGitLabProvider_CreateBranch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/mygroup%2Fmyrepo/repository/branches", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"name": "feature-branch",
			"commit": map[string]interface{}{
				"id": "abc123",
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, _ := NewGitLabProvider(GitProviderConfig{Token: "test", URL: srv.URL})
	err := p.CreateBranch(t.Context(), "mygroup", "myrepo", "feature-branch", "abc123")
	if err != nil {
		t.Fatalf("CreateBranch: %v", err)
	}
}

func TestGitLabProvider_CreatePullRequest(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/mygroup%2Fmyrepo/merge_requests", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"iid":     42,
			"web_url": "https://gitlab.example.com/mygroup/myrepo/-/merge_requests/42",
			"title":   "test MR",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, _ := NewGitLabProvider(GitProviderConfig{Token: "test", URL: srv.URL})
	result, err := p.CreatePullRequest(t.Context(), "mygroup", "myrepo", "test MR", "body", "feature", "main")
	if err != nil {
		t.Fatalf("CreatePullRequest: %v", err)
	}
	if result.Number != 42 {
		t.Errorf("Number = %d, want 42", result.Number)
	}
	if result.Title != "test MR" {
		t.Errorf("Title = %q, want %q", result.Title, "test MR")
	}
}

func TestGitLabProvider_RegistryRegistered(t *testing.T) {
	_, err := NewGitProvider(GitProviderConfig{
		Type:  "gitlab",
		Token: "test",
		URL:   "https://gitlab.example.com",
	})
	if err != nil {
		t.Fatalf("NewGitProvider(gitlab) failed: %v", err)
	}
}

func TestParseRepoURL_SelfHosted(t *testing.T) {
	tests := []struct {
		url       string
		wantOwner string
		wantRepo  string
	}{
		{"https://gitlab.corteva.com/infra/butler-gitops", "infra", "butler-gitops"},
		{"https://gitlab.corteva.com/infra/butler-gitops.git", "infra", "butler-gitops"},
		{"https://github.example.com/org/repo", "org", "repo"},
		{"https://github.com/butlerdotdev/butler-cli", "butlerdotdev", "butler-cli"},
		{"https://gitlab.com/group/project", "group", "project"},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			owner, repo, err := ParseRepoURL(tt.url)
			if err != nil {
				t.Fatalf("ParseRepoURL(%q): %v", tt.url, err)
			}
			if owner != tt.wantOwner || repo != tt.wantRepo {
				t.Errorf("got (%q, %q), want (%q, %q)", owner, repo, tt.wantOwner, tt.wantRepo)
			}
		})
	}
}

func TestGitLabProvider_GetFileContent(t *testing.T) {
	content := "hello world\n"
	encoded := base64.StdEncoding.EncodeToString([]byte(content))

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v4/projects/mygroup%2Fmyrepo/repository/files/path%2Fto%2Ffile.yaml", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"file_name": "file.yaml",
			"file_path": "path/to/file.yaml",
			"content":   encoded,
			"encoding":  "base64",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, _ := NewGitLabProvider(GitProviderConfig{Token: "test", URL: srv.URL})
	data, err := p.GetFileContent(t.Context(), "mygroup", "myrepo", "path/to/file.yaml", "main")
	if err != nil {
		t.Fatalf("GetFileContent: %v", err)
	}
	if string(data) != content {
		t.Errorf("content = %q, want %q", string(data), content)
	}
}

func TestGitLabProvider_CommitFiles(t *testing.T) {
	var receivedActions int
	mux := http.NewServeMux()
	// Tree listing to determine which files exist
	mux.HandleFunc("/api/v4/projects/mygroup%2Fmyrepo/repository/tree", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]interface{}{
			{"path": "existing.yaml", "type": "blob"},
		})
	})
	// Commit creation
	mux.HandleFunc("/api/v4/projects/mygroup%2Fmyrepo/repository/commits", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		actions, _ := body["actions"].([]interface{})
		receivedActions = len(actions)

		json.NewEncoder(w).Encode(map[string]interface{}{
			"id":      "sha256abc",
			"web_url": "https://gitlab.example.com/mygroup/myrepo/-/commit/sha256abc",
			"message": "test commit",
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, _ := NewGitLabProvider(GitProviderConfig{Token: "test", URL: srv.URL})
	result, err := p.CommitFiles(t.Context(), "mygroup", "myrepo", "main", "test commit", []FileCommit{
		{Path: "existing.yaml", Content: []byte("updated")},
		{Path: "new-file.yaml", Content: []byte("created")},
	})
	if err != nil {
		t.Fatalf("CommitFiles: %v", err)
	}
	if result.SHA != "sha256abc" {
		t.Errorf("SHA = %q, want %q", result.SHA, "sha256abc")
	}
	if receivedActions != 2 {
		t.Errorf("receivedActions = %d, want 2", receivedActions)
	}
}

func TestFluxBootstrapParams(t *testing.T) {
	tests := []struct {
		provider     string
		wantSubCmd   string
		wantTokenEnv string
	}{
		{"github", "github", "GITHUB_TOKEN"},
		{"gitlab", "gitlab", "GITLAB_TOKEN"},
		{"", "github", "GITHUB_TOKEN"},
		{"unknown", "github", "GITHUB_TOKEN"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("provider=%q", tt.provider), func(t *testing.T) {
			subCmd, tokenEnv := fluxBootstrapParams(tt.provider)
			if subCmd != tt.wantSubCmd {
				t.Errorf("subCmd = %q, want %q", subCmd, tt.wantSubCmd)
			}
			if tokenEnv != tt.wantTokenEnv {
				t.Errorf("tokenEnv = %q, want %q", tokenEnv, tt.wantTokenEnv)
			}
		})
	}
}
