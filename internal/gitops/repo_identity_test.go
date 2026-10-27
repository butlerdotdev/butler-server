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
	"errors"
	"testing"
)

func TestProviderWebBaseURL(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		providerURL  string
		want         string
		wantErr      bool
	}{
		{"github public via api host", "github", "https://api.github.com", "https://github.com", false},
		{"github public via web host", "github", "https://github.com", "https://github.com", false},
		{"github empty defaults to public", "github", "", "https://github.com", false},
		{"github enterprise strips api path", "github", "https://github.example.com/api/v3", "https://github.example.com", false},
		{"gitlab saas", "gitlab", "https://gitlab.com", "https://gitlab.com", false},
		{"gitlab empty defaults to saas", "gitlab", "", "https://gitlab.com", false},
		{"gitlab self hosted", "gitlab", "https://gitlab.example.com", "https://gitlab.example.com", false},
		{"gitlab self hosted second instance", "gitlab", "https://gitlab.internal.example.net", "https://gitlab.internal.example.net", false},
		{"gitlab api suffix trimmed", "gitlab", "https://gitlab.internal.example.net/api/v4", "https://gitlab.internal.example.net", false},
		{"unconfigured type fails", "", "https://gitlab.internal.example.net", "", true},
		{"unsupported type fails", "bitbucket", "https://bitbucket.example.com", "", true},
		{"malformed url fails", "gitlab", "://not a url", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ProviderWebBaseURL(tt.providerType, tt.providerURL)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestProviderWebBaseURLUnsupportedIsTyped(t *testing.T) {
	_, err := ProviderWebBaseURL("bitbucket", "https://bitbucket.example.com")
	var unsupported *UnsupportedProviderError
	if !errors.As(err, &unsupported) {
		t.Fatalf("want UnsupportedProviderError, got %T (%v)", err, err)
	}
}

func TestRepositoryWebURL(t *testing.T) {
	tests := []struct {
		name         string
		providerType string
		providerURL  string
		fullName     string
		want         string
		wantErr      bool
	}{
		{
			name: "gitlab nested group preserved", providerType: "gitlab",
			providerURL: "https://gitlab.internal.example.net",
			fullName:    "platform/infra/platform/runners/live-infrastructure",
			want:        "https://gitlab.internal.example.net/platform/infra/platform/runners/live-infrastructure",
		},
		{
			name: "gitlab legacy nested path preserved", providerType: "gitlab",
			providerURL: "https://gitlab.example.com",
			fullName:    "platform/etl/airflow/staging/live-infrastructure",
			want:        "https://gitlab.example.com/platform/etl/airflow/staging/live-infrastructure",
		},
		{
			name: "github public", providerType: "github",
			providerURL: "https://api.github.com",
			fullName:    "butlerdotdev/butler-server",
			want:        "https://github.com/butlerdotdev/butler-server",
		},
		{
			name: "github enterprise", providerType: "github",
			providerURL: "https://github.example.com/api/v3",
			fullName:    "platform/live-infrastructure",
			want:        "https://github.example.com/platform/live-infrastructure",
		},
		{
			name: "trailing .git trimmed", providerType: "gitlab",
			providerURL: "https://gitlab.internal.example.net",
			fullName:    "platform/loki/live-infrastructure.git",
			want:        "https://gitlab.internal.example.net/platform/loki/live-infrastructure",
		},
		{name: "single segment rejected", providerType: "gitlab", providerURL: "https://gitlab.internal.example.net", fullName: "live-infrastructure", wantErr: true},
		{name: "empty rejected", providerType: "gitlab", providerURL: "https://gitlab.internal.example.net", fullName: "", wantErr: true},
		{name: "unsupported provider rejected", providerType: "bitbucket", providerURL: "https://x.example.com", fullName: "a/b", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RepositoryWebURL(tt.providerType, tt.providerURL, tt.fullName)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// The defect this closes: a GitLab install used to record github.com URLs for
// every cluster it enabled GitOps on.
func TestRepositoryWebURLNeverFabricatesGitHubForGitLab(t *testing.T) {
	got, err := RepositoryWebURL("gitlab", "https://gitlab.internal.example.net",
		"platform/infra/data/airflow/live-infrastructure")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if want := "https://gitlab.internal.example.net/"; got[:len(want)] != want {
		t.Fatalf("recorded URL %q is not on the configured provider", got)
	}
}

func TestSplitRepoURL(t *testing.T) {
	tests := []struct {
		name, in, host, full string
		wantErr              bool
	}{
		{name: "https nested", in: "https://gitlab.internal.example.net/platform/infra/platform/runners/live-infrastructure.git",
			host: "gitlab.internal.example.net", full: "platform/infra/platform/runners/live-infrastructure"},
		{name: "https two segments", in: "https://github.com/butlerdotdev/butler-server", host: "github.com", full: "butlerdotdev/butler-server"},
		{name: "ssh scp style nested", in: "git@gitlab.example.com:platform/loki/staging/live-infrastructure.git",
			host: "gitlab.example.com", full: "platform/loki/staging/live-infrastructure"},
		{name: "empty", in: "", wantErr: true},
		{name: "host only", in: "https://gitlab.internal.example.net", wantErr: true},
		{name: "garbage", in: "not-a-url", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			host, full, err := SplitRepoURL(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q %q", host, full)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if host != tt.host || full != tt.full {
				t.Fatalf("got %q / %q, want %q / %q", host, full, tt.host, tt.full)
			}
		})
	}
}

func TestResolveRepoForProviderPreservesNestedGroups(t *testing.T) {
	owner, repo, err := ResolveRepoForProvider(
		"https://gitlab.example.com/platform/etl/airflow/staging/live-infrastructure",
		"gitlab", "https://gitlab.example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "platform/etl/airflow/staging" || repo != "live-infrastructure" {
		t.Fatalf("got %q / %q, want the full nested group preserved", owner, repo)
	}
	if got := owner + "/" + repo; got != "platform/etl/airflow/staging/live-infrastructure" {
		t.Fatalf("project id round-trip = %q", got)
	}
}

// Transition safety: while a cluster is still backed by the old provider, a
// Butler that has already been switched to the new one must refuse rather than
// address the same path on the new host.
func TestResolveRepoForProviderFailsClosedAcrossHosts(t *testing.T) {
	_, _, err := ResolveRepoForProvider(
		"https://gitlab.example.com/platform/loki/staging/live-infrastructure",
		"gitlab", "https://gitlab.internal.example.net")
	var mismatch *ProviderHostMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("want ProviderHostMismatchError, got %T (%v)", err, err)
	}
	if mismatch.RepositoryHost != "gitlab.example.com" || mismatch.ProviderHost != "gitlab.internal.example.net" {
		t.Fatalf("mismatch reported wrong hosts: %+v", mismatch)
	}
}

// The fabricated github.com URLs left behind by the old defect must also fail
// closed on a GitLab install, rather than being addressed on the GitLab host.
func TestResolveRepoForProviderRejectsFabricatedGitHubURL(t *testing.T) {
	_, _, err := ResolveRepoForProvider(
		"https://github.com/platform/etl/airflow/staging/live-infrastructure",
		"gitlab", "https://gitlab.example.com")
	var mismatch *ProviderHostMismatchError
	if !errors.As(err, &mismatch) {
		t.Fatalf("want ProviderHostMismatchError, got %T (%v)", err, err)
	}
}

func TestResolveRepoForProviderGitHubStillWorks(t *testing.T) {
	owner, repo, err := ResolveRepoForProvider(
		"https://github.com/butlerdotdev/butler-server", "github", "https://api.github.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if owner != "butlerdotdev" || repo != "butler-server" {
		t.Fatalf("got %q / %q", owner, repo)
	}
}

func TestResolveRepoForProviderUnsupportedAndMalformed(t *testing.T) {
	if _, _, err := ResolveRepoForProvider("https://gitlab.internal.example.net/a/b", "bitbucket", "https://x"); err == nil {
		t.Fatal("unsupported provider must fail closed")
	}
	if _, _, err := ResolveRepoForProvider("https://gitlab.internal.example.net/a/b", "", ""); err == nil {
		t.Fatal("unconfigured provider must fail closed")
	}
	if _, _, err := ResolveRepoForProvider("", "gitlab", "https://gitlab.internal.example.net"); err == nil {
		t.Fatal("empty repository URL must fail closed")
	}
}
