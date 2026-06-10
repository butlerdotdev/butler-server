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

import "testing"

func TestHostnameFromURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		// The bug: the GitHub gitops config URL is the API host, which flux
		// must NOT receive as --hostname. Returns "" so flux uses github.com.
		{"github api host", "https://api.github.com", ""},
		{"github api host uppercase", "https://API.GitHub.com", ""},
		// Public SaaS hosts already mapped to "" (no regression).
		{"github.com", "https://github.com", ""},
		{"gitlab.com", "https://gitlab.com", ""},
		// Inverse failure mode: genuine Enterprise / self-hosted hosts MUST
		// keep their real hostname; the exact-match must not collapse a host
		// that merely contains "github"/"gitlab".
		{"github enterprise", "https://github.mycorp.com", "github.mycorp.com"},
		{"gitlab self-hosted", "https://gitlab.mycorp.com", "gitlab.mycorp.com"},
		{"enterprise with github substring", "https://github.example.org", "github.example.org"},
		// Degenerate inputs.
		{"empty", "", ""},
		{"unparseable", "://bad", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HostnameFromURL(tt.url); got != tt.want {
				t.Errorf("HostnameFromURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
