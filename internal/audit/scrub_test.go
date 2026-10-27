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

package audit

import (
	"encoding/json"
	"strings"
	"testing"
)

// A sentinel that must never survive scrubbing. Fake, not a real credential.
const sentinel = "SENTINEL_MUST_NOT_SURVIVE"

// Every Butler request DTO field that carries a credential. Each must be
// redacted in the stored audit summary; the exact-key list did not cover
// the prefixed ones, which is finding D9.
func TestScrubRedactsEveryButlerCredentialField(t *testing.T) {
	fields := []string{
		"password", "clientSecret", "token", "kubeconfig",
		"harvesterKubeconfig", "nutanixPassword",
		"proxmoxPassword", "proxmoxTokenSecret", "proxmoxTokenId",
		"azureClientSecret", "gcpServiceAccount",
		"awsSecretAccessKey", "awsAccessKeyId",
		"privateKey", "apiKey", "serviceAccountJSON",
	}
	for _, f := range fields {
		body := []byte(`{"name":"lab","` + f + `":"` + sentinel + `"}`)
		got := ScrubRequestBody(body)
		if strings.Contains(got, sentinel) {
			t.Errorf("field %q: credential survived scrubbing: %s", f, got)
		}
		if !strings.Contains(got, `"name":"lab"`) {
			t.Errorf("field %q: non-secret context was lost: %s", f, got)
		}
	}
}

func TestScrubRedactsNestedAndArrayCredentials(t *testing.T) {
	body := []byte(`{
		"provider":"harvester",
		"oidc":{"issuerURL":"https://x","clientSecret":"` + sentinel + `"},
		"nodes":[{"name":"a","password":"` + sentinel + `"},{"name":"b"}],
		"scopes":["openid","email"]
	}`)
	got := ScrubRequestBody(body)
	if strings.Contains(got, sentinel) {
		t.Fatalf("nested or array credential survived: %s", got)
	}
	if !strings.Contains(got, `"issuerURL":"https://x"`) || !strings.Contains(got, `"openid"`) {
		t.Fatalf("non-secret nested context lost: %s", got)
	}
}

func TestScrubTopLevelArray(t *testing.T) {
	got := ScrubRequestBody([]byte(`[{"token":"` + sentinel + `"}]`))
	if strings.Contains(got, sentinel) {
		t.Fatalf("credential in a top-level array survived: %s", got)
	}
}

func TestScrubNeverReturnsRawNonJSON(t *testing.T) {
	// A truncated JSON body, as an oversized request would produce, is not
	// valid JSON and must not be returned raw.
	got := ScrubRequestBody([]byte(`{"harvesterKubeconfig":"` + sentinel))
	if strings.Contains(got, sentinel) {
		t.Fatalf("truncated body leaked a credential: %s", got)
	}
	if strings.Contains(ScrubRequestBody([]byte("plain text "+sentinel)), sentinel) {
		t.Fatalf("non-JSON body was returned raw")
	}
}

func TestScrubOversizedBodyOmitted(t *testing.T) {
	big := `{"harvesterKubeconfig":"` + strings.Repeat("x", maxScrubInput) + sentinel + `"}`
	got := ScrubRequestBody([]byte(big))
	if strings.Contains(got, sentinel) {
		t.Fatalf("oversized body leaked a credential")
	}
	if got != "[omitted: request body too large to summarize]" {
		t.Fatalf("unexpected oversized summary: %s", got)
	}
}

func TestScrubRedactionHasNoLengthOrPrefix(t *testing.T) {
	got := ScrubRequestBody([]byte(`{"clientSecret":"abcdefghijklmnop"}`))
	var parsed map[string]string
	if err := json.Unmarshal([]byte(got), &parsed); err != nil {
		t.Fatalf("scrubbed output is not JSON: %s", got)
	}
	if parsed["clientSecret"] != redactedValue {
		t.Fatalf("redaction did not use the sentinel: %q", parsed["clientSecret"])
	}
}

func TestScrubEmptyAndNonSecret(t *testing.T) {
	if ScrubRequestBody(nil) != "" {
		t.Fatalf("empty body should be empty summary")
	}
	got := ScrubRequestBody([]byte(`{"replicas":3,"environment":"e2e-dev"}`))
	if got != `{"environment":"e2e-dev","replicas":3}` && got != `{"replicas":3,"environment":"e2e-dev"}` {
		t.Fatalf("non-secret body altered unexpectedly: %s", got)
	}
}
