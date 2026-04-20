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

package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/butlerdotdev/butler-server/internal/config"
)

func newDeviceAuthorizeHandler() *DeviceFlowHandler {
	return &DeviceFlowHandler{
		deviceStore: auth.NewDeviceStore(),
		config: &config.Config{
			Server: config.ServerConfig{
				BaseURL: "http://localhost:8080",
			},
			CLIAuth: config.CLIAuthConfig{
				DeviceCodeExpiry: 15 * time.Minute,
			},
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

type deviceAuthorizeResponse struct {
	VerificationURI string `json:"verification_uri"`
}

func decodeDeviceAuthorizeResponse(t *testing.T, body []byte) deviceAuthorizeResponse {
	t.Helper()
	var resp deviceAuthorizeResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatalf("decode body: %v (body=%s)", err, string(body))
	}
	return resp
}

// TestDeviceAuthorize_DerivesVerificationURIFromRequest proves the bug
// fix: when config is at its post-bootstrap defaults and the request
// comes in with a real public Host, the emitted verification URI
// reflects the request's Host instead of advertising localhost.
func TestDeviceAuthorize_DerivesVerificationURIFromRequest(t *testing.T) {
	h := newDeviceAuthorizeHandler()

	req := httptest.NewRequest("POST", "/api/auth/cli/device", nil)
	req.Host = "butler.example.com"
	rec := httptest.NewRecorder()

	h.DeviceAuthorize(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	resp := decodeDeviceAuthorizeResponse(t, rec.Body.Bytes())

	if strings.Contains(resp.VerificationURI, "localhost") {
		t.Errorf("verification_uri = %q, must not advertise localhost for a non-localhost request", resp.VerificationURI)
	}
	if !strings.HasPrefix(resp.VerificationURI, "http://butler.example.com/") {
		t.Errorf("verification_uri = %q, want prefix http://butler.example.com/", resp.VerificationURI)
	}
}

// TestDeviceAuthorize_IgnoresForwardedHeadersWithoutTrust enforces the
// security property at the handler boundary: a request carrying
// X-Forwarded-Host/Proto from an untrusted client must not cause the
// server to advertise the attacker-supplied hostname in the
// verification URI unless TrustProxyHeaders is explicitly set.
func TestDeviceAuthorize_IgnoresForwardedHeadersWithoutTrust(t *testing.T) {
	h := newDeviceAuthorizeHandler()

	req := httptest.NewRequest("POST", "/api/auth/cli/device", nil)
	req.Host = "butler.example.com"
	req.Header.Set("X-Forwarded-Host", "attacker.example.com")
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()

	h.DeviceAuthorize(rec, req)

	if rec.Code != 200 {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}

	resp := decodeDeviceAuthorizeResponse(t, rec.Body.Bytes())

	if strings.Contains(resp.VerificationURI, "attacker.example.com") {
		t.Errorf("verification_uri = %q, X-Forwarded-Host must be ignored without TrustProxyHeaders", resp.VerificationURI)
	}
	if !strings.Contains(resp.VerificationURI, "butler.example.com") {
		t.Errorf("verification_uri = %q, must reflect the real request Host", resp.VerificationURI)
	}
}
