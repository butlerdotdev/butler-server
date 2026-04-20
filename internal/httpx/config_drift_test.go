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

package httpx

import (
	"os"
	"testing"

	"github.com/butlerdotdev/butler-server/internal/config"
)

// TestBaseURLSentinelMatchesConfigDefault guards against drift between
// the default applied in config.Load when BUTLER_BASE_URL is unset and
// the sentinel PublicBaseURL uses to detect that unset-default value.
// If someone changes one and not the other, the sentinel stops
// recognizing the "unset" case and request-based derivation silently
// stops firing for fresh deployments. The test unsets BUTLER_BASE_URL
// for its duration, loads config, and asserts the loaded value equals
// the sentinel.
func TestBaseURLSentinelMatchesConfigDefault(t *testing.T) {
	prev, had := os.LookupEnv("BUTLER_BASE_URL")
	if err := os.Unsetenv("BUTLER_BASE_URL"); err != nil {
		t.Fatalf("unset BUTLER_BASE_URL: %v", err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("BUTLER_BASE_URL", prev)
		}
	})

	cfg := config.Load()
	if cfg.Server.BaseURL != baseURLDefaultPlaceholder {
		t.Fatalf("config.Load default BaseURL = %q, sentinel = %q; update one or both so they agree", cfg.Server.BaseURL, baseURLDefaultPlaceholder)
	}
}
