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

package auth

import (
	"testing"
	"time"
)

// TestSessionService_Expiry confirms the accessor returns the duration the
// service was constructed with. The CLI device flow handler relies on this
// to compute an absolute session-token expiry to return alongside the JWT.
func TestSessionService_Expiry(t *testing.T) {
	tests := []struct {
		name   string
		expiry time.Duration
	}{
		{"default 24h", 24 * time.Hour},
		{"short 5m", 5 * time.Minute},
		{"long 7d", 7 * 24 * time.Hour},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewSessionService("test-secret", tt.expiry)
			if got := s.Expiry(); got != tt.expiry {
				t.Errorf("Expiry() = %v, want %v", got, tt.expiry)
			}
		})
	}
}
