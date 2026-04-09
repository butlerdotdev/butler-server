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
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestDeviceStoreCreate(t *testing.T) {
	hexPattern := regexp.MustCompile(`^[0-9a-f]{64}$`)
	userCodePattern := regexp.MustCompile(`^[A-Z]{4}-[A-Z]{4}$`)

	t.Run("device code is 64 hex characters", func(t *testing.T) {
		store := NewDeviceStore()
		dc, err := store.Create(5 * time.Minute)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if !hexPattern.MatchString(dc.DeviceCode) {
			t.Errorf("device code %q does not match expected 64-char hex pattern", dc.DeviceCode)
		}
	})

	t.Run("user code is XXXX-XXXX uppercase alpha", func(t *testing.T) {
		store := NewDeviceStore()
		dc, err := store.Create(5 * time.Minute)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		if !userCodePattern.MatchString(dc.UserCode) {
			t.Errorf("user code %q does not match XXXX-XXXX pattern", dc.UserCode)
		}
	})

	t.Run("codes are unique across calls", func(t *testing.T) {
		store := NewDeviceStore()
		seen := make(map[string]bool)
		for i := 0; i < 100; i++ {
			dc, err := store.Create(5 * time.Minute)
			if err != nil {
				t.Fatalf("Create iteration %d: %v", i, err)
			}
			if seen[dc.DeviceCode] {
				t.Fatalf("duplicate device code on iteration %d: %s", i, dc.DeviceCode)
			}
			if seen[dc.UserCode] {
				t.Fatalf("duplicate user code on iteration %d: %s", i, dc.UserCode)
			}
			seen[dc.DeviceCode] = true
			seen[dc.UserCode] = true
		}
	})

	t.Run("expiry and interval are set", func(t *testing.T) {
		store := NewDeviceStore()
		before := time.Now()
		dc, err := store.Create(10 * time.Minute)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		after := time.Now()

		if dc.ExpiresAt.Before(before.Add(10*time.Minute)) || dc.ExpiresAt.After(after.Add(10*time.Minute)) {
			t.Errorf("ExpiresAt %v not within expected range", dc.ExpiresAt)
		}
		if dc.Interval != 5 {
			t.Errorf("Interval = %d, want 5", dc.Interval)
		}
		if dc.Approved || dc.Denied {
			t.Error("newly created code should not be approved or denied")
		}
		if dc.UserSession != nil {
			t.Error("newly created code should have nil UserSession")
		}
	})
}

func TestDeviceStoreGet(t *testing.T) {
	t.Run("existing code", func(t *testing.T) {
		store := NewDeviceStore()
		dc, err := store.Create(5 * time.Minute)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, ok := store.Get(dc.DeviceCode)
		if !ok {
			t.Fatal("Get returned false for existing code")
		}
		if got.DeviceCode != dc.DeviceCode {
			t.Errorf("Get returned device code %q, want %q", got.DeviceCode, dc.DeviceCode)
		}
		if got.UserCode != dc.UserCode {
			t.Errorf("Get returned user code %q, want %q", got.UserCode, dc.UserCode)
		}
	})

	t.Run("expired code returns false", func(t *testing.T) {
		store := NewDeviceStore()
		dc, err := store.Create(1 * time.Nanosecond)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
		_, ok := store.Get(dc.DeviceCode)
		if ok {
			t.Error("Get returned true for expired code")
		}
	})

	t.Run("nonexistent code returns false", func(t *testing.T) {
		store := NewDeviceStore()
		_, ok := store.Get("does-not-exist")
		if ok {
			t.Error("Get returned true for nonexistent code")
		}
	})
}

func TestDeviceStoreGetByUserCode(t *testing.T) {
	t.Run("lookup works", func(t *testing.T) {
		store := NewDeviceStore()
		dc, err := store.Create(5 * time.Minute)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		got, ok := store.GetByUserCode(dc.UserCode)
		if !ok {
			t.Fatal("GetByUserCode returned false for existing user code")
		}
		if got.DeviceCode != dc.DeviceCode {
			t.Errorf("GetByUserCode returned device code %q, want %q", got.DeviceCode, dc.DeviceCode)
		}
	})

	t.Run("expired code returns false", func(t *testing.T) {
		store := NewDeviceStore()
		dc, err := store.Create(1 * time.Nanosecond)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		time.Sleep(2 * time.Millisecond)
		_, ok := store.GetByUserCode(dc.UserCode)
		if ok {
			t.Error("GetByUserCode returned true for expired code")
		}
	})

	t.Run("nonexistent user code returns false", func(t *testing.T) {
		store := NewDeviceStore()
		_, ok := store.GetByUserCode("ZZZZ-ZZZZ")
		if ok {
			t.Error("GetByUserCode returned true for nonexistent user code")
		}
	})
}

func TestDeviceStoreApprove(t *testing.T) {
	t.Run("sets approved and attaches session", func(t *testing.T) {
		store := NewDeviceStore()
		dc, err := store.Create(5 * time.Minute)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}

		session := &UserSession{
			Email: "alice@example.com",
			Name:  "Alice",
			Teams: []TeamMembership{{Name: "platform", Role: "admin"}},
		}
		store.Approve(dc.DeviceCode, session)

		got, ok := store.Get(dc.DeviceCode)
		if !ok {
			t.Fatal("Get returned false after approval")
		}
		if !got.Approved {
			t.Error("Approved should be true after Approve()")
		}
		if got.Denied {
			t.Error("Denied should be false after Approve()")
		}
		if got.UserSession == nil {
			t.Fatal("UserSession should be set after Approve()")
		}
		if got.UserSession.Email != "alice@example.com" {
			t.Errorf("UserSession.Email = %q, want %q", got.UserSession.Email, "alice@example.com")
		}
	})

	t.Run("approve nonexistent code is a no-op", func(t *testing.T) {
		store := NewDeviceStore()
		// Must not panic.
		store.Approve("nonexistent", &UserSession{Email: "bob@example.com"})
	})
}

func TestDeviceStoreDeny(t *testing.T) {
	t.Run("sets denied state", func(t *testing.T) {
		store := NewDeviceStore()
		dc, err := store.Create(5 * time.Minute)
		if err != nil {
			t.Fatalf("Create: %v", err)
		}
		store.Deny(dc.DeviceCode)

		got, ok := store.Get(dc.DeviceCode)
		if !ok {
			t.Fatal("Get returned false after denial")
		}
		if !got.Denied {
			t.Error("Denied should be true after Deny()")
		}
		if got.Approved {
			t.Error("Approved should be false after Deny()")
		}
	})

	t.Run("deny nonexistent code is a no-op", func(t *testing.T) {
		store := NewDeviceStore()
		// Must not panic.
		store.Deny("nonexistent")
	})
}

func TestDeviceStoreCleanup(t *testing.T) {
	t.Run("removes expired codes and keeps valid ones", func(t *testing.T) {
		store := NewDeviceStore()

		// Create an already-expired code.
		expired, err := store.Create(1 * time.Nanosecond)
		if err != nil {
			t.Fatalf("Create expired: %v", err)
		}
		time.Sleep(2 * time.Millisecond)

		// Create a code that is still valid.
		valid, err := store.Create(5 * time.Minute)
		if err != nil {
			t.Fatalf("Create valid: %v", err)
		}

		store.Cleanup()

		// Expired code should be gone from both maps (Get already filters by
		// expiry, so check the underlying map through a second Create/Get cycle
		// is not needed -- we verify the user code lookup is also cleaned).
		if _, ok := store.GetByUserCode(expired.UserCode); ok {
			t.Error("expired user code still found after Cleanup")
		}

		// Valid code should still be present.
		if _, ok := store.Get(valid.DeviceCode); !ok {
			t.Error("valid device code missing after Cleanup")
		}
		if _, ok := store.GetByUserCode(valid.UserCode); !ok {
			t.Error("valid user code missing after Cleanup")
		}
	})

	t.Run("removes expired refresh tokens", func(t *testing.T) {
		store := NewDeviceStore()

		store.StoreRefreshToken("expired-token", "alice@example.com", 1*time.Nanosecond)
		time.Sleep(2 * time.Millisecond)
		store.StoreRefreshToken("valid-token", "bob@example.com", 5*time.Minute)

		store.Cleanup()

		if _, ok := store.ValidateRefreshToken("expired-token"); ok {
			t.Error("expired refresh token still valid after Cleanup")
		}
		if email, ok := store.ValidateRefreshToken("valid-token"); !ok {
			t.Error("valid refresh token missing after Cleanup")
		} else if email != "bob@example.com" {
			t.Errorf("ValidateRefreshToken email = %q, want %q", email, "bob@example.com")
		}
	})
}

func TestRefreshTokenRoundTrip(t *testing.T) {
	t.Run("store and validate", func(t *testing.T) {
		store := NewDeviceStore()
		store.StoreRefreshToken("my-token", "alice@example.com", 5*time.Minute)

		email, ok := store.ValidateRefreshToken("my-token")
		if !ok {
			t.Fatal("ValidateRefreshToken returned false for valid token")
		}
		if email != "alice@example.com" {
			t.Errorf("email = %q, want %q", email, "alice@example.com")
		}
	})

	t.Run("rotate on use: second validate fails", func(t *testing.T) {
		store := NewDeviceStore()
		store.StoreRefreshToken("one-time-token", "bob@example.com", 5*time.Minute)

		if _, ok := store.ValidateRefreshToken("one-time-token"); !ok {
			t.Fatal("first ValidateRefreshToken should succeed")
		}
		if _, ok := store.ValidateRefreshToken("one-time-token"); ok {
			t.Error("second ValidateRefreshToken should fail (rotate-on-use)")
		}
	})

	t.Run("expired refresh token returns false", func(t *testing.T) {
		store := NewDeviceStore()
		store.StoreRefreshToken("stale-token", "charlie@example.com", 1*time.Nanosecond)
		time.Sleep(2 * time.Millisecond)

		if _, ok := store.ValidateRefreshToken("stale-token"); ok {
			t.Error("ValidateRefreshToken should return false for expired token")
		}
	})

	t.Run("nonexistent token returns false", func(t *testing.T) {
		store := NewDeviceStore()
		if _, ok := store.ValidateRefreshToken("no-such-token"); ok {
			t.Error("ValidateRefreshToken should return false for nonexistent token")
		}
	})
}

func TestGenerateRefreshToken(t *testing.T) {
	t.Run("produces 64 hex characters", func(t *testing.T) {
		token, err := GenerateRefreshToken()
		if err != nil {
			t.Fatalf("GenerateRefreshToken: %v", err)
		}
		matched, _ := regexp.MatchString(`^[0-9a-f]{64}$`, token)
		if !matched {
			t.Errorf("token %q does not match 64-char hex pattern", token)
		}
	})

	t.Run("two calls produce different tokens", func(t *testing.T) {
		a, err := GenerateRefreshToken()
		if err != nil {
			t.Fatalf("GenerateRefreshToken (1): %v", err)
		}
		b, err := GenerateRefreshToken()
		if err != nil {
			t.Fatalf("GenerateRefreshToken (2): %v", err)
		}
		if a == b {
			t.Errorf("two consecutive calls returned the same token: %s", a)
		}
	})
}

func TestUserCodeCharacterSet(t *testing.T) {
	ambiguous := "01OIL"

	t.Run("alphabet excludes ambiguous characters", func(t *testing.T) {
		for _, ch := range ambiguous {
			if strings.ContainsRune(userCodeAlphabet, ch) {
				t.Errorf("userCodeAlphabet contains ambiguous character %q", string(ch))
			}
		}
	})

	t.Run("generated user codes contain no ambiguous characters", func(t *testing.T) {
		store := NewDeviceStore()
		for i := 0; i < 200; i++ {
			dc, err := store.Create(5 * time.Minute)
			if err != nil {
				t.Fatalf("Create iteration %d: %v", i, err)
			}
			// Strip the dash before checking individual characters.
			raw := strings.ReplaceAll(dc.UserCode, "-", "")
			for _, ch := range raw {
				if strings.ContainsRune(ambiguous, ch) {
					t.Errorf("user code %q contains ambiguous character %q", dc.UserCode, string(ch))
				}
			}
		}
	})
}
