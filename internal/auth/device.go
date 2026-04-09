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
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"
)

// userCodeAlphabet excludes ambiguous characters: 0/O, 1/I/L.
const userCodeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ"

// DeviceCode represents a pending device authorization request.
type DeviceCode struct {
	DeviceCode  string
	UserCode    string
	ExpiresAt   time.Time
	Interval    int // polling interval in seconds
	Approved    bool
	Denied      bool
	UserSession *UserSession // set when approved
}

// RefreshEntry maps a hashed refresh token to the user email it was issued for.
type RefreshEntry struct {
	Email     string
	ExpiresAt time.Time
}

// DeviceStore manages pending device authorization codes and refresh tokens.
type DeviceStore struct {
	mu         sync.RWMutex
	codes      map[string]*DeviceCode // keyed by device_code
	byUserCode map[string]string      // user_code -> device_code lookup

	refreshMu     sync.RWMutex
	refreshTokens map[string]*RefreshEntry // keyed by sha256(token)
}

// NewDeviceStore creates a new device code store.
func NewDeviceStore() *DeviceStore {
	return &DeviceStore{
		codes:         make(map[string]*DeviceCode),
		byUserCode:    make(map[string]string),
		refreshTokens: make(map[string]*RefreshEntry),
	}
}

// Create generates a new device code and user code pair, stores them with the
// given TTL, and returns the DeviceCode.
func (s *DeviceStore) Create(expiry time.Duration) (*DeviceCode, error) {
	deviceCode, err := generateRandomHex(32)
	if err != nil {
		return nil, err
	}

	userCode, err := generateUserCode()
	if err != nil {
		return nil, err
	}

	dc := &DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   userCode,
		ExpiresAt:  time.Now().Add(expiry),
		Interval:   5,
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.codes[deviceCode] = dc
	s.byUserCode[userCode] = deviceCode

	return dc, nil
}

// Get returns the device code entry if it exists and has not expired.
func (s *DeviceStore) Get(deviceCode string) (*DeviceCode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	dc, ok := s.codes[deviceCode]
	if !ok {
		return nil, false
	}
	if time.Now().After(dc.ExpiresAt) {
		return nil, false
	}
	return dc, true
}

// GetByUserCode looks up a device code entry by the human-readable user code.
func (s *DeviceStore) GetByUserCode(userCode string) (*DeviceCode, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	deviceCode, ok := s.byUserCode[userCode]
	if !ok {
		return nil, false
	}
	dc, ok := s.codes[deviceCode]
	if !ok {
		return nil, false
	}
	if time.Now().After(dc.ExpiresAt) {
		return nil, false
	}
	return dc, true
}

// Approve marks a device code as approved and attaches the authenticated user session.
func (s *DeviceStore) Approve(deviceCode string, session *UserSession) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if dc, ok := s.codes[deviceCode]; ok {
		dc.Approved = true
		dc.UserSession = session
	}
}

// Deny marks a device code as denied by the user.
func (s *DeviceStore) Deny(deviceCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if dc, ok := s.codes[deviceCode]; ok {
		dc.Denied = true
	}
}

// Delete removes a device code after it has been consumed.
func (s *DeviceStore) Delete(deviceCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if dc, ok := s.codes[deviceCode]; ok {
		delete(s.byUserCode, dc.UserCode)
		delete(s.codes, deviceCode)
	}
}

// Cleanup removes all expired device codes.
func (s *DeviceStore) Cleanup() {
	s.mu.Lock()
	now := time.Now()
	for code, dc := range s.codes {
		if now.After(dc.ExpiresAt) {
			delete(s.byUserCode, dc.UserCode)
			delete(s.codes, code)
		}
	}
	s.mu.Unlock()

	s.refreshMu.Lock()
	for hash, entry := range s.refreshTokens {
		if now.After(entry.ExpiresAt) {
			delete(s.refreshTokens, hash)
		}
	}
	s.refreshMu.Unlock()
}

// StartCleanup runs a background goroutine that periodically removes expired entries.
// It stops when the provided context is cancelled.
func (s *DeviceStore) StartCleanup(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				s.Cleanup()
			}
		}
	}()
}

// StoreRefreshToken stores a refresh token mapping to the given email.
// The token is stored as its SHA-256 hash.
func (s *DeviceStore) StoreRefreshToken(token, email string, expiry time.Duration) {
	hash := hashRefreshToken(token)
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	s.refreshTokens[hash] = &RefreshEntry{
		Email:     email,
		ExpiresAt: time.Now().Add(expiry),
	}
}

// ValidateRefreshToken checks whether a refresh token is valid and returns
// the associated email. The token is consumed (deleted) on success.
func (s *DeviceStore) ValidateRefreshToken(token string) (string, bool) {
	hash := hashRefreshToken(token)
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()

	entry, ok := s.refreshTokens[hash]
	if !ok {
		return "", false
	}
	// Consume the token (rotate-on-use)
	delete(s.refreshTokens, hash)

	if time.Now().After(entry.ExpiresAt) {
		return "", false
	}
	return entry.Email, true
}

// GenerateRefreshToken produces a 32-byte cryptographically random token,
// returned as a 64-character hex string.
func GenerateRefreshToken() (string, error) {
	return generateRandomHex(32)
}

// generateRandomHex produces n random bytes and returns them hex-encoded.
func generateRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// generateUserCode produces an 8-character code in XXXX-XXXX format using
// only unambiguous uppercase letters.
func generateUserCode() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	code := make([]byte, 8)
	for i := range code {
		code[i] = userCodeAlphabet[int(b[i])%len(userCodeAlphabet)]
	}
	return string(code[:4]) + "-" + string(code[4:]), nil
}

// hashRefreshToken returns the SHA-256 hex digest of a refresh token.
func hashRefreshToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
