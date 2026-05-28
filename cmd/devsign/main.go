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

// Package main is the entry point for devsign — a small helper that mints
// butler-server session JWTs for end-to-end testing of the CLI device flow.
//
// This is dev-time test infrastructure. The signing secret must match the
// BUTLER_JWT_SECRET that a running butler-server instance is configured with,
// so the only realistic use is local dev mode against a butler-server you
// started yourself. Do not deploy.
//
// Usage:
//
//	devsign -email alice@example.com -platform-admin -secret $BUTLER_JWT_SECRET
//
// Prints the JWT to stdout on success. Exits non-zero on missing flags or
// signing errors with a message on stderr.
package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/butlerdotdev/butler-server/internal/auth"
)

func main() {
	var (
		secret        string
		email         string
		name          string
		platformAdmin bool
		expiry        time.Duration
	)

	flag.StringVar(&secret, "secret", os.Getenv("BUTLER_JWT_SECRET"), "JWT signing secret (defaults to BUTLER_JWT_SECRET env)")
	flag.StringVar(&email, "email", "", "user email to embed in the session")
	flag.StringVar(&name, "name", "", "user display name (optional)")
	flag.BoolVar(&platformAdmin, "platform-admin", false, "set IsPlatformAdmin on the session")
	flag.DurationVar(&expiry, "expiry", 24*time.Hour, "session JWT lifetime")
	flag.Parse()

	if secret == "" {
		fmt.Fprintln(os.Stderr, "devsign: -secret is required (or set BUTLER_JWT_SECRET)")
		os.Exit(2)
	}
	if email == "" {
		fmt.Fprintln(os.Stderr, "devsign: -email is required")
		os.Exit(2)
	}

	svc := auth.NewSessionService(secret, expiry)
	user := &auth.UserSession{
		Subject:         "devsign:" + email,
		Email:           email,
		Name:            name,
		IsPlatformAdmin: platformAdmin,
	}

	token, err := svc.CreateSession(user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "devsign: create session: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(token)
}
