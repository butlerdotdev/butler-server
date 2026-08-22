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

package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/butlerdotdev/butler-server/internal/auth"
)

type fakeValidator struct {
	session *auth.UserSession
	err     error
}

func (f fakeValidator) ValidateSession(string) (*auth.UserSession, error) {
	return f.session, f.err
}

type fakeResolver struct {
	teams []auth.TeamMembership
	err   error

	gotEmail  string
	gotGroups []string
}

func (f *fakeResolver) ResolveTeams(_ context.Context, email string, groups []string) ([]auth.TeamMembership, error) {
	f.gotEmail = email
	f.gotGroups = groups
	return f.teams, f.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The terminal gate rests on TeamInfo carrying the role. This proves the
// resolver copies name and role from the resolved membership onto SessionInfo,
// so the extracted function survives a refactor of the router closure.
func TestResolveWSSession_PopulatesRolesFromResolver(t *testing.T) {
	v := fakeValidator{session: &auth.UserSession{Email: "op@co.com", Groups: []string{"eng"}}}
	r := &fakeResolver{teams: []auth.TeamMembership{
		{Name: "team-a", Role: "operator"},
		{Name: "team-b", Role: "viewer"},
	}}
	info, err := resolveWSSession(context.Background(), "tok", wsSessionDeps{validator: v, resolver: r, logger: discardLogger()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.gotEmail != "op@co.com" || len(r.gotGroups) != 1 || r.gotGroups[0] != "eng" {
		t.Errorf("resolver got (%q, %v), want (op@co.com, [eng])", r.gotEmail, r.gotGroups)
	}
	if len(info.Teams) != 2 {
		t.Fatalf("teams = %d, want 2", len(info.Teams))
	}
	if info.Teams[0].Name != "team-a" || info.Teams[0].Role != "operator" {
		t.Errorf("team[0] = %+v, want {team-a operator}", info.Teams[0])
	}
	if info.Teams[1].Name != "team-b" || info.Teams[1].Role != "viewer" {
		t.Errorf("team[1] = %+v, want {team-b viewer}", info.Teams[1])
	}
}

func TestResolveWSSession_ValidateError_Propagates(t *testing.T) {
	v := fakeValidator{err: errors.New("bad token")}
	_, err := resolveWSSession(context.Background(), "tok", wsSessionDeps{validator: v, resolver: &fakeResolver{}, logger: discardLogger()})
	if err == nil {
		t.Fatal("expected the validate error to propagate")
	}
}

// A team-scoped user whose teams fail to resolve gets no teams, which the
// downstream gate treats as refused. The session build itself must not fail,
// so platform admins can still authorize via PlatformRole.
func TestResolveWSSession_ResolveError_FailsClosedNoTeams(t *testing.T) {
	v := fakeValidator{session: &auth.UserSession{Email: "op@co.com"}}
	r := &fakeResolver{err: errors.New("apiserver unavailable")}
	info, err := resolveWSSession(context.Background(), "tok", wsSessionDeps{validator: v, resolver: r, logger: discardLogger()})
	if err != nil {
		t.Fatalf("resolver error must not fail the session build: %v", err)
	}
	if len(info.Teams) != 0 {
		t.Errorf("teams = %d, want 0 on resolve error", len(info.Teams))
	}
}

type fakePortal struct {
	session *auth.UserSession
	claimed bool
	err     error
}

func (f fakePortal) MaybeVerify(context.Context, string) (*auth.UserSession, bool, error) {
	return f.session, f.claimed, f.err
}

type fakeUsers struct {
	info *auth.UserInfo
	err  error
}

func (f fakeUsers) GetUserByEmail(context.Context, string) (*auth.UserInfo, error) {
	return f.info, f.err
}

// A portal proof authenticates the end user without ever consulting the
// HMAC validator, so the relay's service-account cookie is not needed.
func TestResolveWSSession_PortalProof_BypassesHMAC(t *testing.T) {
	v := fakeValidator{err: errors.New("validator must not be called")}
	p := fakePortal{session: &auth.UserSession{Email: "dev@co.com", PlatformRole: "viewer"}, claimed: true}
	info, err := resolveWSSession(context.Background(), "proof", wsSessionDeps{validator: v, resolver: &fakeResolver{}, portal: p, logger: discardLogger()})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if info.Email != "dev@co.com" || info.PlatformRole != "viewer" {
		t.Fatalf("session = %+v, want portal identity", info)
	}
}

// A token that claims the portal shape but fails verification is rejected
// outright; it must not get a second chance as an HMAC session.
func TestResolveWSSession_PortalProofInvalid_Rejected(t *testing.T) {
	v := fakeValidator{session: &auth.UserSession{Email: "admin@butler.local", PlatformRole: "admin"}}
	p := fakePortal{claimed: true, err: errors.New("bad signature")}
	if _, err := resolveWSSession(context.Background(), "proof", wsSessionDeps{validator: v, resolver: &fakeResolver{}, portal: p, logger: discardLogger()}); err == nil {
		t.Fatal("invalid portal proof must be rejected")
	}
	p = fakePortal{claimed: true, session: nil}
	if _, err := resolveWSSession(context.Background(), "proof", wsSessionDeps{validator: v, resolver: &fakeResolver{}, portal: p, logger: discardLogger()}); err == nil {
		t.Fatal("claimed portal proof without a session must be rejected")
	}
}

// Non-portal tokens fall through to the HMAC validator unchanged.
func TestResolveWSSession_NonPortalToken_FallsThrough(t *testing.T) {
	v := fakeValidator{session: &auth.UserSession{Email: "op@co.com"}}
	p := fakePortal{claimed: false}
	info, err := resolveWSSession(context.Background(), "tok", wsSessionDeps{validator: v, resolver: &fakeResolver{}, portal: p, logger: discardLogger()})
	if err != nil || info.Email != "op@co.com" {
		t.Fatalf("fall-through failed: info=%+v err=%v", info, err)
	}
}

func TestResolveWSSession_DisabledUser_Rejected(t *testing.T) {
	v := fakeValidator{session: &auth.UserSession{Email: "gone@co.com"}}
	u := fakeUsers{info: &auth.UserInfo{Disabled: true}}
	if _, err := resolveWSSession(context.Background(), "tok", wsSessionDeps{validator: v, resolver: &fakeResolver{}, users: u, logger: discardLogger()}); !errors.Is(err, errWSUserDisabled) {
		t.Fatalf("err = %v, want errWSUserDisabled", err)
	}
}

// The legacy admin has no User CRD; a lookup miss must not block the session.
func TestResolveWSSession_UserLookupMiss_Allowed(t *testing.T) {
	v := fakeValidator{session: &auth.UserSession{Email: "admin@butler.local", PlatformRole: "admin"}}
	u := fakeUsers{err: errors.New("not found")}
	if _, err := resolveWSSession(context.Background(), "tok", wsSessionDeps{validator: v, resolver: &fakeResolver{}, users: u, logger: discardLogger()}); err != nil {
		t.Fatalf("lookup miss must be tolerated: %v", err)
	}
}
