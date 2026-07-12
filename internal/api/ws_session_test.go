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
}

func (f fakeResolver) ResolveTeams(context.Context, string, []string) ([]auth.TeamMembership, error) {
	return f.teams, f.err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// The terminal gate rests on TeamInfo carrying the role. This proves the
// resolver copies name and role from the resolved membership onto SessionInfo,
// so the extracted function survives a refactor of the router closure.
func TestResolveWSSession_PopulatesRolesFromResolver(t *testing.T) {
	v := fakeValidator{session: &auth.UserSession{Email: "op@co.com"}}
	r := fakeResolver{teams: []auth.TeamMembership{
		{Name: "team-a", Role: "operator"},
		{Name: "team-b", Role: "viewer"},
	}}
	info, err := resolveWSSession(context.Background(), "tok", v, r, discardLogger())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
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
	_, err := resolveWSSession(context.Background(), "tok", v, fakeResolver{}, discardLogger())
	if err == nil {
		t.Fatal("expected the validate error to propagate")
	}
}

// A team-scoped user whose teams fail to resolve gets no teams, which the
// downstream gate treats as refused. The session build itself must not fail,
// so platform admins can still authorize via PlatformRole.
func TestResolveWSSession_ResolveError_FailsClosedNoTeams(t *testing.T) {
	v := fakeValidator{session: &auth.UserSession{Email: "op@co.com"}}
	r := fakeResolver{err: errors.New("apiserver unavailable")}
	info, err := resolveWSSession(context.Background(), "tok", v, r, discardLogger())
	if err != nil {
		t.Fatalf("resolver error must not fail the session build: %v", err)
	}
	if len(info.Teams) != 0 {
		t.Errorf("teams = %d, want 0 on resolve error", len(info.Teams))
	}
}
