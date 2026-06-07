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
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http/httptest"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// fakeGitConfigDeleter records calls and returns canned errors, standing in
// for *k8s.Client (which is not fake-injectable). It implements
// gitConfigDeleter.
type fakeGitConfigDeleter struct {
	configMapErr error
	secretErr    error
	cmCalled     bool
	secretCalled bool
}

func (f *fakeGitConfigDeleter) DeleteConfigMap(_ context.Context, _, _ string) error {
	f.cmCalled = true
	return f.configMapErr
}

func (f *fakeGitConfigDeleter) DeleteSecret(_ context.Context, _, _ string) error {
	f.secretCalled = true
	return f.secretErr
}

func notFound(resource, name string) error {
	return apierrors.NewNotFound(schema.GroupResource{Resource: resource}, name)
}

func TestClearGitProviderConfig(t *testing.T) {
	tests := []struct {
		name        string
		cmErr       error
		secretErr   error
		wantDeleted bool
		wantErr     bool
	}{
		{name: "both present -> deleted", wantDeleted: true},
		{
			name:        "both missing -> nothing deleted, no error (idempotent)",
			cmErr:       notFound("configmaps", gitOpsConfigMapName),
			secretErr:   notFound("secrets", gitOpsSecretName),
			wantDeleted: false,
		},
		{
			name:        "configmap missing, secret present -> deleted",
			cmErr:       notFound("configmaps", gitOpsConfigMapName),
			wantDeleted: true,
		},
		{
			name:        "configmap real error -> error, but secret delete still attempted",
			cmErr:       errors.New("apiserver unreachable"),
			wantDeleted: true, // secret delete succeeds (best-effort)
			wantErr:     true,
		},
		{
			name:      "secret real error -> error propagated",
			secretErr: errors.New("forbidden"),
			wantErr:   true,
		},
		{
			name:      "both real errors -> aggregated, nothing deleted",
			cmErr:     errors.New("apiserver unreachable"),
			secretErr: errors.New("forbidden"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &fakeGitConfigDeleter{configMapErr: tt.cmErr, secretErr: tt.secretErr}
			deleted, err := clearGitProviderConfig(context.Background(), d, "butler-system")

			// Best-effort: both deletes are always attempted, even when the
			// first fails. This is the P1.2 guarantee (a ConfigMap failure
			// must not strand the credential Secret).
			if !d.cmCalled {
				t.Errorf("DeleteConfigMap was not called")
			}
			if !d.secretCalled {
				t.Errorf("DeleteSecret was not called (best-effort cleanup requires attempting both)")
			}

			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if deleted != tt.wantDeleted {
				t.Fatalf("deleted = %v, want %v", deleted, tt.wantDeleted)
			}
		})
	}
}

// TestClearConfigResponse covers the HTTP status mapping (204/404/500) via the
// fake deleter, without a fake Kubernetes clientset.
func TestClearConfigResponse(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name       string
		cmErr      error
		secretErr  error
		wantStatus int
	}{
		{name: "deleted -> 204", wantStatus: 204},
		{
			name:       "nothing configured -> 404",
			cmErr:      notFound("configmaps", gitOpsConfigMapName),
			secretErr:  notFound("secrets", gitOpsSecretName),
			wantStatus: 404,
		},
		{
			name:       "k8s error -> 500",
			cmErr:      errors.New("apiserver unreachable"),
			secretErr:  errors.New("apiserver unreachable"),
			wantStatus: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := &fakeGitConfigDeleter{configMapErr: tt.cmErr, secretErr: tt.secretErr}
			rec := httptest.NewRecorder()
			clearConfigResponse(rec, context.Background(), d, "butler-system", logger)
			if rec.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d (body: %s)", rec.Code, tt.wantStatus, rec.Body.String())
			}
		})
	}
}
