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
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// writeWebhookError detects apiserver webhook denials and surfaces a
// structured 403 for butler-console inline rendering. These tests pin
// the detection heuristic and response shape so consumers can key on
// reason=webhook-denied.

func newWebhookForbiddenError(message, field string) error {
	status := metav1.Status{
		Status:  metav1.StatusFailure,
		Code:    http.StatusForbidden,
		Reason:  metav1.StatusReasonForbidden,
		Message: message,
		Details: &metav1.StatusDetails{
			Group: "butler.butlerlabs.dev",
			Kind:  "Team",
			Causes: []metav1.StatusCause{
				{Type: metav1.CauseTypeForbidden, Field: field, Message: message},
			},
		},
	}
	return &apierrors.StatusError{ErrStatus: status}
}

func TestWriteWebhookError_RecognizedDenial(t *testing.T) {
	w := httptest.NewRecorder()
	err := newWebhookForbiddenError(
		`admission webhook "vteam.butler.butlerlabs.dev" denied the request: spec.resourceLimits may only be modified by platform admins; user "alice@example.com" is not a platform admin`,
		"spec.resourceLimits",
	)
	if !writeWebhookError(w, err) {
		t.Fatal("expected webhook denial to be recognized")
	}
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", w.Code)
	}
	var body map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["reason"] != webhookDenialReason {
		t.Errorf("reason = %q, want %q", body["reason"], webhookDenialReason)
	}
	if body["field"] != "spec.resourceLimits" {
		t.Errorf("field = %q, want spec.resourceLimits", body["field"])
	}
	if body["message"] == "" {
		t.Error("message should carry webhook text, got empty")
	}
}

func TestWriteWebhookError_NonWebhookForbiddenFallsThrough(t *testing.T) {
	w := httptest.NewRecorder()
	// Pure RBAC denial - no "admission webhook" / "denied the request" in the message.
	err := apierrors.NewForbidden(
		schema.GroupResource{Group: "butler.butlerlabs.dev", Resource: "teams"},
		"acme",
		fmt.Errorf(`user "alice@example.com" cannot get resource "teams"`),
	)
	if writeWebhookError(w, err) {
		t.Fatal("non-webhook Forbidden should not be recognized as webhook denial")
	}
	if w.Code != http.StatusOK {
		// writeWebhookError returns false without writing; body and status are untouched.
		t.Fatalf("expected no write, got status %d", w.Code)
	}
}

func TestWriteWebhookError_NilError(t *testing.T) {
	w := httptest.NewRecorder()
	if writeWebhookError(w, nil) {
		t.Fatal("nil error should return false")
	}
}
