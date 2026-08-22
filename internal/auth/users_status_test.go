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

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// The User CRD declares status.inviteExpiresAt with format date-time. The
// status written after set-password must omit the invite fields entirely;
// an empty string fails CRD validation and the invite flow never completes.
func TestActiveUserStatus_OmitsInviteFields(t *testing.T) {
	now := metav1.NewTime(time.Date(2026, 8, 22, 16, 0, 0, 0, time.UTC))
	status := activeUserStatus("user-x-password", "butler-system", now)

	for _, key := range []string{"inviteExpiresAt", "inviteTokenHash"} {
		if _, present := status[key]; present {
			t.Fatalf("status must not carry %q; got %v", key, status[key])
		}
	}
	if status["phase"] != "Active" {
		t.Fatalf("phase = %v, want Active", status["phase"])
	}
	if status["passwordChangedAt"] != "2026-08-22T16:00:00Z" {
		t.Fatalf("passwordChangedAt = %v", status["passwordChangedAt"])
	}
	ref := status["passwordSecretRef"].(map[string]interface{})
	if ref["name"] != "user-x-password" || ref["namespace"] != "butler-system" || ref["key"] != "password" {
		t.Fatalf("passwordSecretRef = %v", ref)
	}
}
