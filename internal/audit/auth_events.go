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

package audit

import "time"

// RecordLogin records a successful login event.
func RecordLogin(emitter *Emitter, email, provider, sourceIP string) {
	if emitter == nil {
		return
	}
	emitter.Emit(Event{
		Timestamp:  time.Now().UTC(),
		User:       email,
		Action:     "login",
		Success:    true,
		StatusCode: 200,
		Provider:   provider,
		SourceIP:   sourceIP,
	})
}

// RecordLogout records a logout event.
func RecordLogout(emitter *Emitter, email, sourceIP string) {
	if emitter == nil {
		return
	}
	emitter.Emit(Event{
		Timestamp:  time.Now().UTC(),
		User:       email,
		Action:     "logout",
		Success:    true,
		StatusCode: 200,
		SourceIP:   sourceIP,
	})
}

// RecordGroupSync records that a user's IdP groups were written to
// the User CRD status.lastSeenGroups field.
func RecordGroupSync(emitter *Emitter, email string, groupCount int, sourceIP string) {
	if emitter == nil {
		return
	}
	emitter.Emit(Event{
		Timestamp:    time.Now().UTC(),
		User:         email,
		Action:       "group_sync",
		ResourceType: "user",
		Success:      true,
		StatusCode:   200,
		SourceIP:     sourceIP,
	})
}

// RecordLoginFailed records a failed login attempt.
func RecordLoginFailed(emitter *Emitter, email, provider, sourceIP, reason string) {
	if emitter == nil {
		return
	}
	emitter.Emit(Event{
		Timestamp:    time.Now().UTC(),
		User:         email,
		Action:       "login_failed",
		Success:      false,
		StatusCode:   401,
		Provider:     provider,
		SourceIP:     sourceIP,
		ErrorMessage: reason,
	})
}
