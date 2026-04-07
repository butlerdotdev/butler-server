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

// Event represents a single audit log entry.
type Event struct {
	Timestamp         time.Time `json:"timestamp"`
	User              string    `json:"user"`
	Action            string    `json:"action"`
	ResourceType      string    `json:"resourceType,omitempty"`
	ResourceName      string    `json:"resourceName,omitempty"`
	ResourceNamespace string    `json:"resourceNamespace,omitempty"`
	TeamRef           string    `json:"teamRef,omitempty"`
	HTTPMethod        string    `json:"httpMethod,omitempty"`
	Path              string    `json:"path,omitempty"`
	StatusCode        int       `json:"statusCode,omitempty"`
	Success           bool      `json:"success"`
	RequestSummary    string    `json:"requestSummary,omitempty"`
	ErrorMessage      string    `json:"errorMessage,omitempty"`
	SourceIP          string    `json:"sourceIP,omitempty"`
	Provider          string    `json:"provider,omitempty"`
}

// QueryOpts defines filter options for querying the audit buffer.
type QueryOpts struct {
	User         string
	Action       string
	ResourceType string
	Success      *bool
	From         time.Time
	To           time.Time
	Offset       int
	Limit        int
	TeamRef      string
}
