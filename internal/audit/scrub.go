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

import (
	"encoding/json"
	"strings"
)

// secretKeyParts are matched case-insensitively as substrings of a JSON
// key. This deliberately catches Butler's prefixed credential fields
// (harvesterKubeconfig, nutanixPassword, proxmoxTokenSecret,
// azureClientSecret, gcpServiceAccount, awsSecretAccessKey, ...), which an
// exact-key list did not, so no provider or identity-provider credential is
// retained in an audit request summary. It subsumes the old exact list.
var secretKeyParts = []string{
	"password",
	"passwd",
	"secret",
	"token",
	"kubeconfig",
	"privatekey",
	"serviceaccount",
	"credential",
	"apikey",
	"accesskey",
}

// maxScrubInput bounds the body we will parse and scrub. A body larger
// than this is summarized as omitted rather than parsed, both to bound
// work and because a truncated JSON body cannot be safely scrubbed.
const maxScrubInput = 256 * 1024

const maxSummaryLength = 1024

// redactedValue replaces any secret-bearing value. The original length
// and any prefix are not retained.
const redactedValue = "[REDACTED]"

func isSensitiveKey(key string) bool {
	k := strings.ToLower(key)
	for _, part := range secretKeyParts {
		if strings.Contains(k, part) {
			return true
		}
	}
	return false
}

// ScrubRequestBody takes a raw request body, redacts every secret-bearing
// field at any depth, and returns a bounded JSON summary. A body that is
// not JSON is never returned raw: it may be a truncated or arbitrary
// payload that still contains credentials, so it is summarized as omitted.
func ScrubRequestBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	if len(body) > maxScrubInput {
		return "[omitted: request body too large to summarize]"
	}

	var data interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		return "[omitted: request body was not JSON]"
	}

	scrubbed := scrubValue(data)

	result, err := json.Marshal(scrubbed)
	if err != nil {
		return ""
	}
	s := string(result)
	if len(s) > maxSummaryLength {
		return s[:maxSummaryLength]
	}
	return s
}

// scrubValue walks maps and arrays, redacting the value of any
// secret-bearing key and recursing into everything else. Top-level
// arrays and scalars are handled too.
func scrubValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		for key, inner := range val {
			if isSensitiveKey(key) {
				val[key] = redactedValue
				continue
			}
			val[key] = scrubValue(inner)
		}
		return val
	case []interface{}:
		for i, item := range val {
			val[i] = scrubValue(item)
		}
		return val
	default:
		return v
	}
}
