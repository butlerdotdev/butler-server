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

var sensitiveKeys = map[string]bool{
	"password":       true,
	"token":          true,
	"secret":         true,
	"kubeconfig":     true,
	"clientsecret":   true,
	"apikey":         true,
	"privatekey":     true,
	"accesskey":      true,
	"secretaccesskey": true,
	"serviceaccount": true,
}

const maxSummaryLength = 1024

// ScrubRequestBody takes raw JSON bytes, redacts sensitive fields,
// and returns a truncated string summary.
func ScrubRequestBody(body []byte) string {
	if len(body) == 0 {
		return ""
	}

	var data map[string]interface{}
	if err := json.Unmarshal(body, &data); err != nil {
		// Not valid JSON — truncate raw body
		s := string(body)
		if len(s) > maxSummaryLength {
			return s[:maxSummaryLength]
		}
		return s
	}

	scrubMap(data)

	result, err := json.Marshal(data)
	if err != nil {
		return ""
	}

	s := string(result)
	if len(s) > maxSummaryLength {
		return s[:maxSummaryLength]
	}
	return s
}

func scrubMap(m map[string]interface{}) {
	for key, val := range m {
		if sensitiveKeys[strings.ToLower(key)] {
			m[key] = "[REDACTED]"
			continue
		}
		switch v := val.(type) {
		case map[string]interface{}:
			scrubMap(v)
		case []interface{}:
			for _, item := range v {
				if nested, ok := item.(map[string]interface{}); ok {
					scrubMap(nested)
				}
			}
		}
	}
}
