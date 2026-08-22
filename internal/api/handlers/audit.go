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
	"net/http"
	"strconv"
	"time"

	"github.com/butlerdotdev/butler-server/internal/audit"
	"github.com/butlerdotdev/butler-server/internal/auth"
	"github.com/go-chi/chi/v5"
)

// AuditHandler handles audit log query endpoints.
type AuditHandler struct {
	emitter *audit.Emitter
}

// NewAuditHandler creates a new audit handler.
func NewAuditHandler(emitter *audit.Emitter) *AuditHandler {
	return &AuditHandler{emitter: emitter}
}

// ListAll returns audit entries across all teams. Platform viewer or above.
func (h *AuditHandler) ListAll(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	if user == nil || !user.IsPlatformViewerOrAbove() {
		writeError(w, http.StatusForbidden, "platform viewer or admin access required")
		return
	}

	opts := parseAuditQuery(r)
	entries, total := h.emitter.Buffer().Query(opts)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"offset":  opts.Offset,
		"limit":   opts.Limit,
	})
}

// ListTeam returns audit entries for a specific team. Team admin only.
func (h *AuditHandler) ListTeam(w http.ResponseWriter, r *http.Request) {
	user := auth.UserFromContext(r.Context())
	teamName := chi.URLParam(r, "name")

	if user == nil {
		writeError(w, http.StatusForbidden, "authentication required")
		return
	}

	if !user.IsPlatformAdmin && !user.IsAdminOfTeam(teamName) {
		writeError(w, http.StatusForbidden, "team admin access required")
		return
	}

	opts := parseAuditQuery(r)
	opts.TeamRef = teamName

	entries, total := h.emitter.Buffer().Query(opts)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"offset":  opts.Offset,
		"limit":   opts.Limit,
	})
}

func parseAuditQuery(r *http.Request) audit.QueryOpts {
	q := r.URL.Query()

	limit := 50
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 && l <= 200 {
		limit = l
	}

	offset := 0
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	opts := audit.QueryOpts{
		User:         q.Get("user"),
		Action:       q.Get("action"),
		ResourceType: q.Get("resourceType"),
		Offset:       offset,
		Limit:        limit,
	}

	if s := q.Get("success"); s == "true" {
		v := true
		opts.Success = &v
	} else if s == "false" {
		v := false
		opts.Success = &v
	}

	if from := q.Get("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			opts.From = t
		} else if t, err := time.Parse("2006-01-02", from); err == nil {
			opts.From = t
		}
	}

	if to := q.Get("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			opts.To = t
		} else if t, err := time.Parse("2006-01-02", to); err == nil {
			opts.To = t.Add(24*time.Hour - time.Nanosecond) // end of day
		}
	}

	return opts
}
