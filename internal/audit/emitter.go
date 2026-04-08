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
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	ws "github.com/butlerdotdev/butler-server/internal/websocket"
)

// Emitter coordinates audit event emission to all configured targets:
// structured logs (always), in-memory ring buffer (always), and webhook (optional).
// NotificationBroadcaster is the interface for sending real-time notifications.
type NotificationBroadcaster interface {
	BroadcastNotification(ws.NotificationPayload)
}

type Emitter struct {
	buffer     *RingBuffer
	logger     *slog.Logger
	webhookURL string
	httpClient *http.Client
	enabled    bool
	hub        NotificationBroadcaster
}

// NewEmitter creates a new audit emitter.
func NewEmitter(bufferSize int, webhookURL string, logger *slog.Logger) *Emitter {
	return &Emitter{
		buffer:     NewRingBuffer(bufferSize),
		logger:     logger,
		webhookURL: webhookURL,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		enabled:    true,
	}
}

// SetEnabled controls whether audit events are recorded.
func (e *Emitter) SetEnabled(enabled bool) {
	e.enabled = enabled
}

// SetWebhookURL updates the webhook URL at runtime.
func (e *Emitter) SetWebhookURL(url string) {
	e.webhookURL = url
}

// SetHub sets the notification broadcaster for real-time push.
func (e *Emitter) SetHub(hub NotificationBroadcaster) {
	e.hub = hub
}

// Emit records an audit event to all configured targets.
func (e *Emitter) Emit(event Event) {
	if !e.enabled {
		return
	}
	// 1. Structured log — always, synchronous
	e.logger.Info("audit",
		slog.String("user", event.User),
		slog.String("action", event.Action),
		slog.String("resourceType", event.ResourceType),
		slog.String("resourceName", event.ResourceName),
		slog.String("resourceNamespace", event.ResourceNamespace),
		slog.String("teamRef", event.TeamRef),
		slog.String("httpMethod", event.HTTPMethod),
		slog.String("path", event.Path),
		slog.Int("statusCode", event.StatusCode),
		slog.Bool("success", event.Success),
		slog.String("sourceIP", event.SourceIP),
	)

	// 2. Ring buffer — always, synchronous (fast, mutex-protected)
	e.buffer.Push(event)

	// 3. Webhook — optional, async (fire-and-forget)
	if e.webhookURL != "" {
		go e.sendWebhook(event)
	}

	// 4. Real-time notification — bridge audit events to WebSocket notifications
	if e.hub != nil {
		if n := shouldNotify(event); n != nil {
			e.hub.BroadcastNotification(*n)
		}
	}
}

// Buffer returns the ring buffer for query access.
func (e *Emitter) Buffer() *RingBuffer {
	return e.buffer
}

func (e *Emitter) sendWebhook(event Event) {
	body, err := json.Marshal(event)
	if err != nil {
		e.logger.Error("Failed to marshal audit event for webhook", "error", err)
		return
	}

	resp, err := e.httpClient.Post(e.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		e.logger.Error("Failed to send audit webhook", "error", err, "url", e.webhookURL)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		e.logger.Warn("Audit webhook returned non-success status",
			slog.Int("statusCode", resp.StatusCode),
			slog.String("url", e.webhookURL),
		)
	}
}
