/*
Copyright 2025 The Butler Authors.

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

package websocket

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/watch"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// MessageType represents WebSocket message types.
type MessageType string

const (
	MessageTypeClusterUpdate MessageType = "cluster_update"
	MessageTypeClusterDelete MessageType = "cluster_delete"
	MessageTypePing          MessageType = "ping"
	MessageTypePong          MessageType = "pong"
	MessageTypeError         MessageType = "error"
	MessageTypeNotification  MessageType = "notification"
)

// Message represents a WebSocket message.
type Message struct {
	Type    MessageType `json:"type"`
	Payload interface{} `json:"payload,omitempty"`

	// team is the owning team of a cluster_update or cluster_delete
	// message, used to route the message to clients that may see it.
	// Empty for team-less clusters and for message types that are
	// routed by other means (notifications carry their own ResourceRef).
	team string
}

// ClusterUpdatePayload is sent when a cluster is created or updated.
type ClusterUpdatePayload struct {
	Cluster interface{} `json:"cluster"`
}

// ClusterDeletePayload is sent when a cluster is deleted.
type ClusterDeletePayload struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Team      string `json:"team,omitempty"`
}

// NotificationPayload is sent for real-time notifications.
type NotificationPayload struct {
	ID          string       `json:"id"`
	Title       string       `json:"title"`
	Message     string       `json:"message"`
	Severity    string       `json:"severity"`
	Category    string       `json:"category"`
	Timestamp   time.Time    `json:"timestamp"`
	ResourceRef *ResourceRef `json:"resourceRef,omitempty"`
}

// ResourceRef identifies the resource a notification relates to.
type ResourceRef struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Team      string `json:"team,omitempty"`
}

// SessionInfo contains the user identity resolved from a WebSocket connection.
// Email is the canonical user identifier surfaced in rejection audit logs
// (ADR-013); empty for anonymous / unresolved paths.
type SessionInfo struct {
	Email           string
	IsPlatformAdmin bool
	PlatformRole    string
	Teams           []TeamInfo
}

// TeamInfo contains team membership data.
type TeamInfo struct {
	Name string
	Role string
}

// SessionResolverFunc resolves user session from an HTTP request.
type SessionResolverFunc func(r *http.Request) (*SessionInfo, error)

// Hub manages WebSocket connections and cluster watches.
type Hub struct {
	k8sClient       *k8s.Client
	log             *slog.Logger
	sessionResolver SessionResolverFunc
	webhookURL      string
	httpClient      *http.Client

	clients    map[*Client]bool
	register   chan *Client
	unregister chan *Client
	broadcast  chan Message

	mu sync.RWMutex
}

// Client represents a WebSocket client connection.
type Client struct {
	hub             *Hub
	conn            *websocket.Conn
	send            chan Message
	teams           []string
	isPlatformAdmin bool
	// seesAllClusters is true for platform admins and platform viewers;
	// both may read every TenantCluster through the REST API, so they
	// receive every cluster_update and cluster_delete too.
	seesAllClusters bool
}

// NewHub creates a new WebSocket hub.
func NewHub(k8sClient *k8s.Client, log *slog.Logger) *Hub {
	return &Hub{
		k8sClient:  k8sClient,
		log:        log,
		httpClient: &http.Client{Timeout: 5 * time.Second},
		clients:    make(map[*Client]bool),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan Message, 256),
	}
}

// SetSessionResolver sets the function used to resolve user sessions from WebSocket upgrade requests.
func (h *Hub) SetSessionResolver(resolver SessionResolverFunc) {
	h.sessionResolver = resolver
}

// SetWebhookURL sets the URL for forwarding notifications to external systems.
func (h *Hub) SetWebhookURL(url string) {
	h.webhookURL = url
}

// Run starts the hub's main loop.
func (h *Hub) Run() {
	go h.watchClusters()

	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			h.log.Debug("Client connected", "clients", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			h.log.Debug("Client disconnected", "clients", len(h.clients))

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				if !clientCanReceiveCluster(client, message) {
					continue
				}
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// BroadcastNotification sends a notification to clients that have access to the relevant team.
// Platform admins receive all notifications. Non-admins only receive notifications
// where resourceRef.team matches one of their teams. Team-less notifications
// (e.g., security events) are only sent to platform admins.
func (h *Hub) BroadcastNotification(n NotificationPayload) {
	if n.ID == "" {
		n.ID = uuid.New().String()
	}
	if n.Timestamp.IsZero() {
		n.Timestamp = time.Now()
	}

	msg := Message{Type: MessageTypeNotification, Payload: n}

	h.mu.RLock()
	for client := range h.clients {
		if !clientCanReceive(client, n) {
			continue
		}
		select {
		case client.send <- msg:
		default:
			// Client buffer full, skip
		}
	}
	h.mu.RUnlock()

	// Forward to external webhook if configured
	if h.webhookURL != "" {
		go h.sendNotificationWebhook(n)
	}
}

func (h *Hub) sendNotificationWebhook(n NotificationPayload) {
	body, err := json.Marshal(n)
	if err != nil {
		h.log.Error("Failed to marshal notification for webhook", "error", err)
		return
	}

	resp, err := h.httpClient.Post(h.webhookURL, "application/json", bytes.NewReader(body))
	if err != nil {
		h.log.Error("Failed to send notification webhook", "error", err, "url", h.webhookURL)
		return
	}
	resp.Body.Close()

	if resp.StatusCode >= 400 {
		h.log.Warn("Notification webhook returned non-success status",
			slog.Int("statusCode", resp.StatusCode),
			slog.String("url", h.webhookURL),
		)
	}
}

// clientCanReceiveCluster decides whether a cluster_update or
// cluster_delete message may be delivered to a client. It mirrors the
// REST visibility rule in ClusterHandler.checkClusterAccess: platform
// admins and viewers see every cluster, members see their own teams'
// clusters, and team-less clusters are visible only to platform roles.
// Other message types pass through unchanged.
func clientCanReceiveCluster(c *Client, m Message) bool {
	if m.Type != MessageTypeClusterUpdate && m.Type != MessageTypeClusterDelete {
		return true
	}
	if c.seesAllClusters {
		return true
	}
	if m.team == "" {
		return false
	}
	for _, team := range c.teams {
		if team == m.team {
			return true
		}
	}
	return false
}

func clientCanReceive(c *Client, n NotificationPayload) bool {
	if c.isPlatformAdmin {
		return true
	}
	if n.ResourceRef == nil || n.ResourceRef.Team == "" {
		return false
	}
	for _, team := range c.teams {
		if team == n.ResourceRef.Team {
			return true
		}
	}
	return false
}

func (h *Hub) watchClusters() {
	previousPhases := make(map[string]string)

	for {
		h.log.Info("Starting TenantCluster watch")

		watcher, err := h.k8sClient.Dynamic().Resource(k8s.TenantClusterGVR).Watch(
			context.Background(),
			metav1.ListOptions{},
		)
		if err != nil {
			h.log.Error("Failed to watch TenantClusters, retrying in 5s", "error", err)
			time.Sleep(5 * time.Second)
			continue
		}

		for event := range watcher.ResultChan() {
			switch event.Type {
			case watch.Added, watch.Modified:
				h.broadcast <- Message{
					Type:    MessageTypeClusterUpdate,
					Payload: ClusterUpdatePayload{Cluster: event.Object},
					team:    clusterTeam(event.Object),
				}

				// Detect phase transitions and emit notifications
				if obj, ok := event.Object.(*unstructured.Unstructured); ok {
					key := obj.GetNamespace() + "/" + obj.GetName()
					newPhase, _, _ := unstructured.NestedString(obj.Object, "status", "phase")
					prevPhase := previousPhases[key]

					if newPhase != "" && newPhase != prevPhase {
						previousPhases[key] = newPhase
						if n := h.clusterPhaseNotification(obj, prevPhase, newPhase); n != nil {
							h.BroadcastNotification(*n)
						}
					}
				}

			case watch.Deleted:
				if obj, ok := event.Object.(interface {
					GetName() string
					GetNamespace() string
				}); ok {
					// Clean up phase tracking
					delete(previousPhases, obj.GetNamespace()+"/"+obj.GetName())

					team := clusterTeam(event.Object)
					h.broadcast <- Message{
						Type: MessageTypeClusterDelete,
						Payload: ClusterDeletePayload{
							Name:      obj.GetName(),
							Namespace: obj.GetNamespace(),
							Team:      team,
						},
						team: team,
					}

					h.BroadcastNotification(NotificationPayload{
						Title:    fmt.Sprintf("Cluster %s deleted", obj.GetName()),
						Message:  fmt.Sprintf("Cluster in namespace %s has been deleted", obj.GetNamespace()),
						Severity: "warning",
						Category: "cluster",
						ResourceRef: &ResourceRef{
							Kind:      "TenantCluster",
							Name:      obj.GetName(),
							Namespace: obj.GetNamespace(),
						},
					})
				}

			case watch.Error:
				h.log.Error("Watch error", "object", event.Object)
			}
		}

		h.log.Info("TenantCluster watch ended, restarting")
		time.Sleep(time.Second)
	}
}

// clusterTeam returns spec.teamRef.name of a watched TenantCluster, or
// an empty string when the object is not an unstructured cluster or
// has no team reference.
func clusterTeam(obj interface{}) string {
	u, ok := obj.(*unstructured.Unstructured)
	if !ok {
		return ""
	}
	team, _, _ := unstructured.NestedString(u.Object, "spec", "teamRef", "name")
	return team
}

func (h *Hub) clusterPhaseNotification(obj *unstructured.Unstructured, oldPhase, newPhase string) *NotificationPayload {
	name := obj.GetName()
	ns := obj.GetNamespace()
	teamRef, _, _ := unstructured.NestedString(obj.Object, "spec", "teamRef", "name")

	ref := &ResourceRef{
		Kind:      "TenantCluster",
		Name:      name,
		Namespace: ns,
		Team:      teamRef,
	}

	switch newPhase {
	case "Ready":
		if oldPhase == "Provisioning" || oldPhase == "Updating" || oldPhase == "Installing" {
			return &NotificationPayload{
				Title:       fmt.Sprintf("Cluster %s is ready", name),
				Message:     "Provisioning completed successfully.",
				Severity:    "success",
				Category:    "cluster",
				ResourceRef: ref,
			}
		}
	case "Failed":
		failureMsg, _, _ := unstructured.NestedString(obj.Object, "status", "failureMessage")
		if failureMsg == "" {
			failureMsg = "Check cluster status for details."
		}
		return &NotificationPayload{
			Title:       fmt.Sprintf("Cluster %s has failed", name),
			Message:     failureMsg,
			Severity:    "error",
			Category:    "cluster",
			ResourceRef: ref,
		}
	case "Degraded":
		return &NotificationPayload{
			Title:       fmt.Sprintf("Cluster %s is degraded", name),
			Message:     "One or more components are unhealthy.",
			Severity:    "warning",
			Category:    "cluster",
			ResourceRef: ref,
		}
	}

	return nil
}

// HandleClusterWatch handles WebSocket connections for cluster updates.
// Gates the upgrade on a valid session (ADR-013). Unauthenticated upgrades
// are rejected with HTTP 401 before any broadcast starts.
func (h *Hub) HandleClusterWatch(w http.ResponseWriter, r *http.Request) {
	session := requireSession(w, r, h.sessionResolver, h.log)
	if session == nil {
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Error("Failed to upgrade WebSocket connection", "error", err)
		return
	}

	var teams []string
	for _, tm := range session.Teams {
		teams = append(teams, tm.Name)
	}

	client := &Client{
		hub:             h,
		conn:            conn,
		send:            make(chan Message, 256),
		teams:           teams,
		isPlatformAdmin: session.PlatformRole == "admin",
		seesAllClusters: session.PlatformRole == "admin" || session.PlatformRole == "viewer",
	}

	h.register <- client

	go client.writePump()
	go client.readPump()
}

func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			data, err := json.Marshal(message)
			if err != nil {
				c.hub.log.Error("Failed to marshal message", "error", err)
				continue
			}

			if err := c.conn.WriteMessage(websocket.TextMessage, data); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadLimit(512)
	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, data, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				c.hub.log.Error("WebSocket read error", "error", err)
			}
			break
		}

		var msg Message
		if err := json.Unmarshal(data, &msg); err != nil {
			continue
		}

		if msg.Type == MessageTypePing {
			c.send <- Message{Type: MessageTypePong}
		}
	}
}

// HandleTerminal handles WebSocket connections for terminal sessions into
// tenant clusters. Gates the upgrade on a valid session and team access to
// the cluster's namespace (ADR-013). Platform admins bypass the team check.
func (h *Hub) HandleTerminal(w http.ResponseWriter, r *http.Request) {
	termType := chi.URLParam(r, "type")
	namespace := chi.URLParam(r, "namespace")
	cluster := chi.URLParam(r, "cluster")
	pod := chi.URLParam(r, "pod")
	container := chi.URLParam(r, "container")

	userSession := requireSession(w, r, h.sessionResolver, h.log)
	if userSession == nil {
		return
	}

	access, role := resolveTerminalAccess(userSession, namespace)
	if access == terminalRefused {
		h.log.Warn("WebSocket upgrade rejected",
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"reason", "forbidden",
			"user", userSession.Email,
			"team", namespace,
			"detail", "team access required",
		)
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Error("Failed to upgrade terminal WebSocket", "error", err)
		return
	}

	termSession := NewTerminalSession(h.k8sClient, h.log, TerminalConfig{
		Type:      termType,
		Namespace: namespace,
		Cluster:   cluster,
		Pod:       pod,
		Container: container,
		ReadOnly:  access != terminalWrite,
		UserEmail: userSession.Email,
		Role:      role,
		Team:      namespace,
	})

	termSession.Run(conn)
}

// HandleManagementTerminal handles WebSocket connections for management
// cluster terminal. Gates the upgrade on platform-admin status (ADR-013).
// Non-admins are rejected with HTTP 403 before upgrade.
func (h *Hub) HandleManagementTerminal(w http.ResponseWriter, r *http.Request) {
	userSession := requireSession(w, r, h.sessionResolver, h.log)
	if userSession == nil {
		return
	}
	if !requirePlatformAdmin(w, r, userSession, h.log) {
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Error("Failed to upgrade management terminal WebSocket", "error", err)
		return
	}

	h.log.Info("Starting management terminal session")

	termSession := NewTerminalSession(h.k8sClient, h.log, TerminalConfig{
		Type:      "management",
		Namespace: "",
		Cluster:   "management",
		UserEmail: userSession.Email,
		Role:      "platform-admin",
		Team:      "management",
	})

	termSession.Run(conn)
}
