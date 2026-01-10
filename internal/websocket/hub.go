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
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
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
)

// Message represents a WebSocket message.
type Message struct {
	Type    MessageType `json:"type"`
	Payload interface{} `json:"payload,omitempty"`
}

// ClusterUpdatePayload is sent when a cluster is created or updated.
type ClusterUpdatePayload struct {
	Cluster interface{} `json:"cluster"`
}

// ClusterDeletePayload is sent when a cluster is deleted.
type ClusterDeletePayload struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// Hub manages WebSocket connections and cluster watches.
type Hub struct {
	k8sClient *k8s.Client
	log       *slog.Logger

	clients    map[*Client]bool
	register   chan *Client
	unregister chan *Client
	broadcast  chan Message

	mu sync.RWMutex
}

// Client represents a WebSocket client connection.
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan Message
}

// NewHub creates a new WebSocket hub.
func NewHub(k8sClient *k8s.Client, log *slog.Logger) *Hub {
	return &Hub{
		k8sClient:  k8sClient,
		log:        log,
		clients:    make(map[*Client]bool),
		register:   make(chan *Client),
		unregister: make(chan *Client),
		broadcast:  make(chan Message, 256),
	}
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

func (h *Hub) watchClusters() {
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
				}

			case watch.Deleted:
				if obj, ok := event.Object.(interface {
					GetName() string
					GetNamespace() string
				}); ok {
					h.broadcast <- Message{
						Type: MessageTypeClusterDelete,
						Payload: ClusterDeletePayload{
							Name:      obj.GetName(),
							Namespace: obj.GetNamespace(),
						},
					}
				}

			case watch.Error:
				h.log.Error("Watch error", "object", event.Object)
			}
		}

		h.log.Info("TenantCluster watch ended, restarting")
		time.Sleep(time.Second)
	}
}

// HandleClusterWatch handles WebSocket connections for cluster updates.
func (h *Hub) HandleClusterWatch(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Error("Failed to upgrade WebSocket connection", "error", err)
		return
	}

	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan Message, 256),
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

// HandleTerminal handles WebSocket connections for terminal sessions.
func (h *Hub) HandleTerminal(w http.ResponseWriter, r *http.Request) {
	termType := chi.URLParam(r, "type")
	namespace := chi.URLParam(r, "namespace")
	cluster := chi.URLParam(r, "cluster")
	pod := chi.URLParam(r, "pod")
	container := chi.URLParam(r, "container")

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Error("Failed to upgrade terminal WebSocket", "error", err)
		return
	}

	session := NewTerminalSession(h.k8sClient, h.log, TerminalConfig{
		Type:      termType,
		Namespace: namespace,
		Cluster:   cluster,
		Pod:       pod,
		Container: container,
	})

	session.Run(conn)
}

// HandleManagementTerminal handles WebSocket connections for management cluster terminal.
func (h *Hub) HandleManagementTerminal(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		h.log.Error("Failed to upgrade management terminal WebSocket", "error", err)
		return
	}

	h.log.Info("Starting management terminal session")

	session := NewTerminalSession(h.k8sClient, h.log, TerminalConfig{
		Type:      "management",
		Namespace: "",
		Cluster:   "management",
	})

	session.Run(conn)
}
