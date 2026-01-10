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
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/butlerdotdev/butler-server/internal/k8s"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

// TerminalConfig holds terminal session configuration.
type TerminalConfig struct {
	Type      string
	Namespace string
	Cluster   string
	Pod       string
	Container string
}

// TerminalSession manages a single terminal WebSocket connection.
type TerminalSession struct {
	k8sClient *k8s.Client
	log       *slog.Logger
	config    TerminalConfig

	conn *websocket.Conn
	pty  *os.File
	cmd  *exec.Cmd

	kubeconfigPath string
	mu             sync.Mutex
}

// TerminalMessage represents messages from the client.
type TerminalMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
	Cols uint16 `json:"cols,omitempty"`
	Rows uint16 `json:"rows,omitempty"`
}

// NewTerminalSession creates a new terminal session.
func NewTerminalSession(k8sClient *k8s.Client, log *slog.Logger, config TerminalConfig) *TerminalSession {
	return &TerminalSession{
		k8sClient: k8sClient,
		log:       log.With("cluster", config.Cluster, "type", config.Type),
		config:    config,
	}
}

// Run starts the terminal session.
func (t *TerminalSession) Run(conn *websocket.Conn) {
	t.conn = conn
	defer conn.Close()

	t.log.Info("Starting terminal session")

	kubeconfigPath, err := t.setupKubeconfig()
	if err != nil {
		t.log.Error("Failed to setup kubeconfig", "error", err)
		t.writeError(fmt.Sprintf("Failed to setup kubeconfig: %v", err))
		return
	}

	t.kubeconfigPath = kubeconfigPath

	if t.config.Type != "management" && kubeconfigPath != "" {
		defer os.Remove(kubeconfigPath)
	}

	if err := t.startShell(); err != nil {
		t.log.Error("Failed to start shell", "error", err)
		t.writeError(fmt.Sprintf("Failed to start shell: %v", err))
		return
	}
	defer t.cleanup()

	done := make(chan struct{})

	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			n, err := t.pty.Read(buf)
			if err != nil {
				if err != io.EOF {
					t.log.Debug("PTY read error", "error", err)
				}
				return
			}
			t.mu.Lock()
			err = t.conn.WriteMessage(websocket.TextMessage, buf[:n])
			t.mu.Unlock()
			if err != nil {
				t.log.Debug("WebSocket write error", "error", err)
				return
			}
		}
	}()

	go func() {
		for {
			_, data, err := t.conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					t.log.Debug("WebSocket read error", "error", err)
				}
				return
			}

			var msg TerminalMessage
			if err := json.Unmarshal(data, &msg); err == nil {
				switch msg.Type {
				case "resize":
					t.resize(msg.Cols, msg.Rows)
					continue
				case "data":
					data = []byte(msg.Data)
				}
			}

			if _, err := t.pty.Write(data); err != nil {
				t.log.Debug("PTY write error", "error", err)
				return
			}
		}
	}()

	<-done
	t.log.Info("Terminal session ended")
}

func (t *TerminalSession) setupKubeconfig() (string, error) {
	var kubeconfigPath string

	if t.config.Type == "management" {
		if kc := os.Getenv("KUBECONFIG"); kc != "" {
			kubeconfigPath = kc
		} else if home, err := os.UserHomeDir(); err == nil {
			defaultPath := filepath.Join(home, ".kube", "config")
			if _, err := os.Stat(defaultPath); err == nil {
				kubeconfigPath = defaultPath
			}
		}

		if kubeconfigPath != "" {
			return kubeconfigPath, nil
		}

		return "", nil
	}

	ctx := context.Background()
	kubeconfig, err := t.k8sClient.GetClusterKubeconfig(
		ctx,
		t.config.Namespace,
		t.config.Cluster,
	)
	if err != nil {
		return "", fmt.Errorf("failed to get tenant kubeconfig: %w", err)
	}

	tmpFile, err := os.CreateTemp("", fmt.Sprintf("kubeconfig-%s-*.yaml", t.config.Cluster))
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %w", err)
	}

	if _, err := tmpFile.WriteString(kubeconfig); err != nil {
		tmpFile.Close()
		os.Remove(tmpFile.Name())
		return "", fmt.Errorf("failed to write kubeconfig: %w", err)
	}
	tmpFile.Close()

	return tmpFile.Name(), nil
}

func (t *TerminalSession) startShell() error {
	shell := "/bin/bash"
	if _, err := os.Stat("/bin/bash"); err != nil {
		shell = "/bin/sh"
	}

	ptmx, tty, err := pty.Open()
	if err != nil {
		return fmt.Errorf("failed to open pty: %w", err)
	}

	t.cmd = exec.Command(shell)
	t.cmd.Stdin = tty
	t.cmd.Stdout = tty
	t.cmd.Stderr = tty

	env := os.Environ()
	if t.kubeconfigPath != "" {
		env = append(env, fmt.Sprintf("KUBECONFIG=%s", t.kubeconfigPath))
	}
	env = append(env, fmt.Sprintf("PS1=[%s] $ ", t.config.Cluster))
	env = append(env, "TERM=xterm-256color")
	t.cmd.Env = env

	if err := t.cmd.Start(); err != nil {
		ptmx.Close()
		tty.Close()
		return fmt.Errorf("failed to start shell: %w", err)
	}

	tty.Close()

	t.pty = ptmx
	return nil
}

func (t *TerminalSession) resize(cols, rows uint16) {
	if t.pty == nil {
		return
	}
	pty.Setsize(t.pty, &pty.Winsize{Cols: cols, Rows: rows})
}

func (t *TerminalSession) cleanup() {
	if t.pty != nil {
		t.pty.Close()
	}
	if t.cmd != nil && t.cmd.Process != nil {
		t.cmd.Process.Kill()
		t.cmd.Wait()
	}
}

func (t *TerminalSession) writeError(msg string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	errMsg := fmt.Sprintf("\x1b[31m%s\x1b[0m\r\n", msg)
	t.conn.WriteMessage(websocket.TextMessage, []byte(errMsg))
}
