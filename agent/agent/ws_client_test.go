package agent

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wscommon "printmaster/common/ws"

	"github.com/gorilla/websocket"
)

func TestWebSocketUsesBearerHeaderAndCustomCA(t *testing.T) {
	observed := make(chan bool, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observed <- r.URL.Query().Get("token") == "" && r.Header.Get("Authorization") == "Bearer test-secret"
		c, e := upgrader.Upgrade(w, r, nil)
		if e != nil {
			return
		}
		defer c.Close()
		for {
			if _, _, e := c.ReadMessage(); e != nil {
				return
			}
		}
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	client := NewWSClient(srv.URL, "test-secret", false)
	client.SetTLSConfig(&tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12})
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer client.Stop()
	if !client.IsConnected() {
		t.Fatal("custom CA was not honored")
	}
	select {
	case ok := <-observed:
		if !ok {
			t.Fatal("credential leaked into URL or header missing")
		}
	case <-time.After(time.Second):
		t.Fatal("handshake not observed")
	}
}

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

// TestWSClientConnection tests basic WebSocket client connection
func TestWSClientConnection(t *testing.T) {
	t.Parallel()

	// Create a test WebSocket server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check token
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != "test-token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Upgrade to WebSocket
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("Upgrade error: %v", err)
			return
		}
		defer conn.Close()

		// Simple echo server
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				break
			}

			// Echo back
			err = conn.WriteMessage(websocket.TextMessage, message)
			if err != nil {
				break
			}
		}
	}))
	defer server.Close()

	// Create WebSocket client
	serverURL := "http" + strings.TrimPrefix(server.URL, "http")
	client := NewWSClient(serverURL, "test-token", false)

	// Start client
	err := client.Start()
	if err != nil {
		t.Fatalf("Failed to start WebSocket client: %v", err)
	}
	defer client.Stop()

	// Wait for connection
	time.Sleep(200 * time.Millisecond)

	// Check if connected
	if !client.IsConnected() {
		t.Error("Expected client to be connected")
	}

	t.Log("WebSocket client connected successfully")
}

// TestWSClientHeartbeat tests sending heartbeat messages
func TestWSClientHeartbeat(t *testing.T) {
	t.Parallel()

	receivedHeartbeat := false

	// Create a test WebSocket server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check token
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != "test-token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Upgrade to WebSocket
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("Upgrade error: %v", err)
			return
		}
		defer conn.Close()

		// Read heartbeat messages
		for {
			_, message, err := conn.ReadMessage()
			if err != nil {
				break
			}

			// Parse message
			var msg wscommon.Message
			if err := json.Unmarshal(message, &msg); err != nil {
				t.Logf("Failed to unmarshal message: %v", err)
				continue
			}

			if msg.Type == wscommon.MessageTypeHeartbeat {
				receivedHeartbeat = true

				// Send pong response
				pongMsg := wscommon.Message{
					Type:      wscommon.MessageTypePong,
					Timestamp: time.Now(),
				}
				payload, _ := json.Marshal(pongMsg)
				conn.WriteMessage(websocket.TextMessage, payload)
			}
		}
	}))
	defer server.Close()

	// Create WebSocket client
	serverURL := "http" + strings.TrimPrefix(server.URL, "http")
	client := NewWSClient(serverURL, "test-token", false)

	// Start client
	err := client.Start()
	if err != nil {
		t.Fatalf("Failed to start WebSocket client: %v", err)
	}
	defer client.Stop()

	// Wait for connection
	time.Sleep(200 * time.Millisecond)

	// Send heartbeat
	heartbeatData := map[string]interface{}{
		"device_count": 10,
	}

	err = client.SendHeartbeat(heartbeatData)
	if err != nil {
		t.Fatalf("Failed to send heartbeat: %v", err)
	}

	// Wait for server to process
	time.Sleep(200 * time.Millisecond)

	if !receivedHeartbeat {
		t.Error("Server did not receive heartbeat")
	}

	t.Log("WebSocket heartbeat sent and received successfully")
}

// TestWSClientReconnection tests automatic reconnection
func TestWSClientReconnection(t *testing.T) {
	t.Parallel()

	connectionCount := 0

	// Create a test WebSocket server that closes connections
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connectionCount++

		// Check token
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != "test-token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Upgrade to WebSocket
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("Upgrade error: %v", err)
			return
		}
		defer conn.Close()

		// Close connection immediately to trigger reconnection
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	// Create WebSocket client with short reconnect delay
	serverURL := "http" + strings.TrimPrefix(server.URL, "http")
	client := NewWSClient(serverURL, "test-token", false)
	client.reconnectDelay = 500 * time.Millisecond // Short delay for testing

	// Start client
	err := client.Start()
	if err != nil {
		t.Fatalf("Failed to start WebSocket client: %v", err)
	}
	defer client.Stop()

	// Wait for initial connection and reconnections (poll until timeout)
	// Increase deadline to avoid flakes on slower machines.
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		if connectionCount >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Should have reconnected at least once
	if connectionCount < 2 {
		t.Errorf("Expected at least 2 connections (initial + reconnect), got %d", connectionCount)
	}

	t.Logf("WebSocket reconnected successfully (%d connections)", connectionCount)
}

// TestWSClientAuthenticationFailure tests handling of authentication failures
func TestWSClientAuthenticationFailure(t *testing.T) {
	t.Parallel()

	// Create a test WebSocket server that rejects connections
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	// Create WebSocket client with invalid token
	serverURL := "http" + strings.TrimPrefix(server.URL, "http")
	client := NewWSClient(serverURL, "invalid-token", false)

	// Start client
	err := client.Start()
	// Start doesn't return error immediately - connection happens asynchronously
	if err != nil {
		t.Fatalf("Unexpected error from Start: %v", err)
	}
	defer client.Stop()

	// Wait a bit for connection attempt
	time.Sleep(200 * time.Millisecond)

	// Should not be connected
	if client.IsConnected() {
		t.Error("Expected client to not be connected with invalid token")
	}

	t.Log("WebSocket authentication failure handled correctly")
}

// TestWSClientRejectsSkipVerify ensures the WS client never disables
// certificate verification, even when a legacy caller passes true.
func TestWSClientRejectsSkipVerify(t *testing.T) {
	t.Parallel()

	// TLS test server (self-signed cert) that upgrades to websocket and immediately closes
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Accept any token for this test
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("Upgrade error: %v", err)
			return
		}
		defer conn.Close()
		// keep connection open long enough for the test to observe a connected state
		time.Sleep(500 * time.Millisecond)
	}))
	defer server.Close()

	serverURL := server.URL

	// A legacy skipVerify=true argument must be ignored; the self-signed
	// certificate remains untrusted and the connection must fail.
	clientRejected := NewWSClient(serverURL, "test-token", true)
	if err := clientRejected.Start(); err != nil {
		t.Fatalf("Start should remain asynchronous: %v", err)
	}
	defer clientRejected.Stop()

	// wait briefly for connection
	time.Sleep(200 * time.Millisecond)
	if clientRejected.IsConnected() {
		t.Fatal("Expected WS client to reject self-signed cert when insecureSkipVerify=true")
	}

	// When skipVerify = false, connection should fail (can't verify cert)
	clientBad := NewWSClient(serverURL, "test-token", false)
	if err := clientBad.Start(); err != nil {
		// Start may not return error immediately; allow it to attempt
		t.Logf("Start returned error (expected possible async behavior): %v", err)
	}
	defer clientBad.Stop()

	// Give it time to try and fail
	time.Sleep(300 * time.Millisecond)
	if clientBad.IsConnected() {
		t.Fatal("Expected WS client to NOT be connected when insecureSkipVerify=false to a self-signed server")
	}
}

func TestWSClientTLSConfigClearsInsecureOverride(t *testing.T) {
	client := NewWSClient("https://server.example", "token", true)
	if client.insecureSkipVerify {
		t.Fatal("legacy insecureSkipVerify argument must be ignored")
	}
	client.SetTLSConfig(&tls.Config{InsecureSkipVerify: true})
	if client.tlsConfig == nil || client.tlsConfig.InsecureSkipVerify {
		t.Fatal("SetTLSConfig must clear InsecureSkipVerify")
	}
	if client.tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("expected minimum TLS version 1.2, got %d", client.tlsConfig.MinVersion)
	}
}

// TestWSClientBasePath verifies that the WebSocket client preserves any base
// path included in the configured server URL when constructing the ws endpoint.
func TestWSClientBasePath(t *testing.T) {
	t.Parallel()

	pathCh := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pathCh <- r.URL.Path
		if strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ") != "test-token" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Logf("Upgrade error: %v", err)
			return
		}
		defer conn.Close()
		time.Sleep(200 * time.Millisecond)
	}))
	defer server.Close()

	baseURL := server.URL + "/nested/base"
	client := NewWSClient(baseURL, "test-token", false)
	if err := client.Start(); err != nil {
		t.Fatalf("Failed to start WebSocket client with base path: %v", err)
	}
	defer client.Stop()

	select {
	case path := <-pathCh:
		if path != "/nested/base/api/v1/agents/ws" {
			t.Fatalf("WebSocket path mismatch, got %q", path)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Timed out waiting for WebSocket request")
	}
}
