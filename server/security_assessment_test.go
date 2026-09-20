//go:build security_assessment

package main

// These tests guard remediated proxy findings. No customer data or live printer is used.
import (
	"encoding/base64"
	"encoding/json"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	wscommon "printmaster/common/ws"
	"printmaster/server/storage"
	"strings"
	"testing"
	"time"
)

func TestAssessmentProxyIsolatesActiveHTMLAndPanelCookie(t *testing.T) {
	const agentID = "assessment-proxy-agent"
	upgraded := make(chan *wscommon.Conn, 1)
	wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := wscommon.UpgradeHTTP(w, r)
		if err == nil {
			upgraded <- c
		}
	}))
	defer wsServer.Close()
	peer, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(wsServer.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	var conn *wscommon.Conn
	select {
	case conn = <-upgraded:
	case <-time.After(3 * time.Second):
		t.Fatal("test WebSocket unavailable")
	}
	defer conn.Close()
	wsConnectionsLock.Lock()
	wsConnections[agentID] = conn
	wsConnectionsLock.Unlock()
	defer func() { wsConnectionsLock.Lock(); delete(wsConnections, agentID); wsConnectionsLock.Unlock() }()
	marker := `<script>window.__printmasterAssessmentMarker=true;</script>`
	done := make(chan error, 1)
	go func() {
		var request wscommon.Message
		if err := peer.ReadJSON(&request); err != nil {
			done <- err
			return
		}
		response := wscommon.Message{Type: "proxy_response", Data: map[string]interface{}{"request_id": request.Data["request_id"], "status_code": 200, "headers": map[string]interface{}{"Content-Type": "text/html", "Set-Cookie": "pm_session=assessment-marker; Path=/; HttpOnly"}, "body": base64.StdEncoding.EncodeToString([]byte("<html><head></head><body>" + marker + "</body></html>"))}}
		if err := peer.WriteJSON(response); err != nil {
			done <- err
			return
		}
		bytes, err := conn.ReadMessage()
		if err != nil {
			done <- err
			return
		}
		if err := json.Unmarshal(bytes, &response); err != nil {
			done <- err
			return
		}
		handleWSProxyResponse(agentID, conn, response)
		done <- nil
	}()
	r := httptest.NewRequest("GET", "http://panel.example/api/v1/proxy/device/assessment-printer/", nil)
	r = r.WithContext(contextWithPrincipal(r.Context(), &storage.User{Username: "admin", Role: storage.RoleAdmin}))
	w := httptest.NewRecorder()
	proxyThroughWebSocketWithTimeout(w, r, agentID, "http://localhost:8080/proxy/assessment-printer/", 3*time.Second)
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("test response timed out")
	}
	if w.Code != 200 || !strings.Contains(w.Body.String(), marker) {
		t.Fatal("proxied HTML response missing")
	}
	csp := w.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "sandbox") || !strings.Contains(csp, "script-src 'none'") {
		t.Fatalf("unsafe HTML was not sandboxed: %q", csp)
	}
	if w.Header().Get("Set-Cookie") != "" {
		t.Fatalf("printer response set a panel cookie: %q", w.Header().Get("Set-Cookie"))
	}
	t.Log("PM-01/PM-03 regression: proxied active HTML is sandboxed and printer cookies are discarded.")
}
