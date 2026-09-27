package main

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	wscommon "printmaster/common/ws"
)

func TestBrowserProxyIsDisabledUnlessExplicitlyConfigured(t *testing.T) {
	previous := serverConfig
	t.Cleanup(func() { serverConfig = previous })
	serverConfig = DefaultConfig()
	if browserProxyEnabled() {
		t.Fatal("browser proxy is enabled by default")
	}
	serverConfig.Server.BrowserProxyEnabled = true
	if !browserProxyEnabled() {
		t.Fatal("explicit browser proxy configuration was ignored")
	}
}

func TestPrinterProxyUnresponsiveAgentTimesOut(t *testing.T) {
	const agentID = "printer-proxy-timeout-test"
	upgraded := make(chan *wscommon.Conn, 1)
	wsServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := wscommon.UpgradeHTTP(w, r)
		if err == nil {
			upgraded <- conn
		}
	}))
	defer wsServer.Close()
	peer, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(wsServer.URL, "http"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	conn := <-upgraded
	defer conn.Close()
	wsConnectionsLock.Lock()
	wsConnections[agentID] = conn
	wsConnectionsLock.Unlock()
	defer func() {
		wsConnectionsLock.Lock()
		delete(wsConnections, agentID)
		wsConnectionsLock.Unlock()
	}()
	r := httptest.NewRequest(http.MethodGet, "https://printer-proxy.example.com/api/v1/proxy/device/test/", nil)
	w := httptest.NewRecorder()
	proxyThroughWebSocketWithTimeout(w, r, agentID, "http://localhost:8080/proxy/test/", 20*time.Millisecond)
	if w.Code != http.StatusGatewayTimeout {
		t.Fatalf("unresponsive Agent status %d, want timeout", w.Code)
	}
}

func TestPrinterProxyRejectsGzipExpansionBomb(t *testing.T) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	chunk := bytes.Repeat([]byte("x"), 64<<10)
	for i := 0; i < (maxProxyDecompressedBodySize/(64<<10))+1; i++ {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := decompressProxyGzip(compressed.Bytes()); err == nil {
		t.Fatal("compressed printer response expanded past the limit")
	}
}

func TestProxyResponseHeadersDiscardCookieAndPolicy(t *testing.T) {
	headers := make(http.Header)
	copySafeProxyResponseHeaders(headers, map[string]interface{}{
		"Content-Type":            "text/html",
		"Set-Cookie":              "pm_session=attacker; Path=/",
		"Content-Security-Policy": "script-src *",
		"Location":                "https://attacker.example/",
		"X-Frame-Options":         "ALLOWALL",
		"X-Test-With-Newline":     "safe\r\nInjected: true",
	})
	if headers.Get("Content-Type") != "text/html" {
		t.Fatal("safe content type was not preserved")
	}
	for _, forbidden := range []string{"Set-Cookie", "Content-Security-Policy", "Location", "X-Frame-Options", "X-Test-With-Newline"} {
		if headers.Get(forbidden) != "" {
			t.Fatalf("unsafe header forwarded: %s=%q", forbidden, headers.Get(forbidden))
		}
	}
}

func TestPrinterProxyHeadersAreBounded(t *testing.T) {
	r := httptest.NewRequest(http.MethodGet, "https://printer-proxy.example.com/api/v1/proxy/device/test/", nil)
	r.Header.Set("Authorization", "Bearer secret")
	r.Header.Set("Cookie", "session=secret")
	r.Header.Set("X-Printer-Long", strings.Repeat("x", 2049))
	r.Header.Set("Accept", "text/html")
	h := trustedProxyHeaders(r)
	if h["Accept"] != "text/html" || h["Authorization"] != "" || h["Cookie"] != "" || h["X-Printer-Long"] != "" {
		t.Fatalf("unexpected proxy header set: %#v", h)
	}
	resp := make(http.Header)
	copySafeProxyResponseHeaders(resp, map[string]interface{}{"Content-Type": strings.Repeat("x", 4097)})
	if resp.Get("Content-Type") != "" {
		t.Fatal("oversized printer header was forwarded")
	}
}

func TestReadBoundedProxyBody(t *testing.T) {
	if _, err := readBoundedProxyBody(bytes.NewReader([]byte("12345")), 4); err == nil {
		t.Fatal("oversized proxy body was accepted")
	}
	body, err := readBoundedProxyBody(bytes.NewReader([]byte("1234")), 4)
	if err != nil || string(body) != "1234" {
		t.Fatalf("bounded body read failed: %q, %v", body, err)
	}
}
