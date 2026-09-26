package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"printmaster/server/storage"
)

func TestCredentialsCannotCrossTrustDomains(t *testing.T) {
	cfg := isolatedTestConfig()
	prev := serverConfig
	serverConfig = cfg
	t.Cleanup(func() { serverConfig = prev })
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/auth/me", requireWebAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	mux.HandleFunc("/api/v1/agents/heartbeat", requireAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	mux.HandleFunc("/api/v1/agents/ws", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	h := trustDomainMiddleware(cfg, mux)
	agentCert := httptest.NewRequest(http.MethodGet, "https://admin.example.com/api/v1/auth/me", nil)
	agentCert.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, agentCert)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("Agent certificate became admin identity: %d", w.Code)
	}
	adminCookie := httptest.NewRequest(http.MethodPost, "https://agents.example.com/api/v1/agents/heartbeat", nil)
	adminCookie.AddCookie(&http.Cookie{Name: "__Host-pm_session", Value: "admin-session"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, adminCookie)
	if w.Code == http.StatusNoContent {
		t.Fatal("admin cookie became Agent identity")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://admin.example.com/api/v1/agents/ws", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("Agent WSS on admin origin: %d", w.Code)
	}
}

func isolatedTestConfig() *Config {
	cfg := DefaultConfig()
	cfg.Server.TrustDomainsEnabled = true
	cfg.Server.AgentHost = "agents.example.com"
	cfg.Server.AdminHost = "admin.example.com"
	cfg.Server.PrinterProxyHost = "printer-proxy.example.com"
	return cfg
}

func TestTrustDomainRouteMatrix(t *testing.T) {
	cfg := isolatedTestConfig()
	mux := http.NewServeMux()
	paths := []string{"/api/v1/agents/heartbeat", "/api/v1/devices/batch", "/api/v1/metrics/batch", "/api/v1/agents/ws", "/api/v1/auth/login", "/admin", "/static/app.js", "/api/v1/users", "/api/v1/proxy/device/serial/", "/api/version"}
	for _, p := range paths {
		mux.HandleFunc(p, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	}
	h := trustDomainMiddleware(cfg, mux)
	cases := []struct {
		host, path string
		allowed    bool
	}{
		{"agents.example.com", "/api/v1/agents/heartbeat", true},
		{"agents.example.com", "/api/v1/auth/login", false},
		{"agents.example.com", "/admin", false},
		{"agents.example.com", "/static/app.js", false},
		{"admin.example.com", "/api/v1/devices/batch", false},
		{"admin.example.com", "/api/v1/metrics/batch", false},
		{"admin.example.com", "/api/v1/agents/ws", false},
		{"admin.example.com", "/api/v1/auth/login", true},
		{"printer-proxy.example.com", "/api/v1/users", false},
		{"printer-proxy.example.com", "/api/v1/agents/ws", false},
		{"printer-proxy.example.com", "/api/v1/proxy/device/serial/", true},
		{"unknown.example.com", "/api/version", false},
	}
	for _, tc := range cases {
		t.Run(tc.host+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://"+tc.host+tc.path, nil)
			r.Host = tc.host
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if got := w.Code == http.StatusNoContent; got != tc.allowed {
				t.Fatalf("status %d, allowed %v", w.Code, tc.allowed)
			}
		})
	}
}

func TestTrustDomainForwardedHostAndOrigin(t *testing.T) {
	cfg := isolatedTestConfig()
	cfg.Server.BehindProxy = true
	cfg.Server.ProxyUseHTTPS = true
	h := trustDomainMiddleware(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	test := func(host, remote, forwarded, origin, site string, status int) {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "https://"+host+"/api/v1/users", nil)
		r.Host, r.RemoteAddr = host, remote
		if forwarded != "" {
			r.Header.Set("X-Forwarded-Host", forwarded)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if site != "" {
			r.Header.Set("Sec-Fetch-Site", site)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != status {
			t.Fatalf("host=%q forwarded=%q origin=%q: got %d want %d", host, forwarded, origin, w.Code, status)
		}
	}
	test("agents.example.com", "203.0.113.9:123", "admin.example.com", "", "", http.StatusNotFound)
	test("agents.example.com", "127.0.0.1:123", "admin.example.com", "", "", http.StatusNoContent)
	test("agents.example.com", "127.0.0.1:123", "admin.example.com, agents.example.com", "", "", http.StatusNotFound)
	test("admin.example.com", "203.0.113.9:123", "", "https://printer-proxy.example.com", "", http.StatusForbidden)
	test("admin.example.com", "203.0.113.9:123", "", "https://admin.example.com", "same-site", http.StatusForbidden)
	test("admin.example.com", "203.0.113.9:123", "", "https://admin.example.com", "same-origin", http.StatusNoContent)
	// Admin session alone never selects an Agent principal or route.
	r := httptest.NewRequest(http.MethodPost, "https://agents.example.com/api/v1/agents/heartbeat", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-pm_session", Value: "admin-session"})
	r.Header.Set("Origin", "https://admin.example.com")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code == http.StatusNoContent {
		t.Fatal("admin browser session reached Agent handler")
	}
}

func TestTrustDomainConfigurationAndCookies(t *testing.T) {
	cfg := isolatedTestConfig()
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Server.AgentHost = "*.example.com" },
		func(c *Config) { c.Server.AgentHost = "https://agents.example.com" },
		func(c *Config) { c.Server.AgentHost = "admin.example.com:443" },
		func(c *Config) { c.Server.PrinterProxyHost = "admin.example.com:8443" },
		func(c *Config) { c.Server.AdminExternalURL = "http://admin.example.com" },
	} {
		bad := *cfg
		mutate(&bad)
		if err := validateTrustDomainConfig(&bad); err == nil {
			t.Fatalf("accepted invalid config %+v", bad.Server)
		}
	}
	bad := DefaultConfig()
	bad.Server.BindAddress = "0.0.0.0"
	if validateTrustDomainConfig(bad) == nil {
		t.Fatal("public bind without trust domains accepted")
	}
	if err := validateTrustDomainConfig(cfg); err != nil {
		t.Fatal(err)
	}
	previous := serverConfig
	serverConfig = cfg
	t.Cleanup(func() { serverConfig = previous })
	r := httptest.NewRequest(http.MethodGet, "https://admin.example.com/", nil)
	w := httptest.NewRecorder()
	clearSessionCookie(w, r)
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "__Host-pm_session" || cookies[0].Domain != "" || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].Path != "/" || cookies[0].SameSite != http.SameSiteLaxMode {
		t.Fatalf("unsafe admin cookie: %+v", cookies)
	}
}

func TestPrinterProxyTicketIsOneUseAndResourceScoped(t *testing.T) {
	previousConfig, previousStore := serverConfig, serverStore
	cfg := isolatedTestConfig()
	cfg.Server.BrowserProxyEnabled = true
	serverConfig = cfg
	store, err := storage.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	serverStore = store
	t.Cleanup(func() { serverConfig, serverStore = previousConfig, previousStore; _ = store.Close() })
	user := &storage.User{Username: "proxy-test", Role: storage.RoleAdmin}
	if err := store.CreateUser(context.Background(), user, "testing-password"); err != nil {
		t.Fatal(err)
	}
	admin := httptest.NewRequest(http.MethodPost, "https://admin.example.com/api/v1/proxy-access", strings.NewReader(`{"kind":"device","id":"serial1"}`))
	admin = admin.WithContext(contextWithPrincipal(admin.Context(), user))
	w := httptest.NewRecorder()
	handleProxyAccess(w, admin)
	if w.Code != http.StatusOK {
		t.Fatalf("ticket mint status %d: %s", w.Code, w.Body.String())
	}
	var response struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(response.URL, "https://printer-proxy.example.com/api/v1/proxy/device/serial1/?ticket=") {
		t.Fatalf("unsafe ticket URL %q", response.URL)
	}
	handler := trustDomainMiddleware(cfg, requirePrinterProxyAuth(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	redeem := func(raw string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, raw, nil)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	wrong := strings.Replace(response.URL, "serial1", "serial2", 1)
	if got := redeem(wrong).Code; got != http.StatusForbidden {
		t.Fatalf("cross-device ticket status %d", got)
	}
	// A mismatched resource consumes the ticket; it cannot be replayed.
	if got := redeem(response.URL).Code; got != http.StatusForbidden {
		t.Fatalf("replayed ticket status %d", got)
	}
	// A new ticket succeeds, and the resulting cookie is proxy-host-only.
	admin = httptest.NewRequest(http.MethodPost, "https://admin.example.com/api/v1/proxy-access", strings.NewReader(`{"kind":"device","id":"serial1"}`))
	admin = admin.WithContext(contextWithPrincipal(admin.Context(), user))
	w = httptest.NewRecorder()
	handleProxyAccess(w, admin)
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	result := redeem(response.URL)
	if result.Code != http.StatusSeeOther {
		t.Fatalf("redemption %d", result.Code)
	}
	cookies := result.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != printerProxyCookie || cookies[0].Domain != "" || !cookies[0].Secure {
		t.Fatalf("unsafe proxy cookies %+v", cookies)
	}
	r := httptest.NewRequest(http.MethodGet, "https://printer-proxy.example.com/api/v1/proxy/device/serial1/", nil)
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent {
		t.Fatalf("valid proxy session %d", w.Code)
	}
	r = httptest.NewRequest(http.MethodGet, "https://printer-proxy.example.com/api/v1/proxy/device/serial2/", nil)
	r.AddCookie(cookies[0])
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code == http.StatusNoContent {
		t.Fatal("proxy session escaped its device scope")
	}
	adminSession, err := store.CreateSession(context.Background(), user.ID, 5)
	if err != nil {
		t.Fatal(err)
	}
	r = httptest.NewRequest(http.MethodGet, "https://admin.example.com/api/v1/proxy/device/serial1/", nil)
	r.AddCookie(&http.Cookie{Name: adminSessionCookieName(), Value: adminSession.Token})
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "https://printer-proxy.example.com/") {
		t.Fatalf("old admin proxy URL did not redirect safely: status=%d location=%s", w.Code, w.Header().Get("Location"))
	}
}
