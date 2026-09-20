package main

import (
	"net/http"
	"net/http/httptest"
	"printmaster/common/requestauth"
	"testing"
)

func TestTrustedProxyPreservesIdentityAndEnforcesRole(t *testing.T) {
	auth := newAgentAuthManager(DefaultAgentConfig(), newAgentSessionManager())
	for _, tc := range []struct {
		role, method, path string
		status             int
	}{
		{"admin", "POST", "/settings", 204},
		{"viewer", "GET", "/devices/list", 204},
		{"viewer", "POST", "/settings", 403},
		{"viewer", "GET", "/api/usb-printers/probe/device", 403},
		{"operator", "POST", "/api/autoupdate/force", 403},
		{"operator", "POST", "/devices/refresh", 204},
		{"unknown", "POST", "/settings", 401},
	} {
		t.Run(tc.role+tc.method+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			r = r.WithContext(requestauth.WithProxyPrincipal(r.Context(), "team-user", tc.role))
			w := httptest.NewRecorder()
			auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p, ok := auth.PrincipalForRequest(r)
				if !ok || p.Username != "team-user" || p.Role != tc.role {
					t.Fatal("lost trusted principal")
				}
				w.WriteHeader(204)
			})).ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status=%d want %d", w.Code, tc.status)
			}
		})
	}
}

func TestAgentRejectsUntrustedIdentityHeaders(t *testing.T) {
	for _, tc := range []struct{ name, path, header, value string }{
		{"proxy", "/settings", "X-PrintMaster-Proxy", "server"},
		{"forwarded_loopback", "/settings", "X-Forwarded-For", "127.0.0.1"},
		{"usb_scan", "/api/usb-printers/scan", "", ""},
		{"usb_probe", "/api/usb-printers/probe/test-device", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultAgentConfig()
			auth := newAgentAuthManager(cfg, newAgentSessionManager())
			reached := false
			h := auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
			r := httptest.NewRequest(http.MethodPost, tc.path, nil)
			r.RemoteAddr = "192.0.2.10:12345"
			if tc.header != "" {
				r.Header.Set(tc.header, tc.value)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if reached || w.Code != http.StatusUnauthorized {
				t.Fatalf("untrusted request reached handler=%v, status=%d", reached, w.Code)
			}
		})
	}
}

func TestAgentAuthMeRejectsSpoofedProxyPrincipal(t *testing.T) {
	auth := newAgentAuthManager(DefaultAgentConfig(), newAgentSessionManager())
	r := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	r.RemoteAddr = "192.0.2.10:12345"
	r.Header.Set("X-PrintMaster-Proxy", "server")
	r.Header.Set("X-PrintMaster-User", "admin")
	r.Header.Set("X-PrintMaster-Role", "admin")
	w := httptest.NewRecorder()
	auth.handleAuthMe(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("spoofed principal accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestLoopbackUsesTransportAddress(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:1234", "[::1]:1234"} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = addr
		if !requestIsLoopback(r) {
			t.Fatalf("actual loopback rejected: %s", addr)
		}
	}
}

func TestUnauthenticatedLoopbackDoesNotBypassAuthentication(t *testing.T) {
	auth := newAgentAuthManager(DefaultAgentConfig(), newAgentSessionManager())
	for _, tc := range []struct {
		host, origin string
		want         int
	}{
		{"attacker.example:8080", "", 401},
		{"127.0.0.1:8080", "https://attacker.example", 403},
		{"127.0.0.1:8080", "http://127.0.0.1:8080", 401},
	} {
		r := httptest.NewRequest("POST", "http://"+tc.host+"/settings", nil)
		r.RemoteAddr = "127.0.0.1:19000"
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		auth.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })).ServeHTTP(w, r)
		if w.Code != tc.want {
			t.Fatalf("host %s origin %s: got %d want %d", tc.host, tc.origin, w.Code, tc.want)
		}
	}
}

func TestDefaultAgentDoesNotTreatLoopbackAsAnAdministrator(t *testing.T) {
	cfg := DefaultAgentConfig()
	// A legacy configuration cannot re-enable this bypass.
	cfg.Web.Auth.AllowLocalAdmin = true
	auth := newAgentAuthManager(cfg, newAgentSessionManager())
	r := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8080/api/v1/auth/me", nil)
	r.RemoteAddr = "127.0.0.1:19000"
	w := httptest.NewRecorder()
	auth.handleAuthMe(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("default loopback request received a principal: %d", w.Code)
	}
}

func TestDisabledAuthModeCannotGrantAdministratorAccess(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Web.Auth.Mode = "disabled"
	auth := newAgentAuthManager(cfg, newAgentSessionManager())
	r := httptest.NewRequest(http.MethodGet, "/settings", nil)
	r.RemoteAddr = "192.0.2.10:12345"
	w := httptest.NewRecorder()
	auth.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("unauthenticated request reached handler") })).ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("disabled mode bypassed authentication: %d", w.Code)
	}
}

func TestServerAuthOptionsExposeAgentBindingIdentity(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Web.Auth.Mode = "server"
	cfg.Server.URL = "https://printmaster.example"
	cfg.Server.AgentID = "agent-123"
	auth := newAgentAuthManager(cfg, newAgentSessionManager())
	opts := auth.optionsPayload()
	if opts.AgentID != cfg.Server.AgentID {
		t.Fatalf("agent id not exposed for callback binding: got %q", opts.AgentID)
	}
	if !opts.LoginSupported || opts.ServerAuthURL == "" {
		t.Fatalf("server auth options unexpectedly disabled: %+v", opts)
	}
}

func TestInvalidRemoteHTTPServerURLIsNotAdvertised(t *testing.T) {
	cfg := DefaultAgentConfig()
	cfg.Web.Auth.Mode = "server"
	cfg.Server.URL = "http://central.example"
	auth := newAgentAuthManager(cfg, newAgentSessionManager())
	if opts := auth.optionsPayload(); opts.ServerURL != "" || opts.ServerAuthURL != "" || opts.LoginSupported {
		t.Fatalf("insecure remote server URL was advertised: %+v", opts)
	}
}
