package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"printmaster/server/storage"
	"strings"
	"testing"
	"time"
)

func TestBatchRejectsOtherAgentIdentity(t *testing.T) {
	for _, handler := range []http.HandlerFunc{handleDevicesBatch, handleMetricsBatch} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(`{"agent_id":"victim","devices":[],"metrics":[]}`))
		r = r.WithContext(context.WithValue(r.Context(), agentContextKey, &storage.Agent{AgentID: "attacker"}))
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != 403 {
			t.Fatalf("status=%d want 403", w.Code)
		}
	}
}

func TestLoginHonorsRateLimitBeforePasswordCheck(t *testing.T) {
	old := authRateLimiter
	authRateLimiter = NewAuthRateLimiter(2, time.Minute, time.Minute)
	t.Cleanup(func() { authRateLimiter.Stop(); authRateLimiter = old })
	r := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"username":"ADMIN","password":"wrong"}`))
	r.RemoteAddr = "192.0.2.10:10000"
	for i := 0; i < 3; i++ {
		authRateLimiter.RecordFailure(getRealIP(r), "login:admin")
	}
	w := httptest.NewRecorder()
	handleAuthLogin(w, r)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatalf("blocked login status=%d", w.Code)
	}
}

func TestJSONBodyRejectsOversizedAndTrailingContent(t *testing.T) {
	for _, body := range []string{`{} {"extra":true}`, `{}` + strings.Repeat(" ", maxRequestBodySize), `{} garbage`} {
		r := httptest.NewRequest("POST", "/", strings.NewReader(body))
		var decoded map[string]interface{}
		if decodeJSONBody(r, &decoded) == nil {
			t.Fatal("invalid or oversized request accepted")
		}
	}
}

func TestPublicAccountMutationsRejectCrossOriginRequests(t *testing.T) {
	handlers := []http.HandlerFunc{
		handlePasswordResetRequest,
		handlePasswordResetConfirm,
		handleInviteAccept,
	}
	for _, handler := range handlers {
		r := httptest.NewRequest(http.MethodPost, "https://printmaster.example/api", strings.NewReader(`{}`))
		r.Header.Set("Origin", "https://attacker.example")
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("cross-origin request status=%d want %d", w.Code, http.StatusForbidden)
		}
	}
}

func TestSensitiveTokenLoggingNeverRevealsShortValues(t *testing.T) {
	for _, value := range []string{"short", "12345678", "  tiny  "} {
		if got := maskSensitiveToken(value); strings.Contains(got, strings.TrimSpace(value)) {
			t.Fatalf("maskSensitiveToken(%q) exposed input: %q", value, got)
		}
	}
	if got := maskSensitiveToken("123456789abcdef"); got != "12345678..." {
		t.Fatalf("long sensitive token mask=%q", got)
	}
}

func TestAgentUpdateEndpointsBindAuthenticatedIdentityAndScope(t *testing.T) {
	agent := &storage.Agent{AgentID: "authenticated-agent"}
	manifestReq := httptest.NewRequest(http.MethodPost, "/api/v1/agents/update/manifest", strings.NewReader(`{"agent_id":"other-agent","component":"agent"}`))
	manifestReq = manifestReq.WithContext(context.WithValue(manifestReq.Context(), agentContextKey, agent))
	manifestW := httptest.NewRecorder()
	handleAgentUpdateManifest(manifestW, manifestReq)
	if manifestW.Code != http.StatusForbidden {
		t.Fatalf("manifest identity mismatch status=%d want %d", manifestW.Code, http.StatusForbidden)
	}

	scopedManifestReq := httptest.NewRequest(http.MethodPost, "/api/v1/agents/update/manifest", strings.NewReader(`{"component":"server"}`))
	scopedManifestReq = scopedManifestReq.WithContext(context.WithValue(scopedManifestReq.Context(), agentContextKey, agent))
	scopedManifestW := httptest.NewRecorder()
	handleAgentUpdateManifest(scopedManifestW, scopedManifestReq)
	if scopedManifestW.Code != http.StatusForbidden {
		t.Fatalf("manifest component scope status=%d want %d", scopedManifestW.Code, http.StatusForbidden)
	}

	telemetryReq := httptest.NewRequest(http.MethodPost, "/api/v1/agents/update/telemetry", strings.NewReader(`{"agent_id":"other-agent"}`))
	telemetryReq = telemetryReq.WithContext(context.WithValue(telemetryReq.Context(), agentContextKey, agent))
	telemetryW := httptest.NewRecorder()
	handleAgentUpdateTelemetry(telemetryW, telemetryReq)
	if telemetryW.Code != http.StatusForbidden {
		t.Fatalf("telemetry identity mismatch status=%d want %d", telemetryW.Code, http.StatusForbidden)
	}

	downloadReq := httptest.NewRequest(http.MethodGet, "/api/v1/agents/update/download/server/1.2.3/windows-amd64", nil)
	downloadReq = downloadReq.WithContext(context.WithValue(downloadReq.Context(), agentContextKey, agent))
	downloadW := httptest.NewRecorder()
	handleAgentUpdateDownload(downloadW, downloadReq)
	if downloadW.Code != http.StatusForbidden {
		t.Fatalf("download component scope status=%d want %d", downloadW.Code, http.StatusForbidden)
	}
}
