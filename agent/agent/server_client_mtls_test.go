package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestServerClientRegisterThenActivateUsesFreshClientCertificate(t *testing.T) {
	clientCertPEM, clientKeyPEM := testIdentityMaterial(t, "agent-client")
	var mu sync.Mutex
	registerHasCertificate := false
	activateHasCertificate := false

	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hasCertificate := r.TLS != nil && len(r.TLS.PeerCertificates) > 0
		switch r.URL.Path {
		case "/api/v1/agents/register-mtls":
			var request struct {
				EnrollmentAttemptID string `json:"enrollment_attempt_id"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.EnrollmentAttemptID == "" {
				http.Error(w, "enrollment attempt missing", http.StatusBadRequest)
				return
			}
			mu.Lock()
			registerHasCertificate = hasCertificate
			mu.Unlock()
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]interface{}{
				"success":            true,
				"credential_id":      "credential-1",
				"tenant_id":          "tenant-1",
				"agent_id":           "agent-1",
				"client_certificate": string(clientCertPEM),
				"expires_at":         time.Now().Add(24 * time.Hour).UTC(),
			})
		case "/api/v1/agents/identity/activate":
			mu.Lock()
			activateHasCertificate = hasCertificate
			mu.Unlock()
			if !hasCertificate {
				http.Error(w, "client certificate required", http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
		default:
			http.NotFound(w, r)
		}
	}))
	server.StartTLS()
	defer server.Close()
	server.TLS.ClientAuth = tls.RequestClientCert

	roots := x509.NewCertPool()
	roots.AddCert(server.Certificate())
	client := NewServerClientWithName(server.URL, "agent-1", "", "", "", false)
	transport := client.HTTPClient.Transport.(*http.Transport)
	baseTLS := transport.TLSClientConfig.Clone()
	baseTLS.RootCAs = roots
	transport.TLSClientConfig = baseTLS

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pending, err := client.RegisterWithMTLS(ctx, "join-token", "csr", "1.0.0", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("register mTLS: %v", err)
	}
	identity, err := BuildClientIdentity(pending.CredentialID, pending.ExpiresAt, pending.ClientCertificate, clientKeyPEM)
	if err != nil {
		t.Fatalf("build client identity: %v", err)
	}
	oldTransport := client.HTTPClient.Transport
	if err := client.SetClientIdentity(identity); err != nil {
		t.Fatalf("install client identity: %v", err)
	}
	if client.HTTPClient.Transport == oldTransport {
		t.Fatal("SetClientIdentity reused the already-used HTTP transport")
	}
	if err := client.ActivateMTLS(ctx); err != nil {
		t.Fatalf("activate mTLS: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if registerHasCertificate {
		t.Fatal("bootstrap registration unexpectedly presented a client certificate")
	}
	if !activateHasCertificate {
		t.Fatal("activation did not present the newly installed client certificate")
	}
}

func TestFreshEnrollmentResponseLossRecoversPersistedAttempt(t *testing.T) {
	dataDir := t.TempDir()
	attempt, err := CreateEnrollmentAttempt(dataDir, "agent-recovery")
	if err != nil {
		t.Fatal(err)
	}
	certificatePEM, _ := testIdentityMaterial(t, "server-issued")
	var calls int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			AgentID             string `json:"agent_id"`
			CSR                 string `json:"csr"`
			EnrollmentAttemptID string `json:"enrollment_attempt_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil || request.AgentID != "agent-recovery" || request.CSR != string(attempt.CSRPEM) || request.EnrollmentAttemptID != attempt.EnrollmentAttemptID {
			http.Error(w, "invalid enrollment request", http.StatusBadRequest)
			return
		}
		calls++
		if calls == 1 {
			// Simulate a committed server transaction whose response is lost.
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "hijacking unavailable", http.StatusInternalServerError)
				return
			}
			conn, _, hijackErr := hijacker.Hijack()
			if hijackErr == nil {
				_ = conn.Close()
			}
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"success":            true,
			"credential_id":      "recovered-credential",
			"tenant_id":          "tenant-recovery",
			"agent_id":           "agent-recovery",
			"client_certificate": string(certificatePEM),
			"expires_at":         time.Now().Add(time.Hour).UTC(),
		})
	}))
	defer server.Close()
	newClient := func() *ServerClient {
		client := NewServerClientWithName(server.URL, "agent-recovery", "", "", "", false)
		transport := client.HTTPClient.Transport.(*http.Transport)
		baseTLS := transport.TLSClientConfig.Clone()
		baseTLS.RootCAs = x509.NewCertPool()
		baseTLS.RootCAs.AddCert(server.Certificate())
		transport.TLSClientConfig = baseTLS
		return client
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	firstClient := newClient()
	if _, err := firstClient.RegisterWithMTLS(ctx, "join-token", string(attempt.CSRPEM), "1.0.0", attempt.EnrollmentAttemptID); err == nil {
		t.Fatal("response-loss request unexpectedly succeeded")
	}
	restartedAttempt, err := LoadEnrollmentAttempt(dataDir, "agent-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if restartedAttempt == nil || restartedAttempt.EnrollmentAttemptID != attempt.EnrollmentAttemptID || string(restartedAttempt.CSRPEM) != string(attempt.CSRPEM) || string(restartedAttempt.PrivateKeyPEM) != string(attempt.PrivateKeyPEM) {
		t.Fatal("restart did not recover the exact pre-enrollment attempt")
	}
	registration, err := newClient().RegisterWithMTLS(ctx, "join-token", string(restartedAttempt.CSRPEM), "1.0.0", restartedAttempt.EnrollmentAttemptID)
	if err != nil {
		t.Fatalf("recovery retry failed: %v", err)
	}
	if registration.CredentialID != "recovered-credential" || calls != 2 {
		t.Fatalf("recovery did not return the committed logical result: credential=%s calls=%d", registration.CredentialID, calls)
	}
}
