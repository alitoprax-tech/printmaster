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
	pending, err := client.RegisterWithMTLS(ctx, "join-token", "csr", "1.0.0")
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
