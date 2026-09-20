package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"printmaster/agent/agent"
)

func workerTestIdentityMaterial(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}
	now := time.Now().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "pending-agent"},
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestPendingActivationIsRetriedWithoutDeletingIdentity(t *testing.T) {
	var activations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/agents/identity/activate" {
			http.NotFound(w, r)
			return
		}
		if activations.Add(1) == 1 {
			// Simulate the server committing activation before the response is
			// lost. The second request must be safe and idempotent.
			http.Error(w, "response lost after commit", http.StatusBadGateway)
			return
		}
		_ = writeJSON(w, map[string]bool{"success": true})
	}))
	defer server.Close()

	dataDir := t.TempDir()
	certPEM, keyPEM := workerTestIdentityMaterial(t)
	clientIdentity, err := agent.BuildClientIdentity("credential-1", time.Now().Add(24*time.Hour), certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build identity: %v", err)
	}
	clientIdentity.TenantID = "tenant-1"
	if err := agent.SavePendingClientIdentity(dataDir, clientIdentity, certPEM, keyPEM); err != nil {
		t.Fatalf("save pending identity: %v", err)
	}

	client := agent.NewServerClient(server.URL, "agent-1", "")
	worker := NewUploadWorker(client, nil, nil, nil, UploadWorkerConfig{UseWebSocket: false}, dataDir)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pending, err := agent.LoadPendingClientIdentity(dataDir)
	if err != nil || pending == nil {
		t.Fatalf("load pending identity: %v", err)
	}
	if activated, err := worker.activatePendingMTLS(ctx, pending); activated || err == nil {
		t.Fatalf("first activation should retain pending state, activated=%v err=%v", activated, err)
	}
	if client.HasClientIdentity() {
		t.Fatal("failed activation should restore the previous in-memory identity")
	}
	if pending, err := agent.LoadPendingClientIdentity(dataDir); err != nil || pending == nil {
		t.Fatalf("pending identity was deleted after activation error: identity=%#v err=%v", pending, err)
	}

	pending, err = agent.LoadPendingClientIdentity(dataDir)
	if err != nil || pending == nil {
		t.Fatalf("reload pending identity: %v", err)
	}
	if activated, err := worker.activatePendingMTLS(ctx, pending); !activated || err != nil {
		t.Fatalf("retry activation failed: activated=%v err=%v", activated, err)
	}
	if active, err := agent.LoadClientIdentity(dataDir); err != nil || active == nil || active.CredentialID != "credential-1" {
		t.Fatalf("pending identity was not promoted: identity=%#v err=%v", active, err)
	}
	if pending, err := agent.LoadPendingClientIdentity(dataDir); err != nil || pending != nil {
		t.Fatalf("pending identity remained after successful retry: identity=%#v err=%v", pending, err)
	}
}

func writeJSON(w http.ResponseWriter, value interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(value)
}
