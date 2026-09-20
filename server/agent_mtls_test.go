package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	wscommon "printmaster/common/ws"
	"printmaster/server/storage"
)

type agentMTLSTestFixture struct {
	store      *storage.SQLiteStore
	manager    *agentCertificateManager
	agent      *storage.Agent
	credential *storage.AgentCredential
	cert       *x509.Certificate
}

func newAgentMTLSTestFixture(t *testing.T, agentID, tenantID, token string) *agentMTLSTestFixture {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PrintMaster Agent Test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyDER, _ := x509.MarshalPKCS8PrivateKey(caKey)
	manager, err := newAgentCertificateManager(caCertPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: caKeyDER}), 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	store, err := storage.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	agent := &storage.Agent{AgentID: agentID, Name: agentID, Hostname: "host", Platform: "windows", ProtocolVersion: "1", Status: "active", TenantID: tenantID, Token: token, RegisteredAt: now, LastSeen: now}
	if token != "" {
		if err := store.RegisterAgent(context.Background(), agent); err != nil {
			t.Fatal(err)
		}
	}
	fixture := &agentMTLSTestFixture{store: store, manager: manager, agent: agent}
	if err := store.CreateTenant(context.Background(), &storage.Tenant{ID: tenantID, Name: tenantID}); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func (f *agentMTLSTestFixture) enroll(t *testing.T) {
	t.Helper()
	_, rawJoin, err := f.store.CreateJoinToken(context.Background(), f.agent.TenantID, 30, true)
	if err != nil {
		t.Fatal(err)
	}
	pendingKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "test agent"}}, pendingKey)
	if err != nil {
		t.Fatal(err)
	}
	credentialID := "credential-" + f.agent.AgentID
	var certPEM []byte
	_, credential, err := f.store.EnrollAgentWithCredential(context.Background(), rawJoin, f.agent, func(join *storage.JoinToken, agent *storage.Agent) (*storage.AgentCredential, error) {
		var issueErr error
		issuedCredential, issuedPEM, issueErr := f.manager.issue(agent.AgentID, join.TenantID, credentialID, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
		certPEM = issuedPEM
		return issuedCredential, issueErr
	})
	if err != nil {
		t.Fatal(err)
	}
	f.credential = credential
	f.cert, err = x509.ParseCertificate(pemBlockBytes(t, certPEM))
	if err != nil {
		t.Fatal(err)
	}
}

func pemBlockBytes(t *testing.T, data []byte) []byte {
	t.Helper()
	block, _ := pem.Decode(data)
	if block == nil {
		t.Fatal("certificate PEM missing")
	}
	return block.Bytes
}

func tlsRequest(cert *x509.Certificate) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://printmaster.test/api/v1/agents/heartbeat", bytes.NewReader([]byte(`{"agent_id":"body-does-not-control-identity","status":"active"}`)))
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	return r
}

func TestP001WrongAgentIdentityUsesCertificateBinding(t *testing.T) {
	f := newAgentMTLSTestFixture(t, "agent-right", "tenant-a", "")
	defer f.store.Close()
	f.enroll(t)
	oldConfig, oldStore, oldManager := serverConfig, serverStore, agentMTLSManager
	defer func() { serverConfig, serverStore, agentMTLSManager = oldConfig, oldStore, oldManager }()
	serverConfig = &Config{Security: SecurityConfig{AgentAuthMode: agentAuthModeMTLS}}
	serverStore, agentMTLSManager = f.store, f.manager
	rr := httptest.NewRecorder()
	requireAuth(handleAgentHeartbeat)(rr, tlsRequest(f.cert))
	if rr.Code != http.StatusOK {
		t.Fatalf("mTLS heartbeat rejected: %d %s", rr.Code, rr.Body.String())
	}
	if got, err := f.store.GetAgent(context.Background(), "agent-right"); err != nil || got.LastSeen.IsZero() {
		t.Fatalf("certificate-bound agent was not updated: %v", err)
	}
}

func TestP001WrongTenantCertificateRejected(t *testing.T) {
	f := newAgentMTLSTestFixture(t, "agent-tenant-a", "tenant-a", "")
	defer f.store.Close()
	f.enroll(t)
	csrKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, csrKey)
	wrongCredential, wrongPEM, err := f.manager.issue(f.agent.AgentID, "tenant-b", "wrong-tenant-credential", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.CreateAgentCredential(context.Background(), wrongCredential); err != nil {
		t.Fatal(err)
	}
	wrongCert, _ := x509.ParseCertificate(pemBlockBytes(t, wrongPEM))
	if _, err := f.manager.authenticate(context.Background(), tlsRequest(wrongCert), f.store); err == nil {
		t.Fatal("wrong tenant certificate accepted")
	}
}

func TestP001ExpiredAndRevokedCertificatesRejected(t *testing.T) {
	f := newAgentMTLSTestFixture(t, "agent-lifecycle", "tenant-a", "")
	defer f.store.Close()
	f.enroll(t)
	if _, err := f.manager.authenticate(context.Background(), tlsRequest(f.cert), f.store); err != nil {
		t.Fatalf("fresh certificate rejected: %v", err)
	}
	if _, err := f.store.DB().Exec("UPDATE agent_credentials SET expires_at = ? WHERE credential_id = ?", time.Now().UTC().Add(-time.Minute), f.credential.CredentialID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.manager.authenticate(context.Background(), tlsRequest(f.cert), f.store); err == nil {
		t.Fatal("expired credential accepted")
	}
	// Re-enroll a second identity for the revocation assertion.
	f2 := newAgentMTLSTestFixture(t, "agent-revoked", "tenant-a", "")
	defer f2.store.Close()
	f2.enroll(t)
	if err := f2.store.RevokeAgentCredential(context.Background(), f2.credential.CredentialID, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := f2.manager.authenticate(context.Background(), tlsRequest(f2.cert), f2.store); err == nil {
		t.Fatal("revoked certificate accepted")
	}
}

func TestP001ActiveWebSocketCredentialRevocation(t *testing.T) {
	oldConnections, oldCredentials := wsConnections, wsConnectionCredentials
	defer func() { wsConnections, wsConnectionCredentials = oldConnections, oldCredentials }()
	wsConnections = map[string]*wscommon.Conn{"agent-active": nil}
	wsConnectionCredentials = map[string]string{"agent-active": "credential-active"}
	closeAgentWebSocketForCredential("credential-active")
	if _, ok := wsConnections["agent-active"]; ok {
		t.Fatal("active WebSocket credential was not removed")
	}
	if _, ok := wsConnectionCredentials["agent-active"]; ok {
		t.Fatal("active WebSocket credential index was not removed")
	}
}

func TestP001LegacyBearerMigrationAndActivation(t *testing.T) {
	f := newAgentMTLSTestFixture(t, "agent-migrate", "tenant-a", "legacy-secret")
	defer f.store.Close()
	oldConfig, oldStore, oldManager := serverConfig, serverStore, agentMTLSManager
	defer func() { serverConfig, serverStore, agentMTLSManager = oldConfig, oldStore, oldManager }()
	serverConfig = &Config{Security: SecurityConfig{AgentAuthMode: agentAuthModeMigration}}
	serverStore, agentMTLSManager = f.store, f.manager
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	csrDER, _ := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	body, _ := json.Marshal(map[string]string{"csr": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))})
	r := httptest.NewRequest(http.MethodPost, "/api/v1/agents/identity/migrate", bytes.NewReader(body))
	r.Header.Set("Authorization", "Bearer legacy-secret")
	rr := httptest.NewRecorder()
	handleAgentIdentityMigrate(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("migration failed: %d %s", rr.Code, rr.Body.String())
	}
	var response struct {
		CredentialID      string    `json:"credential_id"`
		ClientCertificate string    `json:"client_certificate"`
		ExpiresAt         time.Time `json:"expires_at"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.CredentialID == "" || response.ClientCertificate == "" {
		t.Fatal("migration response missing certificate")
	}
	migratedCert, err := x509.ParseCertificate(pemBlockBytes(t, []byte(response.ClientCertificate)))
	if err != nil {
		t.Fatal(err)
	}
	activate := httptest.NewRequest(http.MethodPost, "/api/v1/agents/identity/activate", strings.NewReader(`{}`))
	activate.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{migratedCert}}
	activateRR := httptest.NewRecorder()
	handleAgentIdentityActivate(activateRR, activate)
	if activateRR.Code != http.StatusOK {
		t.Fatalf("mTLS activation failed: %d %s", activateRR.Code, activateRR.Body.String())
	}
	if _, err := f.manager.authenticate(context.Background(), activate, f.store); err != nil {
		t.Fatalf("migrated certificate was not usable after activation: %v", err)
	}
	if _, err := f.store.GetAgentByToken(context.Background(), "legacy-secret"); err == nil {
		t.Fatal("legacy bearer remained usable after activation")
	}
	// Activation is safe to retry when the first response was lost after the
	// server committed the credential transition.
	retry := httptest.NewRecorder()
	handleAgentIdentityActivate(retry, activate)
	if retry.Code != http.StatusOK {
		t.Fatalf("idempotent mTLS activation failed: %d %s", retry.Code, retry.Body.String())
	}
}

func TestP001MigrationDoesNotFallBackFromPresentedCertificateToBearer(t *testing.T) {
	f := newAgentMTLSTestFixture(t, "agent-migration-fallback", "tenant-a", "legacy-secret")
	defer f.store.Close()
	oldConfig, oldStore, oldManager := serverConfig, serverStore, agentMTLSManager
	defer func() { serverConfig, serverStore, agentMTLSManager = oldConfig, oldStore, oldManager }()
	serverConfig = &Config{Security: SecurityConfig{AgentAuthMode: agentAuthModeMigration}}
	serverStore, agentMTLSManager = f.store, f.manager

	r := httptest.NewRequest(http.MethodPost, "/api/v1/agents/identity/migrate", strings.NewReader(`{"csr":"not-used"}`))
	r.Header.Set("Authorization", "Bearer legacy-secret")
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{SerialNumber: big.NewInt(99)}}}
	rr := httptest.NewRecorder()
	handleAgentIdentityMigrate(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("migration accepted bearer alongside presented certificate: %d %s", rr.Code, rr.Body.String())
	}
}

func TestP001BearerRejectedWhenMTLSModeEnabled(t *testing.T) {
	f := newAgentMTLSTestFixture(t, "agent-bearer-off", "tenant-a", "legacy-secret")
	defer f.store.Close()
	oldConfig, oldStore, oldManager := serverConfig, serverStore, agentMTLSManager
	defer func() { serverConfig, serverStore, agentMTLSManager = oldConfig, oldStore, oldManager }()
	serverConfig = &Config{Security: SecurityConfig{AgentAuthMode: agentAuthModeMTLS}}
	serverStore, agentMTLSManager = f.store, f.manager
	r := httptest.NewRequest(http.MethodPost, "/api/v1/agents/heartbeat", strings.NewReader(`{"agent_id":"agent-bearer-off"}`))
	r.Header.Set("Authorization", "Bearer legacy-secret")
	rr := httptest.NewRecorder()
	requireAuth(handleAgentHeartbeat)(rr, r)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("bearer accepted in mtls mode: %d", rr.Code)
	}
	wsReq := httptest.NewRequest(http.MethodGet, "/api/v1/agents/ws", nil)
	wsReq.Header.Set("Authorization", "Bearer legacy-secret")
	wsRR := httptest.NewRecorder()
	handleAgentWebSocket(wsRR, wsReq, f.store)
	if wsRR.Code != http.StatusUnauthorized {
		t.Fatalf("WebSocket bearer accepted in mtls mode: %d", wsRR.Code)
	}
}

func TestP001DatabaseDoesNotStoreReusableAgentBearer(t *testing.T) {
	f := newAgentMTLSTestFixture(t, "agent-db-dump", "tenant-a", "legacy-secret")
	defer f.store.Close()

	var rawToken, tokenHash string
	if err := f.store.DB().QueryRow("SELECT token, legacy_token_hash FROM agents WHERE agent_id = ?", f.agent.AgentID).Scan(&rawToken, &tokenHash); err != nil {
		t.Fatal(err)
	}
	if rawToken != "" {
		t.Fatalf("database still contains raw bearer token")
	}
	expected := sha256.Sum256([]byte("legacy-secret"))
	if tokenHash != hex.EncodeToString(expected[:]) || tokenHash == "legacy-secret" {
		t.Fatalf("legacy bearer was not stored as a one-way hash")
	}
	for _, table := range []string{"agent_credentials", "agent_enrollment_attempts"} {
		var privateKeyColumns int
		query := "SELECT COUNT(*) FROM pragma_table_info('" + table + "') WHERE lower(name) LIKE '%private%' OR lower(name) LIKE '%key_pem%'"
		if err := f.store.DB().QueryRow(query).Scan(&privateKeyColumns); err != nil {
			t.Fatal(err)
		}
		if privateKeyColumns != 0 {
			t.Fatalf("%s schema exposes private-key columns", table)
		}
	}
}

func TestP001FreshEnrollmentResponseLossRecoversSameCertificate(t *testing.T) {
	f := newAgentMTLSTestFixture(t, "agent-response-loss", "tenant-a", "")
	defer f.store.Close()
	oldConfig, oldStore, oldManager := serverConfig, serverStore, agentMTLSManager
	defer func() { serverConfig, serverStore, agentMTLSManager = oldConfig, oldStore, oldManager }()
	serverConfig, serverStore, agentMTLSManager = &Config{Security: SecurityConfig{AgentAuthMode: agentAuthModeMigration}}, f.store, f.manager
	_, joinToken, err := f.store.CreateJoinToken(context.Background(), "tenant-a", 30, true)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "response-loss"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	csr := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	body := func() *bytes.Reader {
		payload, _ := json.Marshal(map[string]string{
			"token":                 joinToken,
			"agent_id":              f.agent.AgentID,
			"csr":                   csr,
			"enrollment_attempt_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		})
		return bytes.NewReader(payload)
	}
	first := httptest.NewRecorder()
	handleAgentMTLSRegister(first, httptest.NewRequest(http.MethodPost, "/api/v1/agents/register-mtls", body()))
	if first.Code != http.StatusOK {
		t.Fatalf("first enrollment failed: %d %s", first.Code, first.Body.String())
	}
	// Simulate a response dropped after the server transaction committed.
	second := httptest.NewRecorder()
	handleAgentMTLSRegister(second, httptest.NewRequest(http.MethodPost, "/api/v1/agents/register-mtls", body()))
	if second.Code != http.StatusOK {
		t.Fatalf("response-loss retry failed: %d %s", second.Code, second.Body.String())
	}
	var firstResponse, secondResponse struct {
		CredentialID      string `json:"credential_id"`
		ClientCertificate string `json:"client_certificate"`
	}
	if err := json.Unmarshal(first.Body.Bytes(), &firstResponse); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(second.Body.Bytes(), &secondResponse); err != nil {
		t.Fatal(err)
	}
	if firstResponse.CredentialID == "" || firstResponse.CredentialID != secondResponse.CredentialID || firstResponse.ClientCertificate != secondResponse.ClientCertificate {
		t.Fatal("response-loss retry returned a different certificate identity")
	}
	var credentialCount, attemptCount int
	if err := f.store.DB().QueryRow("SELECT COUNT(*) FROM agent_credentials").Scan(&credentialCount); err != nil {
		t.Fatal(err)
	}
	if err := f.store.DB().QueryRow("SELECT COUNT(*) FROM agent_enrollment_attempts").Scan(&attemptCount); err != nil {
		t.Fatal(err)
	}
	if credentialCount != 1 || attemptCount != 1 {
		t.Fatalf("response-loss retry issued duplicate credentials: credentials=%d attempts=%d", credentialCount, attemptCount)
	}
}
