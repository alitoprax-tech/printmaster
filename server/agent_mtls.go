package main

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	authz "printmaster/server/authz"
	"printmaster/server/storage"
)

const (
	agentAuthModeLegacy    = "legacy"
	agentAuthModeMigration = "migration"
	agentAuthModeMTLS      = "mtls"
	defaultAgentCertTTL    = 90 * 24 * time.Hour
	minAgentCertTTL        = time.Hour
	maxAgentCertTTL        = 365 * 24 * time.Hour
)

var (
	agentMTLSManager          *agentCertificateManager
	agentCredentialContextKey contextKey = "agent_credential"
)

// agentCertificateManager owns only the Agent CA. It is intentionally
// separate from the server TLS certificate and from release-signing keys.
type agentCertificateManager struct {
	caCert *x509.Certificate
	caKey  crypto.Signer
	caPool *x509.CertPool
	ttl    time.Duration
}

type agentCertificateIdentity struct {
	TenantID     string
	AgentID      string
	CredentialID string
}

type agentPrincipal struct {
	Agent      *storage.Agent
	Credential *storage.AgentCredential
}

func newAgentCertificateManager(certPEM, keyPEM []byte, ttl time.Duration) (*agentCertificateManager, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load Agent CA key pair: %w", err)
	}
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("Agent CA certificate missing")
	}
	caKey, ok := pair.PrivateKey.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("Agent CA private key is not a signing key")
	}
	caCert, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse Agent CA certificate: %w", err)
	}
	if !caCert.IsCA || !caCert.BasicConstraintsValid || caCert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("Agent CA must be a CA certificate with certificate-signing usage")
	}
	if ttl <= 0 {
		ttl = defaultAgentCertTTL
	}
	if ttl < minAgentCertTTL || ttl > maxAgentCertTTL {
		return nil, fmt.Errorf("Agent certificate TTL must be between %s and %s", minAgentCertTTL, maxAgentCertTTL)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &agentCertificateManager{caCert: caCert, caKey: caKey, caPool: pool, ttl: ttl}, nil
}

func (m *agentCertificateManager) issue(agentID, tenantID, credentialID string, csrPEM []byte) (*storage.AgentCredential, []byte, error) {
	if m == nil || m.caCert == nil || m.caKey == nil {
		return nil, nil, fmt.Errorf("Agent CA is not configured")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, nil, fmt.Errorf("valid PEM certificate request required")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("certificate request signature invalid: %w", err)
	}
	if strings.TrimSpace(agentID) == "" || strings.TrimSpace(tenantID) == "" || strings.TrimSpace(credentialID) == "" {
		return nil, nil, fmt.Errorf("certificate identity fields required")
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 160))
	if err != nil {
		return nil, nil, fmt.Errorf("generate certificate serial: %w", err)
	}
	now := time.Now().UTC()
	identityURI, err := agentIdentityURI(tenantID, agentID, credentialID)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{Organization: []string{"PrintMaster Agent"}, CommonName: "PrintMaster Agent"},
		NotBefore:             now.Add(-2 * time.Minute),
		NotAfter:              now.Add(m.ttl),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		AuthorityKeyId:        m.caCert.SubjectKeyId,
		URIs:                  []*url.URL{identityURI},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, m.caCert, csr.PublicKey, m.caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("sign Agent certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse issued Agent certificate: %w", err)
	}
	pubHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	credential := &storage.AgentCredential{
		CredentialID:      credentialID,
		AgentID:           agentID,
		TenantID:          tenantID,
		CertificateSerial: cert.SerialNumber.Text(16),
		PublicKeySHA256:   hex.EncodeToString(pubHash[:]),
		IssuedAt:          cert.NotBefore,
		ExpiresAt:         cert.NotAfter,
	}
	return credential, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func agentIdentityURI(tenantID, agentID, credentialID string) (*url.URL, error) {
	encode := func(v string) string { return base64.RawURLEncoding.EncodeToString([]byte(v)) }
	return url.Parse("spiffe://printmaster/tenant/" + encode(tenantID) + "/agent/" + encode(agentID) + "/credential/" + encode(credentialID))
}

func parseAgentIdentity(cert *x509.Certificate) (agentCertificateIdentity, error) {
	if cert == nil || len(cert.URIs) != 1 {
		return agentCertificateIdentity{}, fmt.Errorf("Agent certificate identity URI missing")
	}
	u := cert.URIs[0]
	if u.Scheme != "spiffe" || u.Host != "printmaster" {
		return agentCertificateIdentity{}, fmt.Errorf("Agent certificate identity URI is not trusted")
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) != 6 || parts[0] != "tenant" || parts[2] != "agent" || parts[4] != "credential" {
		return agentCertificateIdentity{}, fmt.Errorf("Agent certificate identity URI malformed")
	}
	decode := func(v string) (string, error) {
		b, err := base64.RawURLEncoding.DecodeString(v)
		if err != nil || len(b) == 0 {
			return "", fmt.Errorf("invalid encoded identity")
		}
		return string(b), nil
	}
	tenantID, err := decode(parts[1])
	if err != nil {
		return agentCertificateIdentity{}, err
	}
	agentID, err := decode(parts[3])
	if err != nil {
		return agentCertificateIdentity{}, err
	}
	credentialID, err := decode(parts[5])
	if err != nil {
		return agentCertificateIdentity{}, err
	}
	return agentCertificateIdentity{TenantID: tenantID, AgentID: agentID, CredentialID: credentialID}, nil
}

func (m *agentCertificateManager) authenticate(ctx context.Context, r *http.Request, store storage.Store) (*agentPrincipal, error) {
	if m == nil || r == nil || r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("mTLS client certificate required")
	}
	cert := r.TLS.PeerCertificates[0]
	intermediates := x509.NewCertPool()
	for _, intermediate := range r.TLS.PeerCertificates[1:] {
		intermediates.AddCert(intermediate)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: m.caPool, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: time.Now().UTC()}); err != nil {
		return nil, fmt.Errorf("Agent certificate verification failed: %w", err)
	}
	identity, err := parseAgentIdentity(cert)
	if err != nil {
		return nil, err
	}
	credentialStore, ok := store.(storage.AgentCredentialStore)
	if !ok {
		return nil, fmt.Errorf("storage does not support Agent credentials")
	}
	credential, err := credentialStore.GetAgentCredential(ctx, identity.CredentialID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if credential.RevokedAt != nil {
		return nil, fmt.Errorf("Agent certificate revoked")
	}
	if !now.Before(credential.ExpiresAt) {
		return nil, fmt.Errorf("Agent certificate expired")
	}
	if credential.AgentID != identity.AgentID || credential.TenantID != identity.TenantID ||
		strings.ToLower(credential.CertificateSerial) != strings.ToLower(cert.SerialNumber.Text(16)) {
		return nil, fmt.Errorf("Agent certificate identity does not match credential")
	}
	pubHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if !strings.EqualFold(credential.PublicKeySHA256, hex.EncodeToString(pubHash[:])) {
		return nil, fmt.Errorf("Agent certificate public key does not match credential")
	}
	agent, err := store.GetAgent(ctx, identity.AgentID)
	if err != nil {
		return nil, err
	}
	if agent.TenantID != identity.TenantID || credential.AgentID != agent.AgentID {
		return nil, fmt.Errorf("Agent certificate tenant binding mismatch")
	}
	return &agentPrincipal{Agent: agent, Credential: credential}, nil
}

func currentAgentAuthMode() string {
	if serverConfig == nil {
		return agentAuthModeLegacy
	}
	mode := strings.ToLower(strings.TrimSpace(serverConfig.Security.AgentAuthMode))
	if mode == "" {
		return agentAuthModeLegacy
	}
	return mode
}

func configureAgentAuth(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("server configuration unavailable")
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Security.AgentAuthMode))
	if mode == "" {
		mode = agentAuthModeLegacy
		cfg.Security.AgentAuthMode = mode
	}
	if mode != agentAuthModeLegacy && mode != agentAuthModeMigration && mode != agentAuthModeMTLS {
		return fmt.Errorf("invalid security.agent_auth_mode %q", mode)
	}
	agentMTLSManager = nil
	if mode == agentAuthModeLegacy {
		return nil
	}
	if cfg.Server.BehindProxy && !cfg.Server.ProxyUseHTTPS {
		return fmt.Errorf("Agent mTLS requires server.proxy_use_https=true when behind a reverse proxy")
	}
	if strings.TrimSpace(cfg.Security.AgentCACertPath) == "" || strings.TrimSpace(cfg.Security.AgentCAKeyPath) == "" {
		return fmt.Errorf("Agent CA certificate and key paths are required in %s mode", mode)
	}
	if sameFilePath(cfg.Security.AgentCACertPath, cfg.TLS.CertPath) || sameFilePath(cfg.Security.AgentCAKeyPath, cfg.TLS.KeyPath) {
		return fmt.Errorf("Agent CA files must be separate from the server TLS certificate and key")
	}
	certPEM, err := os.ReadFile(cfg.Security.AgentCACertPath)
	if err != nil {
		return fmt.Errorf("read Agent CA certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(cfg.Security.AgentCAKeyPath)
	if err != nil {
		return fmt.Errorf("read Agent CA key: %w", err)
	}
	ttl := time.Duration(cfg.Security.AgentCertificateTTLHours) * time.Hour
	m, err := newAgentCertificateManager(certPEM, keyPEM, ttl)
	if err != nil {
		return err
	}
	agentMTLSManager = m
	return nil
}

func sameFilePath(left, right string) bool {
	left = strings.TrimSpace(left)
	right = strings.TrimSpace(right)
	if left == "" || right == "" {
		return false
	}
	absLeft, leftErr := filepath.Abs(filepath.Clean(left))
	absRight, rightErr := filepath.Abs(filepath.Clean(right))
	if leftErr != nil || rightErr != nil {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return strings.EqualFold(absLeft, absRight)
}

func extractBearerToken(r *http.Request) string {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
		return parts[1]
	}
	return ""
}

// authenticateAgentRequest is shared by HTTP and WebSocket paths. A supplied
// client certificate is transport-authoritative: an invalid certificate never
// falls back to a bearer token from the same request.
func authenticateAgentRequest(ctx context.Context, r *http.Request, store storage.Store) (*agentPrincipal, error) {
	mode := currentAgentAuthMode()
	if mode != agentAuthModeLegacy && r != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return agentMTLSManager.authenticate(ctx, r, store)
	}
	if mode == agentAuthModeMTLS {
		return nil, fmt.Errorf("mTLS client certificate required")
	}
	token := extractBearerToken(r)
	if token == "" {
		return nil, fmt.Errorf("bearer token required")
	}
	agent, err := store.GetAgentByToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return &agentPrincipal{Agent: agent}, nil
}

func newAgentCredentialID() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func decodeCSRRequest(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	var in struct {
		CSR string `json:"csr"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	if err := decoder.Decode(&in); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	if strings.TrimSpace(in.CSR) == "" {
		return nil, fmt.Errorf("csr required")
	}
	return []byte(in.CSR), nil
}

func writeAgentCertificateResponse(w http.ResponseWriter, credential *storage.AgentCredential, certificatePEM []byte) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success":            true,
		"credential_id":      credential.CredentialID,
		"tenant_id":          credential.TenantID,
		"agent_id":           credential.AgentID,
		"client_certificate": string(certificatePEM),
		"expires_at":         credential.ExpiresAt.UTC().Format(time.RFC3339),
	})
}

func handleAgentMTLSRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if currentAgentAuthMode() == agentAuthModeLegacy || agentMTLSManager == nil {
		http.Error(w, "mTLS enrollment is disabled", http.StatusNotFound)
		return
	}
	if serverStore == nil {
		http.Error(w, "storage unavailable", http.StatusInternalServerError)
		return
	}
	var in struct {
		Token           string `json:"token"`
		AgentID         string `json:"agent_id"`
		Name            string `json:"name,omitempty"`
		AgentVersion    string `json:"agent_version,omitempty"`
		ProtocolVersion string `json:"protocol_version,omitempty"`
		Hostname        string `json:"hostname,omitempty"`
		IP              string `json:"ip,omitempty"`
		Platform        string `json:"platform,omitempty"`
		OSVersion       string `json:"os_version,omitempty"`
		GoVersion       string `json:"go_version,omitempty"`
		Architecture    string `json:"architecture,omitempty"`
		NumCPU          int    `json:"num_cpu,omitempty"`
		TotalMemoryMB   int64  `json:"total_memory_mb,omitempty"`
		BuildType       string `json:"build_type,omitempty"`
		GitCommit       string `json:"git_commit,omitempty"`
		CSR             string `json:"csr"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if strings.TrimSpace(in.Token) == "" || strings.TrimSpace(in.AgentID) == "" || strings.TrimSpace(in.CSR) == "" {
		http.Error(w, "token, agent_id and csr required", http.StatusBadRequest)
		return
	}
	credentialStore, ok := serverStore.(storage.AgentCredentialStore)
	if !ok {
		http.Error(w, "mTLS storage unavailable", http.StatusNotImplemented)
		return
	}
	credentialID, err := newAgentCredentialID()
	if err != nil {
		http.Error(w, "credential generation failed", http.StatusInternalServerError)
		return
	}
	now := time.Now().UTC()
	agent := &storage.Agent{AgentID: strings.TrimSpace(in.AgentID), Name: in.Name, Hostname: in.Hostname, IP: in.IP, Platform: in.Platform, Version: in.AgentVersion, ProtocolVersion: in.ProtocolVersion, RegisteredAt: now, LastSeen: now, Status: "active", OSVersion: in.OSVersion, GoVersion: in.GoVersion, Architecture: in.Architecture, NumCPU: in.NumCPU, TotalMemoryMB: in.TotalMemoryMB, BuildType: in.BuildType, GitCommit: in.GitCommit}
	var issuedCertificate []byte
	join, credential, err := credentialStore.EnrollAgentWithCredential(r.Context(), in.Token, agent, func(join *storage.JoinToken, registered *storage.Agent) (*storage.AgentCredential, error) {
		cred, certificatePEM, err := agentMTLSManager.issue(registered.AgentID, join.TenantID, credentialID, []byte(in.CSR))
		issuedCertificate = certificatePEM
		return cred, err
	})
	if err != nil {
		http.Error(w, "enrollment failed: "+err.Error(), http.StatusUnauthorized)
		return
	}
	if len(issuedCertificate) == 0 || credential == nil || join == nil {
		http.Error(w, "certificate response unavailable", http.StatusInternalServerError)
		return
	}
	writeAgentCertificateResponse(w, credential, issuedCertificate)
}

// handleAgentIdentityMigrate upgrades an existing bearer identity while the
// server is in migration mode. The bearer remains valid until activate is
// called with the newly installed certificate.
func handleAgentIdentityMigrate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if currentAgentAuthMode() != agentAuthModeMigration || agentMTLSManager == nil {
		http.Error(w, "migration mode is disabled", http.StatusNotFound)
		return
	}
	principal, err := authenticateLegacyBearer(r.Context(), r)
	if err != nil {
		http.Error(w, "invalid legacy bearer", http.StatusUnauthorized)
		return
	}
	csrPEM, err := decodeCSRRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	credentialID, err := newAgentCredentialID()
	if err != nil {
		http.Error(w, "credential generation failed", http.StatusInternalServerError)
		return
	}
	credential, certificatePEM, err := agentMTLSManager.issue(principal.Agent.AgentID, principal.Agent.TenantID, credentialID, csrPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	store, ok := serverStore.(storage.AgentCredentialStore)
	if !ok {
		http.Error(w, "mTLS storage unavailable", http.StatusNotImplemented)
		return
	}
	if err := store.CreateAgentCredential(r.Context(), credential); err != nil {
		http.Error(w, "store credential failed", http.StatusInternalServerError)
		return
	}
	writeAgentCertificateResponse(w, credential, certificatePEM)
}

func authenticateLegacyBearer(ctx context.Context, r *http.Request) (*agentPrincipal, error) {
	// Migration deliberately uses the legacy bearer only as a bootstrap
	// credential. If a client certificate is present, it is transport-
	// authoritative; never accept a bearer alongside an invalid/stale cert.
	if currentAgentAuthMode() != agentAuthModeLegacy && r != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
		return nil, fmt.Errorf("client certificate must be omitted during bearer migration")
	}
	token := extractBearerToken(r)
	if token == "" {
		return nil, fmt.Errorf("bearer token required")
	}
	if serverStore == nil {
		return nil, fmt.Errorf("storage unavailable")
	}
	agent, err := serverStore.GetAgentByToken(ctx, token)
	if err != nil {
		return nil, err
	}
	return &agentPrincipal{Agent: agent}, nil
}

func handleAgentIdentityRenew(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if agentMTLSManager == nil || currentAgentAuthMode() == agentAuthModeLegacy {
		http.Error(w, "mTLS is disabled", http.StatusNotFound)
		return
	}
	principal, err := authenticateAgentRequest(r.Context(), r, serverStore)
	if err != nil || principal.Credential == nil {
		http.Error(w, "valid mTLS certificate required", http.StatusUnauthorized)
		return
	}
	csrPEM, err := decodeCSRRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	credentialID, err := newAgentCredentialID()
	if err != nil {
		http.Error(w, "credential generation failed", http.StatusInternalServerError)
		return
	}
	credential, certificatePEM, err := agentMTLSManager.issue(principal.Agent.AgentID, principal.Agent.TenantID, credentialID, csrPEM)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	store, ok := serverStore.(storage.AgentCredentialStore)
	if !ok {
		http.Error(w, "mTLS storage unavailable", http.StatusNotImplemented)
		return
	}
	if err := store.CreateAgentCredential(r.Context(), credential); err != nil {
		http.Error(w, "store credential failed", http.StatusInternalServerError)
		return
	}
	writeAgentCertificateResponse(w, credential, certificatePEM)
}

func handleAgentIdentityActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if agentMTLSManager == nil || currentAgentAuthMode() == agentAuthModeLegacy {
		http.Error(w, "mTLS is disabled", http.StatusNotFound)
		return
	}
	principal, err := authenticateAgentRequest(r.Context(), r, serverStore)
	if err != nil || principal.Credential == nil {
		http.Error(w, "valid mTLS certificate required", http.StatusUnauthorized)
		return
	}
	store, ok := serverStore.(storage.AgentCredentialStore)
	if !ok {
		http.Error(w, "mTLS storage unavailable", http.StatusNotImplemented)
		return
	}
	if err := store.RevokeOtherAgentCredentials(r.Context(), principal.Agent.AgentID, principal.Credential.CredentialID, "rotated"); err != nil {
		http.Error(w, "revoke old credentials failed", http.StatusInternalServerError)
		return
	}
	if err := store.ClearLegacyAgentToken(r.Context(), principal.Agent.AgentID); err != nil {
		http.Error(w, "clear legacy credential failed", http.StatusInternalServerError)
		return
	}
	closeAgentWebSocket(principal.Agent.AgentID)
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}

func handleAgentCredentialRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if agentMTLSManager == nil {
		http.Error(w, "mTLS is disabled", http.StatusNotFound)
		return
	}
	var in struct {
		CredentialID string `json:"credential_id"`
		Reason       string `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&in); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	store, ok := serverStore.(storage.AgentCredentialStore)
	if !ok {
		http.Error(w, "mTLS storage unavailable", http.StatusNotImplemented)
		return
	}
	credential, err := store.GetAgentCredential(r.Context(), strings.TrimSpace(in.CredentialID))
	if err != nil {
		http.Error(w, "credential not found", http.StatusNotFound)
		return
	}
	if !authorizeOrReject(w, r, authz.ActionAgentsWrite, authz.ResourceRef{TenantIDs: []string{credential.TenantID}}) {
		return
	}
	if err := store.RevokeAgentCredential(r.Context(), credential.CredentialID, in.Reason); err != nil {
		http.Error(w, "revoke credential failed", http.StatusInternalServerError)
		return
	}
	closeAgentWebSocketForCredential(credential.CredentialID)
	_ = json.NewEncoder(w).Encode(map[string]bool{"success": true})
}
