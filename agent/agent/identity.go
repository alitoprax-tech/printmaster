package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	clientIdentityKeyFile  = "agent_identity.key"
	clientIdentityCertFile = "agent_identity.crt"
	clientIdentityMetaFile = "agent_identity.json"
)

// PendingIdentity keeps a newly generated private key local while the CSR is
// sent to the server. The private key is never included in the request.
type PendingIdentity struct {
	PrivateKeyPEM []byte
	CSRPEM        []byte
}

// ClientIdentity is the persisted certificate metadata and parsed certificate
// used by HTTP and WebSocket transports.
type ClientIdentity struct {
	CredentialID string    `json:"credential_id"`
	ExpiresAt    time.Time `json:"expires_at"`
	Certificate  tls.Certificate
}

func BuildClientIdentity(credentialID string, expiresAt time.Time, certificatePEM, privateKeyPEM []byte) (*ClientIdentity, error) {
	if strings.TrimSpace(credentialID) == "" {
		return nil, fmt.Errorf("credential id required")
	}
	cert, err := tls.X509KeyPair(certificatePEM, privateKeyPEM)
	if err != nil {
		return nil, err
	}
	return &ClientIdentity{CredentialID: credentialID, ExpiresAt: expiresAt, Certificate: cert}, nil
}

// GenerateClientCSR creates an ECDSA P-256 key and a signed CSR. The caller
// must persist the returned private key only after the server returns a cert.
func GenerateClientCSR(agentID string) (*PendingIdentity, error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, fmt.Errorf("agent id required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate Agent key: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "PrintMaster Agent"}}, key)
	if err != nil {
		return nil, fmt.Errorf("create Agent CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal Agent key: %w", err)
	}
	return &PendingIdentity{
		PrivateKeyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		CSRPEM:        pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}),
	}, nil
}

// SaveClientIdentity atomically stores the private key and certificate with
// owner-only permissions. A certificate is never persisted without its key.
func SaveClientIdentity(dataDir, credentialID string, expiresAt time.Time, certificatePEM, privateKeyPEM []byte) error {
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(credentialID) == "" || len(certificatePEM) == 0 || len(privateKeyPEM) == 0 {
		return fmt.Errorf("complete Agent identity required")
	}
	if _, err := tls.X509KeyPair(certificatePEM, privateKeyPEM); err != nil {
		return fmt.Errorf("certificate/private key mismatch: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	for _, path := range []string{filepath.Join(dataDir, clientIdentityKeyFile), filepath.Join(dataDir, clientIdentityCertFile), filepath.Join(dataDir, clientIdentityMetaFile)} {
		_ = os.Remove(path)
	}
	keyPath := filepath.Join(dataDir, clientIdentityKeyFile)
	certPath := filepath.Join(dataDir, clientIdentityCertFile)
	metaPath := filepath.Join(dataDir, clientIdentityMetaFile)
	if err := os.WriteFile(keyPath, privateKeyPEM, 0600); err != nil {
		return err
	}
	if err := os.WriteFile(certPath, certificatePEM, 0600); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	meta, _ := json.Marshal(struct {
		CredentialID string    `json:"credential_id"`
		ExpiresAt    time.Time `json:"expires_at"`
	}{credentialID, expiresAt.UTC()})
	if err := os.WriteFile(metaPath, meta, 0600); err != nil {
		_ = os.Remove(keyPath)
		_ = os.Remove(certPath)
		return err
	}
	return nil
}

// LoadClientIdentity loads the identity if it exists. Missing files are not an
// error so first-time enrollment can still use the legacy bootstrap path.
func LoadClientIdentity(dataDir string) (*ClientIdentity, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, nil
	}
	keyPEM, keyErr := os.ReadFile(filepath.Join(dataDir, clientIdentityKeyFile))
	certPEM, certErr := os.ReadFile(filepath.Join(dataDir, clientIdentityCertFile))
	metaPEM, metaErr := os.ReadFile(filepath.Join(dataDir, clientIdentityMetaFile))
	if os.IsNotExist(keyErr) || os.IsNotExist(certErr) || os.IsNotExist(metaErr) {
		return nil, nil
	}
	if keyErr != nil {
		return nil, keyErr
	}
	if certErr != nil {
		return nil, certErr
	}
	if metaErr != nil {
		return nil, metaErr
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("load Agent identity: %w", err)
	}
	var meta struct {
		CredentialID string    `json:"credential_id"`
		ExpiresAt    time.Time `json:"expires_at"`
	}
	if err := json.Unmarshal(metaPEM, &meta); err != nil {
		return nil, fmt.Errorf("parse Agent identity metadata: %w", err)
	}
	if meta.CredentialID == "" || meta.ExpiresAt.IsZero() {
		return nil, fmt.Errorf("Agent identity metadata incomplete")
	}
	return &ClientIdentity{CredentialID: meta.CredentialID, ExpiresAt: meta.ExpiresAt, Certificate: cert}, nil
}

func DeleteClientIdentity(dataDir string) error {
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("data directory not specified")
	}
	var firstErr error
	for _, file := range []string{clientIdentityKeyFile, clientIdentityCertFile, clientIdentityMetaFile} {
		if err := os.Remove(filepath.Join(dataDir, file)); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
