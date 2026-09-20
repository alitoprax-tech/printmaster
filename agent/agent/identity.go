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
	clientIdentityKeyFile       = "agent_identity.key"
	clientIdentityCertFile      = "agent_identity.crt"
	clientIdentityMetaFile      = "agent_identity.json"
	clientIdentityPendingSuffix = ".pending"
	clientIdentityBackupSuffix  = ".bak"
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
	TenantID     string    `json:"tenant_id,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	Certificate  tls.Certificate
}

type identityFileSet struct {
	key  string
	cert string
	meta string
}

type identityMetadata struct {
	CredentialID string    `json:"credential_id"`
	TenantID     string    `json:"tenant_id,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Kept as a narrow indirection so the rollback path can be exercised without
// changing filesystem permissions in platform-specific tests.
var renameIdentityFile = os.Rename

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
// Existing files are moved to rollback backups until the complete replacement
// is installed, so a write failure cannot destroy the last usable identity.
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
	return saveIdentitySet(dataDir, "", identityMetadata{
		CredentialID: credentialID,
		ExpiresAt:    expiresAt.UTC(),
	}, certificatePEM, privateKeyPEM)
}

// SavePendingClientIdentity persists a newly issued identity without
// replacing the currently active identity. The pending set survives process
// restarts so activation can be retried after an ambiguous network failure.
func SavePendingClientIdentity(dataDir string, identity *ClientIdentity, certificatePEM, privateKeyPEM []byte) error {
	if identity == nil {
		return fmt.Errorf("client identity required")
	}
	if strings.TrimSpace(identity.CredentialID) == "" || len(certificatePEM) == 0 || len(privateKeyPEM) == 0 {
		return fmt.Errorf("complete pending Agent identity required")
	}
	if _, err := tls.X509KeyPair(certificatePEM, privateKeyPEM); err != nil {
		return fmt.Errorf("certificate/private key mismatch: %w", err)
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return err
	}
	return saveIdentitySet(dataDir, clientIdentityPendingSuffix, identityMetadata{
		CredentialID: identity.CredentialID,
		TenantID:     identity.TenantID,
		ExpiresAt:    identity.ExpiresAt.UTC(),
	}, certificatePEM, privateKeyPEM)
}

// PromotePendingClientIdentity makes a previously activated pending identity
// the active identity. The active set is replaced transactionally and the
// pending files are removed only after the replacement is durable.
func PromotePendingClientIdentity(dataDir string) error {
	identity, certificatePEM, privateKeyPEM, err := readIdentitySet(dataDir, clientIdentityPendingSuffix)
	if err != nil || identity == nil {
		identity, certificatePEM, privateKeyPEM, err = readIdentityBackupSet(dataDir, clientIdentityPendingSuffix)
		if err != nil {
			return err
		}
	}
	if identity == nil {
		return fmt.Errorf("pending Agent identity not found")
	}
	if err := saveIdentitySet(dataDir, "", identityMetadata{
		CredentialID: identity.CredentialID,
		TenantID:     identity.TenantID,
		ExpiresAt:    identity.ExpiresAt.UTC(),
	}, certificatePEM, privateKeyPEM); err != nil {
		return err
	}
	return DeletePendingClientIdentity(dataDir)
}

// LoadClientIdentity loads the identity if it exists. Missing files are not an
// error so first-time enrollment can still use the legacy bootstrap path.
func LoadClientIdentity(dataDir string) (*ClientIdentity, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, nil
	}
	identity, _, _, err := readIdentitySet(dataDir, "")
	if err == nil && identity != nil {
		return identity, nil
	}
	// A process or machine crash can occur after the old set was moved to
	// rollback files but before all new files were installed. Recover the last
	// complete set instead of returning a partial identity.
	if backup, _, _, backupErr := readIdentityBackupSet(dataDir, ""); backupErr == nil && backup != nil {
		return backup, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// LoadPendingClientIdentity loads an identity waiting for activation. Missing
// pending files are not an error.
func LoadPendingClientIdentity(dataDir string) (*ClientIdentity, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, nil
	}
	identity, _, _, err := readIdentitySet(dataDir, clientIdentityPendingSuffix)
	if err == nil && identity != nil {
		return identity, nil
	}
	if backup, _, _, backupErr := readIdentityBackupSet(dataDir, clientIdentityPendingSuffix); backupErr == nil && backup != nil {
		return backup, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func DeleteClientIdentity(dataDir string) error {
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("data directory not specified")
	}
	var firstErr error
	for _, path := range identityPathList(dataDir, "", true) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// DeletePendingClientIdentity removes a pending identity and any interrupted
// write backups. It is intentionally separate from DeleteClientIdentity so a
// failed activation never removes the active identity.
func DeletePendingClientIdentity(dataDir string) error {
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("data directory not specified")
	}
	var firstErr error
	for _, path := range identityPathList(dataDir, clientIdentityPendingSuffix, true) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func identityPaths(dataDir, suffix string) identityFileSet {
	return identityFileSet{
		key:  filepath.Join(dataDir, "agent_identity"+suffix+".key"),
		cert: filepath.Join(dataDir, "agent_identity"+suffix+".crt"),
		meta: filepath.Join(dataDir, "agent_identity"+suffix+".json"),
	}
}

func identityPathList(dataDir, suffix string, includeBackups bool) []string {
	paths := identityPaths(dataDir, suffix)
	result := []string{paths.key, paths.cert, paths.meta}
	if includeBackups {
		result = append(result, paths.key+clientIdentityBackupSuffix, paths.cert+clientIdentityBackupSuffix, paths.meta+clientIdentityBackupSuffix)
	}
	return result
}

func readIdentitySet(dataDir, suffix string) (*ClientIdentity, []byte, []byte, error) {
	return readIdentityFiles(identityPaths(dataDir, suffix))
}

func readIdentityBackupSet(dataDir, suffix string) (*ClientIdentity, []byte, []byte, error) {
	paths := identityPaths(dataDir, suffix)
	paths.key += clientIdentityBackupSuffix
	paths.cert += clientIdentityBackupSuffix
	paths.meta += clientIdentityBackupSuffix
	return readIdentityFiles(paths)
}

func readIdentityFiles(paths identityFileSet) (*ClientIdentity, []byte, []byte, error) {
	keyPEM, keyErr := os.ReadFile(paths.key)
	certPEM, certErr := os.ReadFile(paths.cert)
	metaPEM, metaErr := os.ReadFile(paths.meta)
	if os.IsNotExist(keyErr) && os.IsNotExist(certErr) && os.IsNotExist(metaErr) {
		return nil, nil, nil, nil
	}
	if keyErr != nil {
		return nil, nil, nil, keyErr
	}
	if certErr != nil {
		return nil, nil, nil, certErr
	}
	if metaErr != nil {
		return nil, nil, nil, metaErr
	}
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("load Agent identity: %w", err)
	}
	var meta identityMetadata
	if err := json.Unmarshal(metaPEM, &meta); err != nil {
		return nil, nil, nil, fmt.Errorf("parse Agent identity metadata: %w", err)
	}
	if meta.CredentialID == "" || meta.ExpiresAt.IsZero() {
		return nil, nil, nil, fmt.Errorf("Agent identity metadata incomplete")
	}
	return &ClientIdentity{CredentialID: meta.CredentialID, TenantID: meta.TenantID, ExpiresAt: meta.ExpiresAt, Certificate: cert}, certPEM, keyPEM, nil
}

func saveIdentitySet(dataDir, suffix string, meta identityMetadata, certificatePEM, privateKeyPEM []byte) error {
	paths := identityPaths(dataDir, suffix)
	tempDir, err := os.MkdirTemp(dataDir, ".agent-identity-write-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempDir)
	metaPEM, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	tempPaths := identityFileSet{
		key:  filepath.Join(tempDir, filepath.Base(paths.key)),
		cert: filepath.Join(tempDir, filepath.Base(paths.cert)),
		meta: filepath.Join(tempDir, filepath.Base(paths.meta)),
	}
	for _, item := range []struct {
		path string
		data []byte
	}{
		{tempPaths.key, privateKeyPEM},
		{tempPaths.cert, certificatePEM},
		{tempPaths.meta, metaPEM},
	} {
		if err := writeDurableIdentityFile(item.path, item.data); err != nil {
			return err
		}
	}

	targets := []string{paths.key, paths.cert, paths.meta}
	temps := []string{tempPaths.key, tempPaths.cert, tempPaths.meta}
	backups := []string{paths.key + clientIdentityBackupSuffix, paths.cert + clientIdentityBackupSuffix, paths.meta + clientIdentityBackupSuffix}
	moved := make([]int, 0, len(targets))
	installed := make([]int, 0, len(targets))
	rollback := func(cause error) error {
		for i := len(installed) - 1; i >= 0; i-- {
			_ = os.Remove(targets[installed[i]])
		}
		for i := len(moved) - 1; i >= 0; i-- {
			_ = renameIdentityFile(backups[moved[i]], targets[moved[i]])
		}
		return cause
	}
	for i, target := range targets {
		_ = os.Remove(backups[i])
		if _, statErr := os.Stat(target); statErr == nil {
			if err := renameIdentityFile(target, backups[i]); err != nil {
				return rollback(err)
			}
			moved = append(moved, i)
		} else if !os.IsNotExist(statErr) {
			return rollback(statErr)
		}
	}
	for i, temp := range temps {
		if err := renameIdentityFile(temp, targets[i]); err != nil {
			return rollback(err)
		}
		installed = append(installed, i)
	}
	for _, backup := range backups {
		_ = os.Remove(backup)
	}
	_ = syncIdentityDirectory(dataDir)
	return nil
}

func writeDurableIdentityFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func syncIdentityDirectory(dataDir string) error {
	dir, err := os.Open(dataDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
