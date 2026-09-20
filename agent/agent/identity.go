package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// These names are retained as the read-only legacy compatibility format.
	// New writes never update them one at a time.
	clientIdentityKeyFile       = "agent_identity.key"
	clientIdentityCertFile      = "agent_identity.crt"
	clientIdentityMetaFile      = "agent_identity.json"
	clientIdentityPendingSuffix = ".pending"
	clientIdentityBackupSuffix  = ".bak"

	identityRootDirectory       = "identity"
	identityActiveDirectory     = "active"
	identityPendingDirectory    = "pending"
	identityCurrentFile         = "current"
	identityGenerationPrefix    = "gen-"
	identityTombstone           = "none"
	identityJournalPrefix       = ".txn-"
	identityJournalSuffix       = ".json"
	identityEnrollmentDirectory = "enrollment"
	enrollmentAttemptKeyFile    = "key"
	enrollmentAttemptCSRFile    = "csr"
	enrollmentAttemptMetaFile   = "meta.json"

	checkpointAfterKeyWrite                      = "after-key-write"
	checkpointAfterKeyFsync                      = "after-key-fsync"
	checkpointAfterCertWrite                     = "after-cert-write"
	checkpointAfterCertFsync                     = "after-cert-fsync"
	checkpointAfterMetaWrite                     = "after-meta-write"
	checkpointAfterMetaFsync                     = "after-meta-fsync"
	checkpointBeforeGenerationDirFsync           = "before-generation-dir-fsync"
	checkpointAfterGenerationDirFsync            = "after-generation-dir-fsync"
	checkpointBeforePointerSwitch                = "before-pointer-switch"
	checkpointAfterPointerSwitch                 = "after-pointer-switch"
	checkpointBeforeOldCleanup                   = "before-old-cleanup"
	checkpointAfterOldCleanup                    = "after-old-cleanup"
	checkpointEnrollmentAfterKeyWrite            = "enrollment-after-key-write"
	checkpointEnrollmentAfterKeyFsync            = "enrollment-after-key-fsync"
	checkpointEnrollmentAfterCSRWrite            = "enrollment-after-csr-write"
	checkpointEnrollmentAfterCSRFsync            = "enrollment-after-csr-fsync"
	checkpointEnrollmentAfterMetaWrite           = "enrollment-after-meta-write"
	checkpointEnrollmentAfterMetaFsync           = "enrollment-after-meta-fsync"
	checkpointEnrollmentBeforeGenerationDirFsync = "enrollment-before-generation-dir-fsync"
	checkpointEnrollmentAfterGenerationDirFsync  = "enrollment-after-generation-dir-fsync"
	checkpointEnrollmentBeforePointerSwitch      = "enrollment-before-pointer-switch"
	checkpointEnrollmentAfterPointerSwitch       = "enrollment-after-pointer-switch"
	checkpointEnrollmentBeforeOldCleanup         = "enrollment-before-old-cleanup"
	checkpointEnrollmentAfterOldCleanup          = "enrollment-after-old-cleanup"
)

// PendingIdentity keeps a newly generated private key local while the CSR is
// sent to the server. The private key is never included in the request.
type PendingIdentity struct {
	PrivateKeyPEM []byte
	CSRPEM        []byte
	// EnrollmentAttemptID identifies the durable first-enrollment attempt. It
	// is opaque and is sent to the server, while the private key remains local.
	EnrollmentAttemptID string
	AgentID             string
	// KeyBackend and KeyReference describe where the private key is held.
	// They are persisted as metadata only; a Windows CNG/TPM key never has
	// private key bytes on disk.
	KeyBackend   string
	KeyReference string
	signer       crypto.Signer
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
	KeyBackend   string    `json:"key_backend,omitempty"`
	KeyReference string    `json:"key_reference,omitempty"`
}

// identityJournal is a durable replay record. It is deliberately separate
// from the immutable generation files: if a process dies after only one of
// those files has been written, startup can reconstruct the complete
// generation from this record before selecting an identity.
type identityJournal struct {
	Version        int              `json:"version"`
	Generation     string           `json:"generation"`
	Metadata       identityMetadata `json:"metadata"`
	CertificatePEM []byte           `json:"certificate_pem"`
	PrivateKeyPEM  []byte           `json:"private_key_pem"`
}

type enrollmentAttemptMetadata struct {
	AttemptID    string    `json:"enrollment_attempt_id"`
	AgentID      string    `json:"agent_id"`
	CreatedAt    time.Time `json:"created_at"`
	KeyBackend   string    `json:"key_backend,omitempty"`
	KeyReference string    `json:"key_reference,omitempty"`
}

type enrollmentAttemptJournal struct {
	Version       int                       `json:"version"`
	Generation    string                    `json:"generation"`
	Metadata      enrollmentAttemptMetadata `json:"metadata"`
	CSRPEM        []byte                    `json:"csr_pem"`
	PrivateKeyPEM []byte                    `json:"private_key_pem"`
}

type storedIdentity struct {
	identity       *ClientIdentity
	certificatePEM []byte
	privateKeyPEM  []byte
	keyBackend     string
	keyReference   string
	signer         crypto.Signer
	generation     string
}

type identityStoreState uint8

const (
	identityStoreAbsent identityStoreState = iota
	identityStoreAvailable
	identityStoreTombstone
)

var (
	// The platform implementations make directory durability and replacement
	// semantics explicit. Tests may replace the sync function to verify that
	// errors are propagated rather than ignored.
	syncIdentityDirectory = syncIdentityDirectoryPlatform

	identityCheckpointMu   sync.RWMutex
	identityCheckpointHook func(string) error
	enrollmentAttemptMu    sync.Mutex
)

func setIdentityCheckpointHook(hook func(string) error) {
	identityCheckpointMu.Lock()
	identityCheckpointHook = hook
	identityCheckpointMu.Unlock()
}

func hitIdentityCheckpoint(name string) error {
	identityCheckpointMu.RLock()
	hook := identityCheckpointHook
	identityCheckpointMu.RUnlock()
	if hook == nil {
		return nil
	}
	return hook(name)
}

func BuildClientIdentity(credentialID string, expiresAt time.Time, certificatePEM, privateKeyPEM []byte) (*ClientIdentity, error) {
	return buildClientIdentityWithSigner(credentialID, expiresAt, certificatePEM, privateKeyPEM, nil)
}

// BuildClientIdentityFromPending builds an identity using the key backend that
// created the CSR. On Windows this may be a non-exportable CNG/TPM signer;
// callers must not assume PrivateKeyPEM is populated.
func BuildClientIdentityFromPending(credentialID string, expiresAt time.Time, certificatePEM []byte, pending *PendingIdentity) (*ClientIdentity, error) {
	if pending == nil {
		return nil, fmt.Errorf("pending identity required")
	}
	return buildClientIdentityWithSigner(credentialID, expiresAt, certificatePEM, pending.PrivateKeyPEM, pending.signer)
}

func buildClientIdentityWithSigner(credentialID string, expiresAt time.Time, certificatePEM, privateKeyPEM []byte, signer crypto.Signer) (*ClientIdentity, error) {
	if strings.TrimSpace(credentialID) == "" {
		return nil, fmt.Errorf("credential id required")
	}
	cert, err := tlsCertificateWithSigner(certificatePEM, privateKeyPEM, signer)
	if err != nil {
		return nil, err
	}
	return &ClientIdentity{CredentialID: credentialID, ExpiresAt: expiresAt, Certificate: cert}, nil
}

// GenerateClientCSR creates an ECDSA P-256 key and a signed CSR. The caller
// must persist the returned private key together with the issued certificate
// before changing the active client identity.
func GenerateClientCSR(agentID string) (*PendingIdentity, error) {
	return generateSoftwareClientCSR(agentID)
}

// GenerateClientCSRAt creates a CSR using the platform key backend. It is
// used for migration and renewal, where the resulting private key must remain
// protected just like a fresh enrollment key.
func GenerateClientCSRAt(dataDir, agentID string) (*PendingIdentity, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, fmt.Errorf("data directory required")
	}
	keyID, err := newEnrollmentAttemptID()
	if err != nil {
		return nil, fmt.Errorf("generate protected key id: %w", err)
	}
	return generateProtectedClientCSR(dataDir, agentID, keyID)
}

// MigrateLegacyKeyStorage upgrades a legacy PEM identity/enrollment store to
// the platform protected backend. Non-Windows platforms retain their existing
// PEM behavior; Windows performs the migration before the service uses the
// identity and fails closed if protection or durability cannot be confirmed.
func MigrateLegacyKeyStorage(dataDir string) error {
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("data directory required")
	}
	return migrateLegacyKeyStoragePlatform(dataDir)
}

func generateSoftwareClientCSR(agentID string) (*PendingIdentity, error) {
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
		AgentID:       agentID,
		KeyBackend:    keyBackendSoftware,
		signer:        key,
	}, nil
}

// CreateEnrollmentAttempt creates and durably records the key and CSR before
// any network enrollment request is sent. The opaque attempt ID lets the
// server replay the same public enrollment result after a response-loss crash.
// The private key is written only to the Agent's local crash-safe store.
func CreateEnrollmentAttempt(dataDir, agentID string) (*PendingIdentity, error) {
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(agentID) == "" {
		return nil, fmt.Errorf("data directory and agent id required")
	}
	attemptID, err := newEnrollmentAttemptID()
	if err != nil {
		return nil, fmt.Errorf("generate enrollment attempt id: %w", err)
	}
	pending, err := generateProtectedClientCSR(dataDir, agentID, attemptID)
	if err != nil {
		return nil, err
	}
	pending.EnrollmentAttemptID = attemptID
	if err := saveEnrollmentAttempt(dataDir, pending); err != nil {
		return nil, fmt.Errorf("persist pre-enrollment attempt: %w", err)
	}
	return pending, nil
}

// LoadEnrollmentAttempt recovers the newest complete pre-enrollment attempt.
// Incomplete generations and corrupt pointers are ignored/recovered using the
// same journal and immutable-generation rules as active identities.
func LoadEnrollmentAttempt(dataDir, agentID string) (*PendingIdentity, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, nil
	}
	attempt, state, err := loadEnrollmentAttemptStore(enrollmentStoreRoot(dataDir))
	if err != nil {
		return nil, err
	}
	if attempt == nil || state == identityStoreTombstone {
		return nil, nil
	}
	if strings.TrimSpace(agentID) != "" && attempt.AgentID != strings.TrimSpace(agentID) {
		return nil, fmt.Errorf("pre-enrollment attempt belongs to a different Agent")
	}
	return attempt, nil
}

// LoadOrCreateEnrollmentAttempt reuses a durable attempt after a process
// restart; it creates a new one only when no attempt is recoverable.
func LoadOrCreateEnrollmentAttempt(dataDir, agentID string) (*PendingIdentity, error) {
	enrollmentAttemptMu.Lock()
	defer enrollmentAttemptMu.Unlock()
	attempt, err := LoadEnrollmentAttempt(dataDir, agentID)
	if err != nil {
		return nil, err
	}
	if attempt != nil {
		return attempt, nil
	}
	return CreateEnrollmentAttempt(dataDir, agentID)
}

// CompleteEnrollmentAttempt tombstones the attempt selector after the issued
// identity has been activated. Immutable generations remain for forensics and
// recovery, but they can no longer be selected on startup.
func CompleteEnrollmentAttempt(dataDir, attemptID string) error {
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(attemptID) == "" {
		return fmt.Errorf("data directory and enrollment attempt id required")
	}
	attempt, err := LoadEnrollmentAttempt(dataDir, "")
	if err != nil {
		return err
	}
	if attempt == nil {
		return nil
	}
	if attempt.EnrollmentAttemptID != strings.TrimSpace(attemptID) {
		return fmt.Errorf("enrollment attempt id does not match persisted attempt")
	}
	return writeEnrollmentPointer(enrollmentStoreRoot(dataDir), identityTombstone)
}

func newEnrollmentAttemptID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// SaveClientIdentity commits a new immutable active generation. The current
// pointer is the only mutable selector; key, certificate, metadata, and all
// prior complete generations remain untouched.
func SaveClientIdentity(dataDir, credentialID string, expiresAt time.Time, certificatePEM, privateKeyPEM []byte) error {
	if strings.TrimSpace(dataDir) == "" || strings.TrimSpace(credentialID) == "" || len(certificatePEM) == 0 || len(privateKeyPEM) == 0 {
		return fmt.Errorf("complete Agent identity required")
	}
	if _, err := tlsCertificateWithSigner(certificatePEM, privateKeyPEM, nil); err != nil {
		return fmt.Errorf("certificate/private key mismatch: %w", err)
	}
	return saveIdentityGeneration(identityStoreRoot(dataDir, false), identityMetadata{
		CredentialID: credentialID,
		ExpiresAt:    expiresAt.UTC(),
	}, certificatePEM, privateKeyPEM)
}

// SavePendingClientIdentity persists a newly issued identity without replacing
// the currently active identity. The pending generation and its journal remain
// recoverable until activation has been confirmed by the server.
func SavePendingClientIdentity(dataDir string, identity *ClientIdentity, certificatePEM, privateKeyPEM []byte) error {
	if identity == nil {
		return fmt.Errorf("client identity required")
	}
	if strings.TrimSpace(identity.CredentialID) == "" || len(certificatePEM) == 0 || len(privateKeyPEM) == 0 {
		return fmt.Errorf("complete pending Agent identity required")
	}
	if _, err := tlsCertificateWithSigner(certificatePEM, privateKeyPEM, nil); err != nil {
		return fmt.Errorf("certificate/private key mismatch: %w", err)
	}
	return saveIdentityGeneration(identityStoreRoot(dataDir, true), identityMetadata{
		CredentialID: identity.CredentialID,
		TenantID:     identity.TenantID,
		ExpiresAt:    identity.ExpiresAt.UTC(),
	}, certificatePEM, privateKeyPEM)
}

// SavePendingClientIdentityFromPending persists a certificate with the exact
// key backend that generated its CSR. This keeps TPM/CNG identities as key
// references and keeps DPAPI ciphertext off the plaintext identity path.
func SavePendingClientIdentityFromPending(dataDir string, identity *ClientIdentity, certificatePEM []byte, pending *PendingIdentity) error {
	if identity == nil || pending == nil {
		return fmt.Errorf("pending identity required")
	}
	if strings.TrimSpace(identity.CredentialID) == "" || len(certificatePEM) == 0 {
		return fmt.Errorf("complete pending Agent identity required")
	}
	if _, err := tlsCertificateWithSigner(certificatePEM, pending.PrivateKeyPEM, pending.signer); err != nil {
		return fmt.Errorf("certificate/private key mismatch: %w", err)
	}
	return saveIdentityGenerationWithKey(identityStoreRoot(dataDir, true), identityMetadata{
		CredentialID: identity.CredentialID,
		TenantID:     identity.TenantID,
		ExpiresAt:    identity.ExpiresAt.UTC(),
		KeyBackend:   pending.KeyBackend,
		KeyReference: pending.KeyReference,
	}, certificatePEM, pending.PrivateKeyPEM)
}

// PromotePendingClientIdentity commits the pending generation as a new active
// generation, then writes a pending tombstone. Pending generation files are
// retained so a crash during cleanup cannot remove the recovery material.
func PromotePendingClientIdentity(dataDir string) error {
	pending, state, err := loadStoredIdentity(dataDir, true)
	if err != nil {
		return err
	}
	if pending == nil {
		if state != identityStoreAbsent && state != identityStoreTombstone {
			return fmt.Errorf("pending Agent identity unavailable")
		}
		return fmt.Errorf("pending Agent identity not found")
	}
	if err := saveIdentityGenerationWithKey(identityStoreRoot(dataDir, false), identityMetadata{
		CredentialID: pending.identity.CredentialID,
		TenantID:     pending.identity.TenantID,
		ExpiresAt:    pending.identity.ExpiresAt.UTC(),
		KeyBackend:   pending.keyBackend,
		KeyReference: pending.keyReference,
	}, pending.certificatePEM, pending.privateKeyPEM); err != nil {
		return err
	}
	// This switch is intentionally last. If it fails, pending remains visible
	// and activation can be retried; it is never deleted before active is safe.
	if err := writeCurrentPointer(identityStoreRoot(dataDir, true), identityTombstone); err != nil {
		return err
	}
	return removeLegacyIdentityFiles(dataDir, clientIdentityPendingSuffix)
}

// LoadClientIdentity loads the newest complete active generation. Corrupt or
// incomplete generations are ignored; a valid pointer is preferred, while a
// missing/corrupt pointer falls back to the newest complete generation.
func LoadClientIdentity(dataDir string) (*ClientIdentity, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, nil
	}
	identity, state, err := loadStoredIdentity(dataDir, false)
	if identity != nil {
		return identity.identity, nil
	}
	if err != nil {
		return nil, err
	}
	if state == identityStoreTombstone {
		return nil, nil
	}
	// Pre-generation installations remain readable and can be migrated by the
	// next renewal/enrollment write. Legacy files are never written by this
	// implementation and are only a compatibility fallback.
	legacy, _, _, legacyErr := readIdentityFiles(identityPaths(dataDir, ""))
	if legacyErr == nil && legacy != nil {
		return legacy, nil
	}
	if backup, _, _, backupErr := readIdentityBackupSet(dataDir, ""); backupErr == nil && backup != nil {
		return backup, nil
	}
	if legacyErr != nil && !isMissingIdentityError(legacyErr) {
		return nil, legacyErr
	}
	return nil, nil
}

// LoadPendingClientIdentity loads a complete pending generation. A pending
// tombstone suppresses stale legacy files after successful promotion.
func LoadPendingClientIdentity(dataDir string) (*ClientIdentity, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, nil
	}
	identity, state, err := loadStoredIdentity(dataDir, true)
	if identity != nil {
		return identity.identity, nil
	}
	if err != nil {
		return nil, err
	}
	if state == identityStoreTombstone {
		return nil, nil
	}
	legacy, _, _, legacyErr := readIdentityFiles(identityPaths(dataDir, clientIdentityPendingSuffix))
	if legacyErr == nil && legacy != nil {
		return legacy, nil
	}
	if backup, _, _, backupErr := readIdentityBackupSet(dataDir, clientIdentityPendingSuffix); backupErr == nil && backup != nil {
		return backup, nil
	}
	if legacyErr != nil && !isMissingIdentityError(legacyErr) {
		return nil, legacyErr
	}
	return nil, nil
}

// DeleteClientIdentity clears the active selector. Generation files are
// deliberately retained; the tombstone prevents their reuse while preserving
// forensic/recovery material for a later controlled migration.
func DeleteClientIdentity(dataDir string) error {
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("data directory not specified")
	}
	if err := writeCurrentPointer(identityStoreRoot(dataDir, false), identityTombstone); err != nil {
		return err
	}
	return removeLegacyIdentityFiles(dataDir, "")
}

// DeletePendingClientIdentity clears pending selection without deleting
// immutable generations. It is kept for compatibility with callers that need
// an explicit administrative cleanup; activation itself uses a tombstone only
// after the active pointer has switched.
func DeletePendingClientIdentity(dataDir string) error {
	if strings.TrimSpace(dataDir) == "" {
		return fmt.Errorf("data directory not specified")
	}
	if err := writeCurrentPointer(identityStoreRoot(dataDir, true), identityTombstone); err != nil {
		return err
	}
	return removeLegacyIdentityFiles(dataDir, clientIdentityPendingSuffix)
}

func identityStoreRoot(dataDir string, pending bool) string {
	name := identityActiveDirectory
	if pending {
		name = identityPendingDirectory
	}
	return filepath.Join(dataDir, identityRootDirectory, name)
}

func enrollmentStoreRoot(dataDir string) string {
	return filepath.Join(dataDir, identityRootDirectory, identityEnrollmentDirectory)
}

func saveEnrollmentAttempt(dataDir string, attempt *PendingIdentity) error {
	if attempt == nil || strings.TrimSpace(attempt.EnrollmentAttemptID) == "" || strings.TrimSpace(attempt.AgentID) == "" || len(attempt.CSRPEM) == 0 {
		return fmt.Errorf("complete pre-enrollment attempt required")
	}
	// A TPM/CNG-backed attempt deliberately has no private-key bytes. Its
	// durable key reference is sufficient to reopen the non-exportable signer.
	if len(attempt.PrivateKeyPEM) == 0 && (!isCNGKeyBackend(attempt.KeyBackend) || strings.TrimSpace(attempt.KeyReference) == "") {
		return fmt.Errorf("pre-enrollment private key reference missing")
	}
	if err := validateEnrollmentAttempt(attempt); err != nil {
		return err
	}
	root := enrollmentStoreRoot(dataDir)
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	if err := recoverEnrollmentTransactions(root); err != nil {
		return fmt.Errorf("recover enrollment transaction: %w", err)
	}
	storedKey, keyRef, err := prepareStoredKey(root, attempt.PrivateKeyPEM, keyReference{Backend: attempt.KeyBackend, Reference: attempt.KeyReference})
	if err != nil {
		return err
	}
	attempt.KeyBackend, attempt.KeyReference = keyRef.Backend, keyRef.Reference
	metadata := enrollmentAttemptMetadata{AttemptID: attempt.EnrollmentAttemptID, AgentID: attempt.AgentID, CreatedAt: time.Now().UTC(), KeyBackend: keyRef.Backend, KeyReference: keyRef.Reference}
	metaJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	generation, err := newGenerationName()
	if err != nil {
		return err
	}
	journalJSON, err := json.Marshal(enrollmentAttemptJournal{Version: 1, Generation: generation, Metadata: metadata, CSRPEM: attempt.CSRPEM, PrivateKeyPEM: storedKey})
	if err != nil {
		return err
	}
	journalPath := filepath.Join(root, identityJournalPrefix+generation+identityJournalSuffix)
	if err := writeDurableIdentityFile(journalPath, journalJSON, "", ""); err != nil {
		return err
	}
	if err := syncIdentityDirectoryChecked(root, "", ""); err != nil {
		return fmt.Errorf("sync enrollment journal directory: %w", err)
	}
	tempDir, err := os.MkdirTemp(root, ".enrollment-generation-write-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tempDir)
		}
	}()
	if err := writeEnrollmentGenerationFiles(tempDir, metaJSON, attempt.CSRPEM, storedKey, true); err != nil {
		return err
	}
	finalDir := filepath.Join(root, generation)
	if err := os.Rename(tempDir, finalDir); err != nil {
		return err
	}
	if err := syncIdentityDirectoryChecked(root, "", ""); err != nil {
		return fmt.Errorf("sync enrollment generation parent directory: %w", err)
	}
	if err := writeEnrollmentPointer(root, generation); err != nil {
		return err
	}
	committed = true
	if err := cleanupEnrollmentJournal(root, journalPath); err != nil {
		return err
	}
	return nil
}

func validateEnrollmentAttempt(attempt *PendingIdentity) error {
	if !isOpaqueEnrollmentAttemptID(attempt.EnrollmentAttemptID) {
		return fmt.Errorf("invalid enrollment attempt id")
	}
	csrBlock, _ := pem.Decode(attempt.CSRPEM)
	if csrBlock == nil || csrBlock.Type != "CERTIFICATE REQUEST" {
		return fmt.Errorf("pre-enrollment CSR missing")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse pre-enrollment CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("pre-enrollment CSR signature invalid: %w", err)
	}
	privateSigner := attempt.signer
	if privateSigner == nil {
		keyBlock, _ := pem.Decode(attempt.PrivateKeyPEM)
		if keyBlock == nil {
			return fmt.Errorf("pre-enrollment private key missing")
		}
		key, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("parse pre-enrollment private key: %w", err)
		}
		var ok bool
		privateSigner, ok = key.(crypto.Signer)
		if !ok {
			return fmt.Errorf("pre-enrollment private key is not a signer")
		}
	}
	if !publicKeysEqual(privateSigner.Public(), csr.PublicKey) {
		return fmt.Errorf("pre-enrollment CSR does not match private key")
	}
	return nil
}

func publicKeysEqual(left, right crypto.PublicKey) bool {
	leftDER, leftErr := x509.MarshalPKIXPublicKey(left)
	rightDER, rightErr := x509.MarshalPKIXPublicKey(right)
	return leftErr == nil && rightErr == nil && string(leftDER) == string(rightDER)
}

func isOpaqueEnrollmentAttemptID(id string) bool {
	if len(id) != 64 {
		return false
	}
	for _, r := range id {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

func writeEnrollmentGenerationFiles(dir string, metaJSON, csrPEM, privateKeyPEM []byte, checkpoints bool) error {
	write := func(path string, data []byte, afterWrite, afterFsync string) error {
		if checkpoints {
			return writeDurableIdentityFile(path, data, afterWrite, afterFsync)
		}
		return writeDurableIdentityFile(path, data, "", "")
	}
	if err := write(filepath.Join(dir, enrollmentAttemptKeyFile), privateKeyPEM, checkpointEnrollmentAfterKeyWrite, checkpointEnrollmentAfterKeyFsync); err != nil {
		return err
	}
	if err := write(filepath.Join(dir, enrollmentAttemptCSRFile), csrPEM, checkpointEnrollmentAfterCSRWrite, checkpointEnrollmentAfterCSRFsync); err != nil {
		return err
	}
	if err := write(filepath.Join(dir, enrollmentAttemptMetaFile), metaJSON, checkpointEnrollmentAfterMetaWrite, checkpointEnrollmentAfterMetaFsync); err != nil {
		return err
	}
	return syncIdentityDirectoryChecked(dir, checkpointEnrollmentBeforeGenerationDirFsync, checkpointEnrollmentAfterGenerationDirFsync)
}

func writeEnrollmentPointer(root, generation string) error {
	if generation != identityTombstone && !isGenerationName(generation) {
		return fmt.Errorf("invalid enrollment pointer generation")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(root, ".enrollment-current-write-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.WriteString(generation + "\n"); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := hitIdentityCheckpoint(checkpointEnrollmentBeforePointerSwitch); err != nil {
		return err
	}
	if err := atomicReplaceIdentityFilePlatform(tempPath, filepath.Join(root, identityCurrentFile)); err != nil {
		return fmt.Errorf("switch enrollment pointer: %w", err)
	}
	if err := hitIdentityCheckpoint(checkpointEnrollmentAfterPointerSwitch); err != nil {
		return err
	}
	return syncIdentityDirectoryChecked(root, "", "")
}

func loadEnrollmentAttemptStore(root string) (*PendingIdentity, identityStoreState, error) {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, identityStoreAbsent, nil
	}
	if err != nil {
		return nil, identityStoreAvailable, err
	}
	if err := recoverEnrollmentTransactions(root); err != nil {
		recoveryErr := err
		attempt, state, _ := selectEnrollmentGeneration(root, entries)
		if attempt != nil || state == identityStoreTombstone {
			return attempt, state, nil
		}
		return nil, state, recoveryErr
	}
	entries, err = os.ReadDir(root)
	if err != nil {
		return nil, identityStoreAvailable, err
	}
	return selectEnrollmentGeneration(root, entries)
}

func selectEnrollmentGeneration(root string, entries []os.DirEntry) (*PendingIdentity, identityStoreState, error) {
	state := identityStoreAbsent
	for _, entry := range entries {
		if entry.Name() == identityCurrentFile || strings.HasPrefix(entry.Name(), identityGenerationPrefix) || strings.HasPrefix(entry.Name(), identityJournalPrefix) {
			state = identityStoreAvailable
			break
		}
	}
	if current, err := os.ReadFile(filepath.Join(root, identityCurrentFile)); err == nil {
		name := strings.TrimSpace(string(current))
		if name == identityTombstone {
			return nil, identityStoreTombstone, nil
		}
		if isGenerationName(name) {
			if attempt, readErr := readEnrollmentGeneration(root, name); readErr == nil {
				return attempt, identityStoreAvailable, nil
			}
			state = identityStoreAvailable
		}
	} else if !os.IsNotExist(err) {
		state = identityStoreAvailable
	}
	if state == identityStoreAbsent {
		return nil, state, nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, identityStoreAvailable, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !isGenerationName(entry.Name()) {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for _, name := range names {
		if attempt, readErr := readEnrollmentGeneration(root, name); readErr == nil {
			return attempt, identityStoreAvailable, nil
		}
	}
	return nil, identityStoreAvailable, nil
}

func readEnrollmentGeneration(root, generation string) (*PendingIdentity, error) {
	if !isGenerationName(generation) {
		return nil, fmt.Errorf("invalid enrollment generation name")
	}
	path := filepath.Join(root, generation)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("enrollment generation is not a directory")
	}
	for _, name := range []string{enrollmentAttemptKeyFile, enrollmentAttemptCSRFile, enrollmentAttemptMetaFile} {
		fileInfo, statErr := os.Lstat(filepath.Join(path, name))
		if statErr != nil {
			return nil, statErr
		}
		if fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("enrollment generation contains a non-regular file")
		}
	}
	privateKeyPEM, err := os.ReadFile(filepath.Join(path, enrollmentAttemptKeyFile))
	if err != nil {
		return nil, err
	}
	csrPEM, err := os.ReadFile(filepath.Join(path, enrollmentAttemptCSRFile))
	if err != nil {
		return nil, err
	}
	metaJSON, err := os.ReadFile(filepath.Join(path, enrollmentAttemptMetaFile))
	if err != nil {
		return nil, err
	}
	var metadata enrollmentAttemptMetadata
	if err := json.Unmarshal(metaJSON, &metadata); err != nil {
		return nil, err
	}
	privateKeyPEM, signer, err := restoreStoredKey(path, privateKeyPEM, keyReference{Backend: metadata.KeyBackend, Reference: metadata.KeyReference})
	if err != nil {
		return nil, err
	}
	attempt := &PendingIdentity{PrivateKeyPEM: privateKeyPEM, CSRPEM: csrPEM, EnrollmentAttemptID: metadata.AttemptID, AgentID: metadata.AgentID, KeyBackend: metadata.KeyBackend, KeyReference: metadata.KeyReference, signer: signer}
	if err := validateEnrollmentAttempt(attempt); err != nil {
		return nil, err
	}
	return attempt, nil
}

func recoverEnrollmentTransactions(root string) error {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var firstErr error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), identityJournalPrefix) || !strings.HasSuffix(entry.Name(), identityJournalSuffix) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			if firstErr == nil {
				firstErr = readErr
			}
			continue
		}
		var journal enrollmentAttemptJournal
		if err := json.Unmarshal(data, &journal); err != nil || journal.Version != 1 || !isGenerationName(journal.Generation) {
			if firstErr == nil {
				if err == nil {
					err = fmt.Errorf("invalid enrollment transaction")
				}
				firstErr = err
			}
			continue
		}
		if err := recoverEnrollmentJournal(root, path, journal); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func recoverEnrollmentJournal(root, journalPath string, journal enrollmentAttemptJournal) error {
	privateKeyPEM, signer, err := restoreStoredKey(root, journal.PrivateKeyPEM, keyReference{Backend: journal.Metadata.KeyBackend, Reference: journal.Metadata.KeyReference})
	if err != nil {
		return err
	}
	storedKey, keyRef, err := prepareStoredKey(root, privateKeyPEM, keyReference{Backend: journal.Metadata.KeyBackend, Reference: journal.Metadata.KeyReference})
	if err != nil {
		return fmt.Errorf("protect recovered enrollment key: %w", err)
	}
	journal.Metadata.KeyBackend, journal.Metadata.KeyReference = keyRef.Backend, keyRef.Reference
	attempt := &PendingIdentity{PrivateKeyPEM: privateKeyPEM, CSRPEM: journal.CSRPEM, EnrollmentAttemptID: journal.Metadata.AttemptID, AgentID: journal.Metadata.AgentID, KeyBackend: journal.Metadata.KeyBackend, KeyReference: journal.Metadata.KeyReference, signer: signer}
	if err := validateEnrollmentAttempt(attempt); err != nil {
		return err
	}
	if _, err := readEnrollmentGeneration(root, journal.Generation); err != nil {
		tempDir, err := os.MkdirTemp(root, ".enrollment-generation-recover-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tempDir)
		metaJSON, marshalErr := json.Marshal(journal.Metadata)
		if marshalErr != nil {
			return marshalErr
		}
		if err := writeEnrollmentGenerationFiles(tempDir, metaJSON, journal.CSRPEM, storedKey, false); err != nil {
			return err
		}
		finalDir := filepath.Join(root, journal.Generation)
		if _, statErr := os.Stat(finalDir); statErr == nil {
			if removeErr := os.RemoveAll(finalDir); removeErr != nil {
				return removeErr
			}
		} else if !os.IsNotExist(statErr) {
			return statErr
		}
		if err := os.Rename(tempDir, finalDir); err != nil {
			return err
		}
		if err := syncIdentityDirectory(root); err != nil {
			return fmt.Errorf("sync recovered enrollment generation parent directory: %w", err)
		}
	}
	current, currentErr := os.ReadFile(filepath.Join(root, identityCurrentFile))
	currentName := strings.TrimSpace(string(current))
	currentComplete := false
	if currentErr == nil && isGenerationName(currentName) {
		_, currentReadErr := readEnrollmentGeneration(root, currentName)
		currentComplete = currentReadErr == nil
	}
	if currentName != identityTombstone && !currentComplete {
		if err := writeEnrollmentPointer(root, journal.Generation); err != nil {
			return err
		}
	}
	return cleanupEnrollmentJournal(root, journalPath)
}

func cleanupEnrollmentJournal(root, journalPath string) error {
	if err := hitIdentityCheckpoint(checkpointEnrollmentBeforeOldCleanup); err != nil {
		return err
	}
	if err := os.Remove(journalPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := syncIdentityDirectoryChecked(root, "", ""); err != nil {
		return fmt.Errorf("sync enrollment cleanup: %w", err)
	}
	return hitIdentityCheckpoint(checkpointEnrollmentAfterOldCleanup)
}

func loadStoredIdentity(dataDir string, pending bool) (*storedIdentity, identityStoreState, error) {
	root := identityStoreRoot(dataDir, pending)
	stored, state, err := loadIdentityStore(root)
	if stored != nil || state == identityStoreTombstone || err != nil {
		return stored, state, err
	}
	// Legacy pending/active files are considered only when there is no new store
	// at all. This prevents a stale .bak set from overriding a deliberate
	// generation tombstone while allowing an older installation to complete its
	// first controlled promotion.
	suffix := ""
	if pending {
		suffix = clientIdentityPendingSuffix
	}
	identity, certificatePEM, privateKeyPEM, legacyErr := readIdentityFiles(identityPaths(dataDir, suffix))
	if legacyErr == nil && identity != nil {
		return &storedIdentity{identity: identity, certificatePEM: certificatePEM, privateKeyPEM: privateKeyPEM}, identityStoreAvailable, nil
	}
	if backup, backupCert, backupKey, backupErr := readIdentityBackupSet(dataDir, suffix); backupErr == nil && backup != nil {
		return &storedIdentity{identity: backup, certificatePEM: backupCert, privateKeyPEM: backupKey}, identityStoreAvailable, nil
	}
	if legacyErr != nil && !isMissingIdentityError(legacyErr) {
		return nil, identityStoreAvailable, legacyErr
	}
	return nil, identityStoreAbsent, nil
}

func loadIdentityStore(root string) (*storedIdentity, identityStoreState, error) {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, identityStoreAbsent, nil
	}
	if err != nil {
		return nil, identityStoreAvailable, err
	}
	if err := recoverIdentityTransactions(root); err != nil {
		// Continue to use an already complete old generation. A failed replay
		// must never make a complete credential disappear; the error is returned
		// only when no usable generation remains below.
		recoveryErr := err
		stored, state, _ := selectIdentityGeneration(root, entries)
		if stored != nil {
			return stored, state, nil
		}
		if state == identityStoreTombstone {
			return nil, state, nil
		}
		return nil, state, recoveryErr
	}
	entries, err = os.ReadDir(root)
	if err != nil {
		return nil, identityStoreAvailable, err
	}
	return selectIdentityGeneration(root, entries)
}

func selectIdentityGeneration(root string, entries []os.DirEntry) (*storedIdentity, identityStoreState, error) {
	state := identityStoreAbsent
	for _, entry := range entries {
		if entry.Name() == identityCurrentFile || strings.HasPrefix(entry.Name(), identityGenerationPrefix) || strings.HasPrefix(entry.Name(), identityJournalPrefix) {
			state = identityStoreAvailable
			break
		}
	}
	currentPath := filepath.Join(root, identityCurrentFile)
	if current, err := os.ReadFile(currentPath); err == nil {
		name := strings.TrimSpace(string(current))
		if name == identityTombstone {
			return nil, identityStoreTombstone, nil
		}
		if isGenerationName(name) {
			if stored, readErr := readGeneration(root, name); readErr == nil {
				return stored, identityStoreAvailable, nil
			}
			state = identityStoreAvailable
		}
	} else if !os.IsNotExist(err) {
		state = identityStoreAvailable
	}
	if state == identityStoreAbsent {
		return nil, state, nil
	}
	stored, err := newestCompleteGeneration(root)
	if err != nil {
		return nil, identityStoreAvailable, err
	}
	if stored != nil {
		return stored, identityStoreAvailable, nil
	}
	return nil, identityStoreAvailable, nil
}

func newestCompleteGeneration(root string) (*storedIdentity, error) {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() || !isGenerationName(entry.Name()) {
			continue
		}
		info, infoErr := entry.Info()
		if infoErr != nil || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	for _, name := range names {
		stored, err := readGeneration(root, name)
		if err == nil {
			return stored, nil
		}
	}
	return nil, nil
}

func isGenerationName(name string) bool {
	if filepath.Base(name) != name || !strings.HasPrefix(name, identityGenerationPrefix) {
		return false
	}
	rest := strings.TrimPrefix(name, identityGenerationPrefix)
	if len(rest) < 16 {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && r != '-' {
			return false
		}
	}
	return true
}

func newGenerationName() (string, error) {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s%020d-%s", identityGenerationPrefix, time.Now().UTC().UnixNano(), hex.EncodeToString(random)), nil
}

func readGeneration(root, generation string) (*storedIdentity, error) {
	if !isGenerationName(generation) {
		return nil, fmt.Errorf("invalid identity generation name")
	}
	path := filepath.Join(root, generation)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("identity generation is not a directory")
	}
	paths := identityFileSet{
		key:  filepath.Join(path, "key"),
		cert: filepath.Join(path, "cert"),
		meta: filepath.Join(path, "meta.json"),
	}
	for _, filePath := range []string{paths.key, paths.cert, paths.meta} {
		fileInfo, statErr := os.Lstat(filePath)
		if statErr != nil {
			return nil, statErr
		}
		if fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() {
			return nil, fmt.Errorf("identity generation contains a non-regular file")
		}
	}
	identity, cert, key, keyBackend, keyReference, signer, err := readStoredIdentityFiles(path, paths)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, fmt.Errorf("identity generation incomplete")
	}
	return &storedIdentity{identity: identity, certificatePEM: cert, privateKeyPEM: key, keyBackend: keyBackend, keyReference: keyReference, signer: signer, generation: generation}, nil
}

func saveIdentityGeneration(root string, metadata identityMetadata, certificatePEM, privateKeyPEM []byte) error {
	return saveIdentityGenerationWithKey(root, metadata, certificatePEM, privateKeyPEM)
}

func saveIdentityGenerationWithKey(root string, metadata identityMetadata, certificatePEM, privateKeyPEM []byte) error {
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	if err := recoverIdentityTransactions(root); err != nil {
		return fmt.Errorf("recover identity transaction: %w", err)
	}
	if !(isCNGKeyBackend(metadata.KeyBackend) && len(privateKeyPEM) == 0) {
		if _, err := tlsCertificateWithSigner(certificatePEM, privateKeyPEM, nil); err != nil {
			return fmt.Errorf("certificate/private key mismatch: %w", err)
		}
	}
	storedKey, keyRef, err := prepareStoredKey(root, privateKeyPEM, keyReference{Backend: metadata.KeyBackend, Reference: metadata.KeyReference})
	if err != nil {
		return err
	}
	metadata.KeyBackend, metadata.KeyReference = keyRef.Backend, keyRef.Reference
	metaPEM, err := json.Marshal(metadata)
	if err != nil {
		return err
	}
	generation, err := newGenerationName()
	if err != nil {
		return err
	}
	journal := identityJournal{Version: 1, Generation: generation, Metadata: metadata, CertificatePEM: certificatePEM, PrivateKeyPEM: storedKey}
	journalPEM, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	journalPath := filepath.Join(root, identityJournalPrefix+generation+identityJournalSuffix)
	if err := writeDurableIdentityFile(journalPath, journalPEM, "", ""); err != nil {
		return err
	}
	if err := syncIdentityDirectoryChecked(root, "", ""); err != nil {
		return fmt.Errorf("sync identity journal directory: %w", err)
	}

	tempDir, err := os.MkdirTemp(root, ".generation-write-")
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.RemoveAll(tempDir)
		}
	}()
	if err := writeGenerationFiles(tempDir, metaPEM, certificatePEM, storedKey, true); err != nil {
		return err
	}
	finalDir := filepath.Join(root, generation)
	if err := os.Rename(tempDir, finalDir); err != nil {
		return err
	}
	if err := syncIdentityDirectoryChecked(root, "", ""); err != nil {
		return fmt.Errorf("sync generation parent directory: %w", err)
	}
	if err := writeCurrentPointer(root, generation); err != nil {
		return err
	}
	committed = true
	if err := cleanupIdentityJournal(root, journalPath); err != nil {
		return err
	}
	return nil
}

func writeGenerationFiles(dir string, metaPEM, certificatePEM, privateKeyPEM []byte, checkpoints bool) error {
	write := func(path string, data []byte, afterWrite, afterFsync string) error {
		if checkpoints {
			return writeDurableIdentityFile(path, data, afterWrite, afterFsync)
		}
		return writeDurableIdentityFile(path, data, "", "")
	}
	if err := write(filepath.Join(dir, "key"), privateKeyPEM, checkpointAfterKeyWrite, checkpointAfterKeyFsync); err != nil {
		return err
	}
	if err := write(filepath.Join(dir, "cert"), certificatePEM, checkpointAfterCertWrite, checkpointAfterCertFsync); err != nil {
		return err
	}
	if err := write(filepath.Join(dir, "meta.json"), metaPEM, checkpointAfterMetaWrite, checkpointAfterMetaFsync); err != nil {
		return err
	}
	return syncIdentityDirectoryChecked(dir, checkpointBeforeGenerationDirFsync, checkpointAfterGenerationDirFsync)
}

func writeCurrentPointer(root, generation string) error {
	if generation != identityTombstone && !isGenerationName(generation) {
		return fmt.Errorf("invalid identity pointer generation")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(root, ".current-write-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if err := temp.Chmod(0600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.WriteString(generation + "\n"); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := hitIdentityCheckpoint(checkpointBeforePointerSwitch); err != nil {
		return err
	}
	if err := atomicReplaceIdentityFilePlatform(tempPath, filepath.Join(root, identityCurrentFile)); err != nil {
		return fmt.Errorf("switch identity pointer: %w", err)
	}
	if err := hitIdentityCheckpoint(checkpointAfterPointerSwitch); err != nil {
		return err
	}
	if err := syncIdentityDirectoryChecked(root, "", ""); err != nil {
		return fmt.Errorf("sync identity pointer directory: %w", err)
	}
	return nil
}

func syncIdentityDirectoryChecked(path, before, after string) error {
	if before != "" {
		if err := hitIdentityCheckpoint(before); err != nil {
			return err
		}
	}
	if err := syncIdentityDirectory(path); err != nil {
		return err
	}
	if after != "" {
		if err := hitIdentityCheckpoint(after); err != nil {
			return err
		}
	}
	return nil
}

func cleanupIdentityJournal(root, journalPath string) error {
	if err := hitIdentityCheckpoint(checkpointBeforeOldCleanup); err != nil {
		return err
	}
	if err := os.Remove(journalPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := syncIdentityDirectoryChecked(root, "", ""); err != nil {
		return fmt.Errorf("sync identity cleanup: %w", err)
	}
	return hitIdentityCheckpoint(checkpointAfterOldCleanup)
}

func recoverIdentityTransactions(root string) error {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var firstErr error
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), identityJournalPrefix) || !strings.HasSuffix(entry.Name(), identityJournalSuffix) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			if firstErr == nil {
				firstErr = readErr
			}
			continue
		}
		var journal identityJournal
		if err := json.Unmarshal(data, &journal); err != nil || journal.Version != 1 || !isGenerationName(journal.Generation) {
			if firstErr == nil {
				if err == nil {
					err = fmt.Errorf("invalid identity transaction")
				}
				firstErr = err
			}
			continue
		}
		if err := recoverIdentityJournal(root, path, journal); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func recoverIdentityJournal(root, journalPath string, journal identityJournal) error {
	if _, err := readGeneration(root, journal.Generation); err != nil {
		storedKey, signer, keyErr := restoreStoredKey(root, journal.PrivateKeyPEM, keyReference{Backend: journal.Metadata.KeyBackend, Reference: journal.Metadata.KeyReference})
		if keyErr != nil {
			return fmt.Errorf("invalid identity transaction key: %w", keyErr)
		}
		storedKey, keyRef, keyErr := prepareStoredKey(root, storedKey, keyReference{Backend: journal.Metadata.KeyBackend, Reference: journal.Metadata.KeyReference})
		if keyErr != nil {
			return fmt.Errorf("protect recovered identity key: %w", keyErr)
		}
		journal.Metadata.KeyBackend, journal.Metadata.KeyReference = keyRef.Backend, keyRef.Reference
		if _, keyErr := tlsCertificateWithSigner(journal.CertificatePEM, storedKey, signer); keyErr != nil {
			return fmt.Errorf("invalid identity transaction certificate/key: %w", keyErr)
		}
		metaPEM, marshalErr := json.Marshal(journal.Metadata)
		if marshalErr != nil {
			return marshalErr
		}
		tempDir, err := os.MkdirTemp(root, ".generation-recover-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tempDir)
		if err := writeGenerationFiles(tempDir, metaPEM, journal.CertificatePEM, storedKey, false); err != nil {
			return err
		}
		finalDir := filepath.Join(root, journal.Generation)
		// A power loss can leave the final directory name present while one of
		// its files is missing despite the journal being durable. Replace that
		// incomplete directory from the replay record; complete generations are
		// never modified.
		if _, statErr := os.Stat(finalDir); statErr == nil {
			if removeErr := os.RemoveAll(finalDir); removeErr != nil {
				return removeErr
			}
		} else if !os.IsNotExist(statErr) {
			return statErr
		}
		if err := os.Rename(tempDir, finalDir); err != nil {
			return err
		}
		if err := syncIdentityDirectory(root); err != nil {
			return fmt.Errorf("sync recovered generation parent directory: %w", err)
		}
	}

	current, currentErr := os.ReadFile(filepath.Join(root, identityCurrentFile))
	currentName := strings.TrimSpace(string(current))
	currentComplete := false
	if currentErr == nil && isGenerationName(currentName) {
		_, currentReadErr := readGeneration(root, currentName)
		currentComplete = currentReadErr == nil
	}
	// A valid old pointer is safe to retain. If no valid selector exists, the
	// recovered generation becomes the selector; this is essential for first
	// enrollment where the join token may already be consumed.
	if currentName != identityTombstone && !currentComplete {
		if err := writeCurrentPointer(root, journal.Generation); err != nil {
			return err
		}
	}
	return cleanupIdentityJournal(root, journalPath)
}

func writeDurableIdentityFile(path string, data []byte, afterWrite, afterFsync string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	closeWithError := func(cause error) error {
		if closeErr := f.Close(); cause == nil {
			return closeErr
		}
		return cause
	}
	if _, err := f.Write(data); err != nil {
		return closeWithError(err)
	}
	if afterWrite != "" {
		if err := hitIdentityCheckpoint(afterWrite); err != nil {
			return closeWithError(err)
		}
	}
	if err := f.Sync(); err != nil {
		return closeWithError(err)
	}
	if afterFsync != "" {
		if err := hitIdentityCheckpoint(afterFsync); err != nil {
			return closeWithError(err)
		}
	}
	return f.Close()
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

func readStoredIdentityFiles(root string, paths identityFileSet) (*ClientIdentity, []byte, []byte, string, string, crypto.Signer, error) {
	keyStored, keyErr := os.ReadFile(paths.key)
	certPEM, certErr := os.ReadFile(paths.cert)
	metaPEM, metaErr := os.ReadFile(paths.meta)
	if keyErr != nil || certErr != nil || metaErr != nil {
		if os.IsNotExist(keyErr) && os.IsNotExist(certErr) && os.IsNotExist(metaErr) {
			return nil, nil, nil, "", "", nil, nil
		}
		if keyErr != nil {
			return nil, nil, nil, "", "", nil, keyErr
		}
		if certErr != nil {
			return nil, nil, nil, "", "", nil, certErr
		}
		return nil, nil, nil, "", "", nil, metaErr
	}
	var meta identityMetadata
	if err := json.Unmarshal(metaPEM, &meta); err != nil {
		return nil, nil, nil, "", "", nil, fmt.Errorf("parse Agent identity metadata: %w", err)
	}
	privateKeyPEM, signer, err := restoreStoredKey(root, keyStored, keyReference{Backend: meta.KeyBackend, Reference: meta.KeyReference})
	if err != nil {
		return nil, nil, nil, "", "", nil, err
	}
	cert, err := tlsCertificateWithSigner(certPEM, privateKeyPEM, signer)
	if err != nil {
		return nil, nil, nil, "", "", nil, fmt.Errorf("load Agent identity: %w", err)
	}
	if meta.CredentialID == "" || meta.ExpiresAt.IsZero() {
		return nil, nil, nil, "", "", nil, fmt.Errorf("Agent identity metadata incomplete")
	}
	return &ClientIdentity{CredentialID: meta.CredentialID, TenantID: meta.TenantID, ExpiresAt: meta.ExpiresAt, Certificate: cert}, certPEM, privateKeyPEM, meta.KeyBackend, meta.KeyReference, signer, nil
}

func identityPaths(dataDir, suffix string) identityFileSet {
	return identityFileSet{
		key:  filepath.Join(dataDir, "agent_identity"+suffix+".key"),
		cert: filepath.Join(dataDir, "agent_identity"+suffix+".crt"),
		meta: filepath.Join(dataDir, "agent_identity"+suffix+".json"),
	}
}

func readIdentityBackupSet(dataDir, suffix string) (*ClientIdentity, []byte, []byte, error) {
	paths := identityPaths(dataDir, suffix)
	paths.key += clientIdentityBackupSuffix
	paths.cert += clientIdentityBackupSuffix
	paths.meta += clientIdentityBackupSuffix
	return readIdentityFiles(paths)
}

func removeLegacyIdentityFiles(dataDir, suffix string) error {
	var firstErr error
	removed := false
	paths := identityPaths(dataDir, suffix)
	for _, path := range []string{
		paths.key,
		paths.cert,
		paths.meta,
		paths.key + clientIdentityBackupSuffix,
		paths.cert + clientIdentityBackupSuffix,
		paths.meta + clientIdentityBackupSuffix,
	} {
		if err := os.Remove(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		removed = true
	}
	if firstErr != nil {
		return firstErr
	}
	if removed {
		if err := syncIdentityDirectory(dataDir); err != nil {
			return err
		}
	}
	return nil
}

func isMissingIdentityError(err error) bool {
	return err == nil || errors.Is(err, os.ErrNotExist)
}
