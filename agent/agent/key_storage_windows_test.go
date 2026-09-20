//go:build windows
// +build windows

package agent

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
	"unsafe"
)

func TestWindowsDPAPIKeyStorageRoundTrip(t *testing.T) {
	_, plain := testIdentityMaterial(t, "dpapi")
	stored, ref, err := protectPrivateKeyPlatform(t.TempDir(), plain, keyReference{Backend: keyBackendDPAPI})
	if err != nil {
		t.Fatalf("protect key with DPAPI: %v", err)
	}
	if ref.Backend != keyBackendDPAPI {
		t.Fatalf("unexpected backend %q", ref.Backend)
	}
	if bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatal("DPAPI envelope contains plaintext PEM")
	}
	recovered, _, err := unprotectPrivateKeyPlatform(t.TempDir(), stored, ref)
	if err != nil {
		t.Fatalf("unprotect key with DPAPI: %v", err)
	}
	if !bytes.Equal(recovered, plain) {
		t.Fatal("DPAPI round trip changed private key bytes")
	}
}

func TestWindowsEnrollmentGenerationDoesNotStorePlaintextKey(t *testing.T) {
	dataDir := t.TempDir()
	attempt, err := CreateEnrollmentAttempt(dataDir, "windows-protected-agent")
	if err != nil {
		t.Fatalf("create protected enrollment attempt: %v", err)
	}
	if isCNGKeyBackend(attempt.KeyBackend) && len(attempt.PrivateKeyPEM) != 0 {
		t.Fatal("TPM enrollment exposed private key bytes")
	}
	gen, err := os.ReadFile(filepath.Join(enrollmentStoreRoot(dataDir), identityCurrentFile))
	if err != nil {
		t.Fatalf("read enrollment pointer: %v", err)
	}
	keyPath := filepath.Join(enrollmentStoreRoot(dataDir), string(bytes.TrimSpace(gen)), enrollmentAttemptKeyFile)
	stored, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read persisted enrollment key: %v", err)
	}
	if bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatal("persisted enrollment generation contains plaintext private key")
	}
	loaded, err := LoadEnrollmentAttempt(dataDir, attempt.AgentID)
	if err != nil || loaded == nil {
		t.Fatalf("recover protected enrollment attempt: %v", err)
	}
	if isCNGKeyBackend(loaded.KeyBackend) && loaded.KeyReference == "" {
		t.Fatal("recovered TPM enrollment attempt has no key reference")
	}
}

func TestWindowsProtectedSignerBuildsTLSClientCertificate(t *testing.T) {
	pending, err := generateProtectedClientCSR(t.TempDir(), "tls-agent", "tls-test-key")
	if err != nil {
		t.Fatalf("generate protected CSR: %v", err)
	}
	if pending.signer == nil {
		t.Fatal("protected CSR did not retain a signer")
	}
	defer func() {
		if signer, ok := pending.signer.(*cngSigner); ok {
			signer.close()
		}
	}()
	now := time.Now().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "tls-agent"},
		NotBefore: now, NotAfter: now.Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pending.signer.Public(), pending.signer)
	if err != nil {
		t.Fatalf("sign certificate with protected key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	cert, err := tlsCertificateWithSigner(certPEM, pending.PrivateKeyPEM, pending.signer)
	if err != nil {
		t.Fatalf("build TLS certificate with protected key: %v", err)
	}
	if _, err := cert.PrivateKey.(crypto.Signer).Sign(rand.Reader, make([]byte, 32), crypto.SHA256); err != nil {
		t.Fatalf("sign TLS handshake digest with protected key: %v", err)
	}
}

func TestWindowsTPMPrivateKeyExportIsRejected(t *testing.T) {
	pending, err := generateProtectedClientCSR(t.TempDir(), "export-agent", "export-test-key")
	if err != nil {
		t.Fatalf("generate protected CSR: %v", err)
	}
	signer, ok := pending.signer.(*cngSigner)
	if !ok {
		t.Skip("TPM/CNG provider unavailable; DPAPI fallback is covered separately")
	}
	defer signer.close()
	blobType, err := ncryptUTF16("PKCS8_PRIVATEKEY")
	if err != nil {
		t.Fatal(err)
	}
	var size uint32
	status, _, _ := procNCryptExportKey.Call(uintptr(signer.key), 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if status == 0 {
		t.Fatal("non-exportable TPM/CNG private key was exportable")
	}
}

func TestWindowsLegacyPlaintextIdentityMigration(t *testing.T) {
	dataDir := t.TempDir()
	certPEM, keyPEM := testIdentityMaterial(t, "legacy-agent")
	root := identityStoreRoot(dataDir, false)
	if err := os.MkdirAll(root, 0700); err != nil {
		t.Fatal(err)
	}
	generation := "gen-0000000000000001-1ead"
	path := filepath.Join(root, generation)
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(identityMetadata{CredentialID: "legacy-credential", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"key": keyPEM, "cert": certPEM, "meta.json": meta} {
		if err := os.WriteFile(filepath.Join(path, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeCurrentPointer(root, generation); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyKeyStorage(dataDir); err != nil {
		t.Fatalf("migrate legacy identity: %v", err)
	}
	loaded, err := LoadClientIdentity(dataDir)
	if err != nil || loaded == nil || loaded.CredentialID != "legacy-credential" {
		t.Fatalf("migrated identity unavailable: %v %#v", err, loaded)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("legacy plaintext generation was not removed: %v", err)
	}
	current, err := os.ReadFile(filepath.Join(root, identityCurrentFile))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := os.ReadFile(filepath.Join(root, string(bytes.TrimSpace(current)), "key"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(stored, []byte("PRIVATE KEY")) {
		t.Fatal("migrated identity still contains plaintext PEM")
	}
}

func TestWindowsLegacyMigrationFailureKeepsSource(t *testing.T) {
	dataDir := t.TempDir()
	root := identityStoreRoot(dataDir, false)
	generation := "gen-0000000000000002-1bad"
	path := filepath.Join(root, generation)
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "key"), []byte("not-a-key"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "cert"), []byte("not-a-cert"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "meta.json"), []byte(`{"credential_id":"bad","expires_at":"2030-01-01T00:00:00Z"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeCurrentPointer(root, generation); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyKeyStorage(dataDir); err == nil {
		t.Fatal("invalid legacy identity migration unexpectedly succeeded")
	}
	if _, err := os.Stat(filepath.Join(path, "key")); err != nil {
		t.Fatalf("legacy key was removed after failed migration: %v", err)
	}
}

func TestWindowsLegacyMigrationRetryAfterDurabilityFailure(t *testing.T) {
	dataDir := t.TempDir()
	certPEM, keyPEM := testIdentityMaterial(t, "legacy-retry")
	root := identityStoreRoot(dataDir, false)
	generation := "gen-0000000000000003-1e7c"
	path := filepath.Join(root, generation)
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	meta, err := json.Marshal(identityMetadata{CredentialID: "legacy-retry", ExpiresAt: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"key": keyPEM, "cert": certPEM, "meta.json": meta} {
		if err := os.WriteFile(filepath.Join(path, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := writeCurrentPointer(root, generation); err != nil {
		t.Fatal(err)
	}
	originalSync := syncIdentityDirectory
	syncIdentityDirectory = func(string) error { return errors.New("simulated durability failure") }
	firstErr := MigrateLegacyKeyStorage(dataDir)
	syncIdentityDirectory = originalSync
	if firstErr == nil {
		t.Fatal("migration unexpectedly succeeded during durability failure")
	}
	if _, err := os.Stat(filepath.Join(path, "key")); err != nil {
		t.Fatalf("legacy key disappeared after failed migration: %v", err)
	}
	if err := MigrateLegacyKeyStorage(dataDir); err != nil {
		t.Fatalf("migration retry failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(path, "key")); !os.IsNotExist(err) {
		t.Fatalf("legacy generation remained after successful retry: %v", err)
	}
}
