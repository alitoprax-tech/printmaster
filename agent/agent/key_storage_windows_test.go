//go:build windows
// +build windows

package agent

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestMain(m *testing.M) {
	// Most package tests run as the interactive test runner rather than the
	// installed service. Keep the DPAPI fallback tests deterministic by
	// injecting the service identity at the test boundary; the wrong-user test
	// below overrides only the current SID and verifies the production gate.
	fakeServiceSID, err := windows.StringToSid("S-1-5-21-111111111-222222222-333333333-4242")
	if err != nil {
		os.Exit(1)
	}
	oldCurrent := currentWindowsProcessSID
	oldExpected := lookupPrintMasterServiceSID
	currentWindowsProcessSID = func() (*windows.SID, error) { return fakeServiceSID, nil }
	lookupPrintMasterServiceSID = func() (*windows.SID, error) { return fakeServiceSID, nil }
	code := m.Run()
	currentWindowsProcessSID = oldCurrent
	lookupPrintMasterServiceSID = oldExpected
	os.Exit(code)
}

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

func TestWindowsDPAPIRejectsWrongUserContext(t *testing.T) {
	serviceSID, err := windows.StringToSid("S-1-5-21-111111111-222222222-333333333-4242")
	if err != nil {
		t.Fatal(err)
	}
	wrongSID, err := windows.StringToSid("S-1-5-21-111111111-222222222-333333333-4243")
	if err != nil {
		t.Fatal(err)
	}
	oldCurrent := currentWindowsProcessSID
	oldExpected := lookupPrintMasterServiceSID
	t.Cleanup(func() {
		currentWindowsProcessSID = oldCurrent
		lookupPrintMasterServiceSID = oldExpected
	})
	lookupPrintMasterServiceSID = func() (*windows.SID, error) { return serviceSID, nil }
	currentWindowsProcessSID = func() (*windows.SID, error) { return serviceSID, nil }
	if err := requirePrintMasterServiceIdentity(); err != nil {
		t.Fatalf("expected service identity to pass the DPAPI gate: %v", err)
	}
	_, plain := testIdentityMaterial(t, "dpapi-wrong-user")
	currentWindowsProcessSID = func() (*windows.SID, error) { return wrongSID, nil }
	if _, err := protectWithDPAPI(plain); err == nil {
		t.Fatal("wrong Windows user context unexpectedly reached DPAPI")
	}
	dataDir := t.TempDir()
	if _, _, err := protectPrivateKeyPlatform(dataDir, plain, keyReference{Backend: keyBackendDPAPI}); err == nil {
		t.Fatal("wrong Windows user context unexpectedly persisted a DPAPI key")
	}
	entries, err := os.ReadDir(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("wrong-user DPAPI fallback wrote %d filesystem entries", len(entries))
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
	if pending.KeyBackend != keyBackendTPM {
		if signer, ok := pending.signer.(*cngSigner); ok {
			signer.close()
		}
		t.Skip("TPM provider unavailable; Software KSP is covered by the non-skippable integration test")
	}
	signer, ok := pending.signer.(*cngSigner)
	if !ok {
		t.Fatal("TPM enrollment did not return a CNG signer")
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

func TestWindowsSoftwareKSPNonExportablePersistedKey(t *testing.T) {
	provider, err := openCNGProvider(ncryptSoftwareProvider)
	if err != nil {
		t.Fatalf("open Microsoft Software Key Storage Provider: %v", err)
	}
	providerOpen := true
	defer func() {
		if providerOpen {
			_, _, _ = procNCryptFreeObject.Call(uintptr(provider))
		}
	}()

	controlledSID, err := currentWindowsProcessSIDPlatform()
	if err != nil {
		t.Fatalf("read controlled test SID: %v", err)
	}
	keyID, err := newEnrollmentAttemptID()
	if err != nil {
		t.Fatalf("generate unique CNG test key name: %v", err)
	}
	keyName := fmt.Sprintf("PrintMaster-SoftwareKSP-Test-%s", keyID)
	key, err := createCNGKeyWithACL(provider, keyName, func(key windows.Handle) error {
		return setCNGKeyACL(key, controlledSID)
	})
	if err != nil {
		t.Fatalf("create persisted Software KSP key: %v", err)
	}
	keyOpen := true
	defer func() {
		if keyOpen {
			_, _, _ = procNCryptDeleteKey.Call(uintptr(key), 0)
		}
	}()

	securityDescriptor, err := readCNGProperty(key, ncryptSecurityDescriptor, uintptr(windows.DACL_SECURITY_INFORMATION))
	if err != nil {
		t.Fatalf("read persisted CNG security descriptor: %v", err)
	}
	assertCNGDACLContains(t, securityDescriptor, controlledSID)
	assertCNGDACLExcludesBroadPrincipals(t, securityDescriptor)

	exportPolicy, err := readCNGProperty(key, ncryptExportPolicyProperty, 0)
	if err != nil {
		t.Fatalf("read persisted CNG export policy: %v", err)
	}
	if len(exportPolicy) < 4 || binary.LittleEndian.Uint32(exportPolicy[:4])&ncryptAllowPlaintextExport != 0 {
		t.Fatalf("CNG export policy permits plaintext export: %#v", exportPolicy)
	}

	public, err := exportCNGPublicKey(key)
	if err != nil {
		t.Fatalf("export CNG public key: %v", err)
	}
	firstSigner := &cngSigner{provider: provider, key: key, public: public}
	if err := assertCNGSignature(firstSigner, "software-ksp-first"); err != nil {
		t.Fatal(err)
	}
	firstSigner.close()
	providerOpen = false
	keyOpen = false

	provider, err = openCNGProvider(ncryptSoftwareProvider)
	if err != nil {
		t.Fatalf("reopen Microsoft Software Key Storage Provider: %v", err)
	}
	providerOpen = true
	key, err = openCNGKey(provider, keyName)
	if err != nil {
		t.Fatalf("reopen persisted Software KSP key: %v", err)
	}
	keyOpen = true
	public, err = exportCNGPublicKey(key)
	if err != nil {
		t.Fatalf("export public key after reopen: %v", err)
	}
	secondSigner := &cngSigner{provider: provider, key: key, public: public}
	if err := assertCNGSignature(secondSigner, "software-ksp-reopen"); err != nil {
		t.Fatal(err)
	}
	privateBlob, err := ncryptUTF16("PKCS8_PRIVATEKEY")
	if err != nil {
		t.Fatal(err)
	}
	var privateSize uint32
	status, _, _ := procNCryptExportKey.Call(uintptr(key), 0, uintptr(unsafe.Pointer(privateBlob)), 0, 0, 0, uintptr(unsafe.Pointer(&privateSize)), 0)
	if status == 0 {
		t.Fatal("non-exportable Software KSP private key was exportable")
	}
	secondSigner.close()
	providerOpen = false
	keyOpen = false

	// Delete the test key only after all reopen/sign/export assertions have
	// completed. NCryptDeleteKey also invalidates the key handle.
	provider, err = openCNGProvider(ncryptSoftwareProvider)
	if err != nil {
		t.Fatalf("open provider for test-key cleanup: %v", err)
	}
	providerOpen = true
	key, err = openCNGKey(provider, keyName)
	if err != nil {
		t.Fatalf("open test key for cleanup: %v", err)
	}
	keyOpen = true
	status, _, _ = procNCryptDeleteKey.Call(uintptr(key), 0)
	if err := ncryptStatus(status); err != nil {
		t.Fatalf("delete Software KSP test key: %v", err)
	}
	keyOpen = false
	_, _, _ = procNCryptFreeObject.Call(uintptr(provider))
	providerOpen = false
}

func assertCNGSignature(signer *cngSigner, label string) error {
	digest := sha256.Sum256([]byte(label))
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("%s CNG signature: %w", label, err)
	}
	if !ecdsa.VerifyASN1(signer.public, digest[:], signature) {
		return fmt.Errorf("%s CNG signature did not verify", label)
	}
	return nil
}

func assertCNGDACLContains(t *testing.T, descriptor []byte, expected *windows.SID) {
	t.Helper()
	if len(descriptor) == 0 {
		t.Fatal("CNG security descriptor is empty")
	}
	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&descriptor[0]))
	if !sd.IsValid() {
		t.Fatalf("CNG security descriptor is invalid: %s", sd.String())
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("CNG security descriptor has no DACL: %v", err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if expected.Equals(aceSID) {
			return
		}
	}
	t.Fatalf("CNG DACL does not contain expected SID %s (SDDL %q)", expected.String(), sd.String())
}

func assertCNGDACLExcludesBroadPrincipals(t *testing.T, descriptor []byte) {
	t.Helper()
	broad := []*windows.SID{}
	for _, value := range []string{"S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-7"} {
		sid, err := windows.StringToSid(value)
		if err != nil {
			t.Fatal(err)
		}
		broad = append(broad, sid)
	}
	sd := (*windows.SECURITY_DESCRIPTOR)(unsafe.Pointer(&descriptor[0]))
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("read CNG DACL for broad-principal check: %v", err)
	}
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil || ace == nil {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		for _, sid := range broad {
			if sid.Equals(aceSID) {
				t.Fatalf("CNG DACL contains broad principal %s (SDDL %q)", sid.String(), sd.String())
			}
		}
	}
}

func TestCNGServiceACLDescriptorContainsOnlyRequiredPrincipals(t *testing.T) {
	serviceSID, err := windows.StringToSid("S-1-5-80-123456789-123456789-123456789-123456789-123456789")
	if err != nil {
		t.Fatal(err)
	}
	sd, err := cngKeySecurityDescriptor(serviceSID)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := unsafe.Slice((*byte)(unsafe.Pointer(sd)), sd.Length())
	assertCNGDACLContains(t, descriptor, serviceSID)
	assertCNGDACLExcludesBroadPrincipals(t, descriptor)
	if !strings.Contains(sd.String(), "SY") || !strings.Contains(sd.String(), "BA") {
		t.Fatalf("service ACL omitted SYSTEM or Administrators: %q", sd.String())
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
