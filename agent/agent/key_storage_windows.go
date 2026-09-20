//go:build windows
// +build windows

package agent

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	dpapiEnvelopePrefix                   = "PM-DPAPI-USER-V1\x00"
	ncryptMachineKeyFlag          uintptr = 0x00000020 // NCRYPT_MACHINE_KEY_FLAG
	ncryptPersistFlag             uintptr = 0x80000000 // NCRYPT_PERSIST_FLAG
	ncryptSecurityDescriptorFlags         = ncryptPersistFlag | uintptr(windows.DACL_SECURITY_INFORMATION)
	ncryptExportPolicyProperty            = "Export Policy"
	ncryptAllowPlaintextExport            = 0x00000001
	ncryptSecurityDescriptor              = "Security Descr"
	ncryptECCPublicBlob                   = "ECCPUBLICBLOB"
	ncryptECDSAP256Algorithm              = "ECDSA_P256"
	ncryptPlatformProvider                = "Microsoft Platform Crypto Provider"
	ncryptSoftwareProvider                = "Microsoft Software Key Storage Provider"
)

var ncrypt = windows.NewLazySystemDLL("ncrypt.dll")

var (
	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procNCryptSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procNCryptGetProperty         = ncrypt.NewProc("NCryptGetProperty")
	procNCryptFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptExportKey           = ncrypt.NewProc("NCryptExportKey")
	procNCryptDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
	procNCryptSignHash            = ncrypt.NewProc("NCryptSignHash")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

type cngSigner struct {
	provider windows.Handle
	key      windows.Handle
	public   *ecdsa.PublicKey
}

func (s *cngSigner) Public() crypto.PublicKey { return s.public }

func (s *cngSigner) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, fmt.Errorf("CNG signing digest is empty")
	}
	var size uint32
	status, _, _ := procNCryptSignHash.Call(uintptr(s.key), 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return nil, syscall.Errno(status)
	}
	if size == 0 || size > 512 {
		return nil, fmt.Errorf("invalid CNG signature size %d", size)
	}
	raw := make([]byte, size)
	status, _, _ = procNCryptSignHash.Call(uintptr(s.key), 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)), uintptr(unsafe.Pointer(&raw[0])), uintptr(len(raw)), uintptr(unsafe.Pointer(&size)), 0)
	if status != 0 {
		return nil, syscall.Errno(status)
	}
	if len(raw) != 64 {
		return nil, fmt.Errorf("unexpected P-256 CNG signature size %d", len(raw))
	}
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(raw[:32]), new(big.Int).SetBytes(raw[32:])})
}

func (s *cngSigner) close() {
	if s == nil {
		return
	}
	if s.key != 0 {
		_, _, _ = procNCryptFreeObject.Call(uintptr(s.key))
		s.key = 0
	}
	if s.provider != 0 {
		_, _, _ = procNCryptFreeObject.Call(uintptr(s.provider))
		s.provider = 0
	}
}

func ncryptStatus(status uintptr) error {
	if status == 0 {
		return nil
	}
	return syscall.Errno(status)
}

func ncryptUTF16(value string) (*uint16, error) {
	return windows.UTF16PtrFromString(value)
}

// readCNGProperty reads a bounded persisted CNG property. Security descriptor
// callers must pass the SECURITY_INFORMATION selector required by NCrypt for
// that property (for example, DACL_SECURITY_INFORMATION).
func readCNGProperty(key windows.Handle, propertyName string, flags uintptr) ([]byte, error) {
	property, err := ncryptUTF16(propertyName)
	if err != nil {
		return nil, err
	}
	var size uint32
	status, _, _ := procNCryptGetProperty.Call(
		uintptr(key), uintptr(unsafe.Pointer(property)), 0, 0,
		uintptr(unsafe.Pointer(&size)), flags,
	)
	if err := ncryptStatus(status); err != nil {
		return nil, fmt.Errorf("read CNG property %q size: %w", propertyName, err)
	}
	if size == 0 || size > 1<<20 {
		return nil, fmt.Errorf("invalid CNG property %q size %d", propertyName, size)
	}
	value := make([]byte, size)
	status, _, _ = procNCryptGetProperty.Call(
		uintptr(key), uintptr(unsafe.Pointer(property)), uintptr(unsafe.Pointer(&value[0])), uintptr(len(value)),
		uintptr(unsafe.Pointer(&size)), flags,
	)
	if err := ncryptStatus(status); err != nil {
		return nil, fmt.Errorf("read CNG property %q: %w", propertyName, err)
	}
	if size > uint32(len(value)) {
		return nil, fmt.Errorf("CNG property %q grew unexpectedly", propertyName)
	}
	return value[:size], nil
}

func openCNGProvider(name string) (windows.Handle, error) {
	providerName, err := ncryptUTF16(name)
	if err != nil {
		return 0, err
	}
	var provider windows.Handle
	status, _, _ := procNCryptOpenStorageProvider.Call(uintptr(unsafe.Pointer(&provider)), uintptr(unsafe.Pointer(providerName)), 0)
	if err := ncryptStatus(status); err != nil {
		return 0, err
	}
	return provider, nil
}

func createCNGKey(provider windows.Handle, keyName string) (windows.Handle, error) {
	return createCNGKeyWithACL(provider, keyName, setCNGKeyServiceACL)
}

func createCNGKeyWithACL(provider windows.Handle, keyName string, applyACL func(windows.Handle) error) (windows.Handle, error) {
	algorithm, err := ncryptUTF16(ncryptECDSAP256Algorithm)
	if err != nil {
		return 0, err
	}
	name, err := ncryptUTF16(keyName)
	if err != nil {
		return 0, err
	}
	var key windows.Handle
	status, _, _ := procNCryptCreatePersistedKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(algorithm)), uintptr(unsafe.Pointer(name)), 0, ncryptMachineKeyFlag, 0)
	if err := ncryptStatus(status); err != nil {
		return 0, err
	}
	// Explicitly deny plaintext export. The Platform Crypto Provider also
	// enforces this in hardware for TPM-backed keys.
	policy := uint32(0)
	property, err := ncryptUTF16(ncryptExportPolicyProperty)
	if err != nil {
		return 0, err
	}
	status, _, _ = procNCryptSetProperty.Call(uintptr(key), uintptr(unsafe.Pointer(property)), uintptr(unsafe.Pointer(&policy)), unsafe.Sizeof(policy), 0)
	if err := ncryptStatus(status); err != nil {
		_, _, _ = procNCryptDeleteKey.Call(uintptr(key), 0)
		_, _, _ = procNCryptFreeObject.Call(uintptr(key))
		return 0, err
	}
	if err := applyACL(key); err != nil {
		_, _, _ = procNCryptDeleteKey.Call(uintptr(key), 0)
		_, _, _ = procNCryptFreeObject.Call(uintptr(key))
		return 0, fmt.Errorf("apply CNG key ACL: %w", err)
	}
	status, _, _ = procNCryptFinalizeKey.Call(uintptr(key), 0)
	if err := ncryptStatus(status); err != nil {
		_, _, _ = procNCryptDeleteKey.Call(uintptr(key), 0)
		_, _, _ = procNCryptFreeObject.Call(uintptr(key))
		return 0, err
	}
	return key, nil
}

func setCNGKeyServiceACL(key windows.Handle) error {
	serviceSID, _, _, err := windows.LookupSID("", windowsPrintMasterServiceAccount)
	if err != nil {
		return fmt.Errorf("resolve Agent service SID for CNG key: %w", err)
	}
	return setCNGKeyACL(key, serviceSID)
}

func setCNGKeyACL(key windows.Handle, serviceSID *windows.SID) error {
	if serviceSID == nil {
		return fmt.Errorf("CNG key ACL service SID is nil")
	}
	sd, err := cngKeySecurityDescriptor(serviceSID)
	if err != nil {
		return err
	}
	length := sd.Length()
	if length == 0 {
		return fmt.Errorf("CNG key ACL is empty")
	}
	descriptor := unsafe.Slice((*byte)(unsafe.Pointer(sd)), length)
	property, err := ncryptUTF16(ncryptSecurityDescriptor)
	if err != nil {
		return err
	}
	status, _, _ := procNCryptSetProperty.Call(uintptr(key), uintptr(unsafe.Pointer(property)), uintptr(unsafe.Pointer(&descriptor[0])), uintptr(length), ncryptSecurityDescriptorFlags)
	if err := ncryptStatus(status); err != nil {
		return fmt.Errorf("set CNG key DACL: %w", err)
	}
	return nil
}

func cngKeySecurityDescriptor(serviceSID *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	if serviceSID == nil {
		return nil, fmt.Errorf("CNG key ACL service SID is nil")
	}
	sddl := fmt.Sprintf("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;%s)", serviceSID.String())
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("build CNG key ACL: %w", err)
	}
	return sd, nil
}

func openCNGKey(provider windows.Handle, keyName string) (windows.Handle, error) {
	name, err := ncryptUTF16(keyName)
	if err != nil {
		return 0, err
	}
	var key windows.Handle
	status, _, _ := procNCryptOpenKey.Call(uintptr(provider), uintptr(unsafe.Pointer(&key)), uintptr(unsafe.Pointer(name)), 0, ncryptMachineKeyFlag)
	if err := ncryptStatus(status); err != nil {
		return 0, err
	}
	return key, nil
}

func exportCNGPublicKey(key windows.Handle) (*ecdsa.PublicKey, error) {
	blobType, err := ncryptUTF16(ncryptECCPublicBlob)
	if err != nil {
		return nil, err
	}
	var size uint32
	status, _, _ := procNCryptExportKey.Call(uintptr(key), 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&size)), 0)
	if err := ncryptStatus(status); err != nil {
		return nil, err
	}
	if size < 8 || size > 4096 {
		return nil, fmt.Errorf("invalid CNG public key size %d", size)
	}
	blob := make([]byte, size)
	status, _, _ = procNCryptExportKey.Call(uintptr(key), 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&blob[0])), uintptr(len(blob)), uintptr(unsafe.Pointer(&size)), 0)
	if err := ncryptStatus(status); err != nil {
		return nil, err
	}
	cbKey := binary.LittleEndian.Uint32(blob[4:8])
	if cbKey != 32 || uint64(8+2*cbKey) > uint64(size) {
		return nil, fmt.Errorf("unexpected CNG public key length %d", cbKey)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(blob[8 : 8+cbKey]), Y: new(big.Int).SetBytes(blob[8+cbKey : 8+2*cbKey])}, nil
}

func newCNGSigner(keyName string, create bool) (*cngSigner, error) {
	return newCNGSignerWithProvider(ncryptPlatformProvider, keyName, create)
}

func newCNGSignerWithProvider(providerName, keyName string, create bool) (*cngSigner, error) {
	provider, err := openCNGProvider(providerName)
	if err != nil {
		return nil, err
	}
	var key windows.Handle
	if create {
		key, err = createCNGKey(provider, keyName)
	} else {
		key, err = openCNGKey(provider, keyName)
	}
	if err != nil {
		_, _, _ = procNCryptFreeObject.Call(uintptr(provider))
		return nil, err
	}
	public, err := exportCNGPublicKey(key)
	if err != nil {
		_, _, _ = procNCryptFreeObject.Call(uintptr(key))
		_, _, _ = procNCryptFreeObject.Call(uintptr(provider))
		return nil, err
	}
	return &cngSigner{provider: provider, key: key, public: public}, nil
}

func generateProtectedClientCSR(dataDir, agentID, keyID string) (*PendingIdentity, error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, fmt.Errorf("agent id required")
	}
	keyName := "PrintMaster-Agent-" + keyID
	var cngFailures []error
	// Prefer a hardware-backed key. If the platform provider is unavailable,
	// use the Microsoft software CNG provider with the same non-exportable
	// policy and service ACL before falling back to user-scoped DPAPI.
	for _, candidate := range []struct {
		provider string
		backend  string
	}{
		{provider: ncryptPlatformProvider, backend: keyBackendTPM},
		{provider: ncryptSoftwareProvider, backend: keyBackendCNG},
	} {
		signer, err := newCNGSignerWithProvider(candidate.provider, keyName, true)
		if err != nil {
			cngFailures = append(cngFailures, fmt.Errorf("%s: %w", candidate.provider, err))
			continue
		}
		csrDER, csrErr := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "PrintMaster Agent"}}, signer)
		if csrErr == nil {
			return &PendingIdentity{CSRPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), AgentID: agentID, KeyBackend: candidate.backend, KeyReference: keyName, signer: signer}, nil
		}
		cngFailures = append(cngFailures, fmt.Errorf("%s CSR: %w", candidate.provider, csrErr))
		_, _, _ = procNCryptDeleteKey.Call(uintptr(signer.key), 0)
		signer.close()
	}
	// A TPM/CNG failure is not silently downgraded to machine-wide DPAPI. The
	// user-scoped DPAPI fallback is bound to the service account and still keeps
	// plaintext key bytes out of the identity generations.
	if err := requirePrintMasterServiceIdentity(); err != nil {
		if len(cngFailures) > 0 {
			return nil, fmt.Errorf("CNG providers unavailable (%v); refusing DPAPI fallback: %w", errors.Join(cngFailures...), err)
		}
		return nil, fmt.Errorf("refusing DPAPI fallback: %w", err)
	}
	pending, err := generateSoftwareClientCSR(agentID)
	if err != nil {
		return nil, err
	}
	pending.KeyBackend = keyBackendDPAPI
	return pending, nil
}

func protectPrivateKeyPlatform(_ string, privateKeyPEM []byte, ref keyReference) ([]byte, keyReference, error) {
	ref = ref.normalized()
	if isCNGKeyBackend(ref.Backend) {
		if ref.Reference == "" || len(privateKeyPEM) != 0 {
			return nil, keyReference{}, fmt.Errorf("invalid CNG key reference material")
		}
		return nil, ref, nil
	}
	if len(privateKeyPEM) == 0 {
		return nil, keyReference{}, fmt.Errorf("private key material missing")
	}
	protected, err := protectWithDPAPI(privateKeyPEM)
	if err != nil {
		return nil, keyReference{}, fmt.Errorf("protect Agent private key with service-scoped DPAPI: %w", err)
	}
	return append([]byte(dpapiEnvelopePrefix), protected...), keyReference{Backend: keyBackendDPAPI}, nil
}

func unprotectPrivateKeyPlatform(_ string, stored []byte, ref keyReference) ([]byte, crypto.Signer, error) {
	ref = ref.normalized()
	if isCNGKeyBackend(ref.Backend) {
		if ref.Reference == "" || len(stored) != 0 {
			return nil, nil, fmt.Errorf("invalid CNG key reference storage")
		}
		provider := ncryptPlatformProvider
		if ref.Backend == keyBackendCNG {
			provider = ncryptSoftwareProvider
		}
		signer, err := newCNGSignerWithProvider(provider, ref.Reference, false)
		if err != nil {
			return nil, nil, fmt.Errorf("open CNG Agent key: %w", err)
		}
		return nil, signer, nil
	}
	// P0-01 generations written before Windows key protection used a raw PEM
	// file and omitted the backend metadata. Read that format only for the
	// one-time migration path; all new writes use DPAPI or a CNG reference.
	if ref.Backend == keyBackendSoftware && strings.HasPrefix(string(stored), "-----BEGIN ") {
		signer, err := signerFromPEM(stored)
		return stored, signer, err
	}
	if len(stored) >= len(dpapiEnvelopePrefix) && string(stored[:len(dpapiEnvelopePrefix)]) == dpapiEnvelopePrefix {
		stored = stored[len(dpapiEnvelopePrefix):]
	}
	plain, err := unprotectWithDPAPI(stored)
	if err != nil {
		return nil, nil, fmt.Errorf("unprotect Agent private key with service-scoped DPAPI: %w", err)
	}
	signer, err := signerFromPEM(plain)
	return plain, signer, err
}

func protectWithDPAPI(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fmt.Errorf("empty secret")
	}
	if err := requirePrintMasterServiceIdentity(); err != nil {
		return nil, err
	}
	in := windows.DataBlob{Size: uint32(len(plain)), Data: &plain[0]}
	entropyBytes := sha256.Sum256([]byte("PrintMaster Agent DPAPI service identity v1"))
	entropy := windows.DataBlob{Size: uint32(len(entropyBytes)), Data: &entropyBytes[0]}
	var out windows.DataBlob
	if err := windows.CryptProtectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

func migrateLegacyKeyStoragePlatform(dataDir string) error {
	if err := migrateLegacyIdentityRoot(dataDir, false); err != nil {
		return fmt.Errorf("migrate active Agent identity: %w", err)
	}
	if err := migrateLegacyIdentityRoot(dataDir, true); err != nil {
		return fmt.Errorf("migrate pending Agent identity: %w", err)
	}
	if err := migrateLegacyEnrollmentRoot(dataDir); err != nil {
		return fmt.Errorf("migrate pre-enrollment identity: %w", err)
	}
	return nil
}

func migrateLegacyIdentityRoot(dataDir string, pending bool) error {
	root := identityStoreRoot(dataDir, pending)
	store, storeState, storeErr := loadIdentityStore(root)
	if storeErr != nil {
		return storeErr
	}
	if store == nil && storeState == identityStoreAvailable {
		if current := readCurrentPointer(root); isGenerationName(current) {
			if _, readErr := readGeneration(root, current); readErr != nil {
				return fmt.Errorf("current identity generation is corrupt: %w", readErr)
			}
		}
	}
	stored, state, err := loadStoredIdentity(dataDir, pending)
	if err != nil {
		return err
	}
	if state == identityStoreTombstone {
		suffix := ""
		if pending {
			suffix = clientIdentityPendingSuffix
		}
		if err := removeLegacyIdentityFiles(dataDir, suffix); err != nil {
			return fmt.Errorf("remove tombstoned legacy identity files: %w", err)
		}
		return removeLegacyGenerationsWithoutSelection(root)
	}
	desiredCredential := ""
	desiredGeneration := readCurrentPointer(root)
	if stored != nil && stored.identity != nil {
		desiredCredential = stored.identity.CredentialID
	}
	if stored != nil && isLegacyKeyBackend(stored.keyBackend) {
		newGeneration, err := migrateIdentityGeneration(root, stored)
		if err != nil {
			return err
		}
		desiredGeneration = newGeneration
		// A legacy flat set is no longer needed after the protected generation
		// has become current. Removal is deliberately last and failure is fatal.
		if stored.generation == "" {
			suffix := ""
			if pending {
				suffix = clientIdentityPendingSuffix
			}
			if err := removeLegacyIdentityFiles(dataDir, suffix); err != nil {
				return fmt.Errorf("remove legacy identity files: %w", err)
			}
		}
	}
	var migrateErr error
	desiredGeneration, migrateErr = migrateLegacyIdentityGenerations(root, desiredCredential, desiredGeneration)
	if migrateErr != nil {
		return migrateErr
	}
	if isGenerationName(desiredGeneration) {
		if err := writeCurrentPointer(root, desiredGeneration); err != nil {
			return err
		}
	}
	return nil
}

func removeLegacyGenerationsWithoutSelection(root string) error {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isGenerationName(entry.Name()) {
			continue
		}
		stored, readErr := readGeneration(root, entry.Name())
		if readErr == nil && stored != nil && isLegacyKeyBackend(stored.keyBackend) {
			if err := removeLegacyGeneration(root, entry.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

func migrateLegacyIdentityGenerations(root, desiredCredential, desiredGeneration string) (string, error) {
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return desiredGeneration, nil
	}
	if err != nil {
		return desiredGeneration, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isGenerationName(entry.Name()) {
			continue
		}
		stored, readErr := readGeneration(root, entry.Name())
		if readErr != nil || stored == nil || !isLegacyKeyBackend(stored.keyBackend) {
			continue
		}
		newGeneration, err := migrateIdentityGeneration(root, stored)
		if err != nil {
			return desiredGeneration, err
		}
		if stored.identity != nil && stored.identity.CredentialID == desiredCredential {
			desiredGeneration = newGeneration
		}
	}
	return desiredGeneration, nil
}

func migrateIdentityGeneration(root string, stored *storedIdentity) (string, error) {
	if stored == nil || stored.identity == nil || len(stored.privateKeyPEM) == 0 {
		return "", fmt.Errorf("legacy identity has no recoverable private key")
	}
	metadata := identityMetadata{
		CredentialID: stored.identity.CredentialID,
		TenantID:     stored.identity.TenantID,
		ExpiresAt:    stored.identity.ExpiresAt.UTC(),
	}
	oldGeneration := stored.generation
	if err := saveIdentityGenerationWithKey(root, metadata, stored.certificatePEM, stored.privateKeyPEM); err != nil {
		return "", err
	}
	newGeneration := readCurrentPointer(root)
	if !isGenerationName(newGeneration) {
		return "", fmt.Errorf("protected identity migration did not select a generation")
	}
	verified, err := readGeneration(root, newGeneration)
	if err != nil || verified == nil || verified.identity == nil || verified.identity.CredentialID != stored.identity.CredentialID {
		if err == nil {
			err = fmt.Errorf("protected identity verification returned an incomplete generation")
		}
		return "", fmt.Errorf("verify protected identity migration: %w", err)
	}
	if oldGeneration != "" {
		if err := removeLegacyGeneration(root, oldGeneration); err != nil {
			return "", fmt.Errorf("remove legacy identity generation: %w", err)
		}
	}
	return newGeneration, nil
}

func migrateLegacyEnrollmentRoot(dataDir string) error {
	root := enrollmentStoreRoot(dataDir)
	entries, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := recoverEnrollmentTransactions(root); err != nil {
		return err
	}
	currentName := readCurrentPointer(root)
	desiredGeneration := currentName
	desiredAttemptID := ""
	if currentName != identityTombstone {
		if selected, _, selectErr := loadEnrollmentAttemptStore(root); selectErr == nil && selected != nil {
			desiredAttemptID = selected.EnrollmentAttemptID
		}
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isGenerationName(entry.Name()) {
			continue
		}
		attempt, readErr := readEnrollmentGeneration(root, entry.Name())
		if readErr != nil || attempt == nil || !isLegacyKeyBackend(attempt.KeyBackend) {
			continue
		}
		if currentName == identityTombstone {
			if err := removeLegacyGeneration(root, entry.Name()); err != nil {
				return fmt.Errorf("remove completed legacy enrollment generation: %w", err)
			}
			continue
		}
		oldGeneration := entry.Name()
		if err := saveEnrollmentAttempt(dataDir, attempt); err != nil {
			return err
		}
		newGeneration := readCurrentPointer(root)
		if !isGenerationName(newGeneration) {
			return fmt.Errorf("protected enrollment migration did not select a generation")
		}
		verified, verifyErr := readEnrollmentGeneration(root, newGeneration)
		if verifyErr != nil || verified == nil || verified.EnrollmentAttemptID != attempt.EnrollmentAttemptID {
			if verifyErr == nil {
				verifyErr = fmt.Errorf("protected enrollment verification returned an incomplete generation")
			}
			return fmt.Errorf("verify protected enrollment migration: %w", verifyErr)
		}
		if err := removeLegacyGeneration(root, oldGeneration); err != nil {
			return fmt.Errorf("remove legacy enrollment generation: %w", err)
		}
		if attempt.EnrollmentAttemptID == desiredAttemptID {
			desiredGeneration = newGeneration
		}
		currentName = newGeneration
	}
	if isGenerationName(desiredGeneration) {
		if err := writeEnrollmentPointer(root, desiredGeneration); err != nil {
			return err
		}
	}
	return nil
}

func readCurrentPointer(root string) string {
	data, err := os.ReadFile(filepath.Join(root, identityCurrentFile))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func removeLegacyGeneration(root, generation string) error {
	if !isGenerationName(generation) {
		return fmt.Errorf("invalid legacy generation name")
	}
	if err := os.RemoveAll(filepath.Join(root, generation)); err != nil {
		return err
	}
	return syncIdentityDirectoryChecked(root, "", "")
}

func isLegacyKeyBackend(backend string) bool {
	return backend == "" || backend == keyBackendSoftware
}

func unprotectWithDPAPI(protected []byte) ([]byte, error) {
	if len(protected) == 0 {
		return nil, fmt.Errorf("empty protected secret")
	}
	if err := requirePrintMasterServiceIdentity(); err != nil {
		return nil, err
	}
	in := windows.DataBlob{Size: uint32(len(protected)), Data: &protected[0]}
	entropyBytes := sha256.Sum256([]byte("PrintMaster Agent DPAPI service identity v1"))
	entropy := windows.DataBlob{Size: uint32(len(entropyBytes)), Data: &entropyBytes[0]}
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(&in, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}
