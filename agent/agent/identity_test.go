package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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
)

func testIdentityMaterial(t *testing.T, commonName string) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("generate certificate serial: %v", err)
	}
	now := time.Now().Add(-time.Minute)
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    now,
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal test key: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func TestIdentityGenerationCrashCheckpoints(t *testing.T) {
	checkpoints := []string{
		checkpointAfterKeyWrite,
		checkpointAfterKeyFsync,
		checkpointAfterCertWrite,
		checkpointAfterCertFsync,
		checkpointAfterMetaWrite,
		checkpointAfterMetaFsync,
		checkpointBeforeGenerationDirFsync,
		checkpointAfterGenerationDirFsync,
		checkpointBeforePointerSwitch,
		checkpointAfterPointerSwitch,
		checkpointBeforeOldCleanup,
		checkpointAfterOldCleanup,
	}
	expires := time.Now().Add(24 * time.Hour)
	for _, checkpoint := range checkpoints {
		t.Run(checkpoint, func(t *testing.T) {
			dataDir := t.TempDir()
			oldCert, oldKey := testIdentityMaterial(t, "old")
			newCert, newKey := testIdentityMaterial(t, "new")
			if err := SaveClientIdentity(dataDir, "old-credential", expires, oldCert, oldKey); err != nil {
				t.Fatalf("save baseline identity: %v", err)
			}
			setIdentityCheckpointHook(func(name string) error {
				if name == checkpoint {
					return errors.New("simulated process crash")
				}
				return nil
			})
			_ = SaveClientIdentity(dataDir, "new-credential", expires, newCert, newKey)
			setIdentityCheckpointHook(nil)

			loaded, err := LoadClientIdentity(dataDir)
			if err != nil {
				t.Fatalf("restart load after %s: %v", checkpoint, err)
			}
			if loaded == nil || (loaded.CredentialID != "old-credential" && loaded.CredentialID != "new-credential") {
				t.Fatalf("restart lost both complete identities after %s: %#v", checkpoint, loaded)
			}
		})
	}
}

func TestPreEnrollmentAttemptCrashRecovery(t *testing.T) {
	checkpoints := []string{
		checkpointEnrollmentAfterKeyWrite,
		checkpointEnrollmentAfterKeyFsync,
		checkpointEnrollmentAfterCSRWrite,
		checkpointEnrollmentAfterCSRFsync,
		checkpointEnrollmentAfterMetaWrite,
		checkpointEnrollmentAfterMetaFsync,
		checkpointEnrollmentBeforeGenerationDirFsync,
		checkpointEnrollmentAfterGenerationDirFsync,
		checkpointEnrollmentBeforePointerSwitch,
		checkpointEnrollmentAfterPointerSwitch,
		checkpointEnrollmentBeforeOldCleanup,
		checkpointEnrollmentAfterOldCleanup,
	}
	for _, checkpoint := range checkpoints {
		t.Run(checkpoint, func(t *testing.T) {
			dataDir := t.TempDir()
			setIdentityCheckpointHook(func(name string) error {
				if name == checkpoint {
					return errors.New("simulated process crash")
				}
				return nil
			})
			_, _ = CreateEnrollmentAttempt(dataDir, "agent-pre-enroll")
			setIdentityCheckpointHook(nil)
			loaded, err := LoadEnrollmentAttempt(dataDir, "agent-pre-enroll")
			if err != nil {
				t.Fatalf("restart load after %s: %v", checkpoint, err)
			}
			if loaded == nil || loaded.EnrollmentAttemptID == "" || len(loaded.PrivateKeyPEM) == 0 || len(loaded.CSRPEM) == 0 {
				t.Fatalf("pre-enrollment attempt lost after %s: %#v", checkpoint, loaded)
			}
		})
	}
}

func TestPreEnrollmentAttemptCompleteTombstone(t *testing.T) {
	dataDir := t.TempDir()
	attempt, err := CreateEnrollmentAttempt(dataDir, "agent-complete")
	if err != nil {
		t.Fatal(err)
	}
	if err := CompleteEnrollmentAttempt(dataDir, attempt.EnrollmentAttemptID); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadEnrollmentAttempt(dataDir, "agent-complete")
	if err != nil {
		t.Fatal(err)
	}
	if loaded != nil {
		t.Fatalf("completed pre-enrollment attempt remained selectable: %#v", loaded)
	}
}

func TestPreEnrollmentAttemptCorruptPointerFallsBackToCompleteGeneration(t *testing.T) {
	dataDir := t.TempDir()
	attempt, err := CreateEnrollmentAttempt(dataDir, "agent-pointer-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(enrollmentStoreRoot(dataDir), identityCurrentFile), []byte("corrupt\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadEnrollmentAttempt(dataDir, "agent-pointer-recovery")
	if err != nil {
		t.Fatal(err)
	}
	if loaded == nil || loaded.EnrollmentAttemptID != attempt.EnrollmentAttemptID {
		t.Fatalf("corrupt pointer did not recover complete attempt: %#v", loaded)
	}
}

func TestPendingIdentityCrashCheckpoints(t *testing.T) {
	checkpoints := []string{
		checkpointAfterKeyWrite,
		checkpointAfterKeyFsync,
		checkpointAfterCertWrite,
		checkpointAfterCertFsync,
		checkpointAfterMetaWrite,
		checkpointAfterMetaFsync,
		checkpointBeforeGenerationDirFsync,
		checkpointAfterGenerationDirFsync,
		checkpointBeforePointerSwitch,
		checkpointAfterPointerSwitch,
		checkpointBeforeOldCleanup,
		checkpointAfterOldCleanup,
	}
	expires := time.Now().Add(24 * time.Hour)
	for _, checkpoint := range checkpoints {
		t.Run(checkpoint, func(t *testing.T) {
			dataDir := t.TempDir()
			certPEM, keyPEM := testIdentityMaterial(t, "pending")
			identity, err := BuildClientIdentity("pending-credential", expires, certPEM, keyPEM)
			if err != nil {
				t.Fatalf("build pending identity: %v", err)
			}
			identity.TenantID = "tenant-1"
			setIdentityCheckpointHook(func(name string) error {
				if name == checkpoint {
					return errors.New("simulated process crash")
				}
				return nil
			})
			_ = SavePendingClientIdentity(dataDir, identity, certPEM, keyPEM)
			setIdentityCheckpointHook(nil)

			loaded, err := LoadPendingClientIdentity(dataDir)
			if err != nil {
				t.Fatalf("restart pending load after %s: %v", checkpoint, err)
			}
			if loaded == nil || loaded.CredentialID != "pending-credential" || loaded.TenantID != "tenant-1" {
				t.Fatalf("pending identity lost after %s: %#v", checkpoint, loaded)
			}
		})
	}
}

func TestIdentityPointerCorruptionFallsBackToCompleteGeneration(t *testing.T) {
	dataDir := t.TempDir()
	oldCert, oldKey := testIdentityMaterial(t, "old")
	newCert, newKey := testIdentityMaterial(t, "new")
	expires := time.Now().Add(24 * time.Hour)
	if err := SaveClientIdentity(dataDir, "old-credential", expires, oldCert, oldKey); err != nil {
		t.Fatalf("save old identity: %v", err)
	}
	if err := SaveClientIdentity(dataDir, "new-credential", expires, newCert, newKey); err != nil {
		t.Fatalf("save new identity: %v", err)
	}
	root := identityStoreRoot(dataDir, false)
	if err := os.WriteFile(filepath.Join(root, identityCurrentFile), []byte("../../outside\n"), 0600); err != nil {
		t.Fatalf("corrupt current pointer: %v", err)
	}
	loaded, err := LoadClientIdentity(dataDir)
	if err != nil {
		t.Fatalf("load after corrupt pointer: %v", err)
	}
	if loaded == nil || (loaded.CredentialID != "old-credential" && loaded.CredentialID != "new-credential") {
		t.Fatalf("corrupt pointer discarded all complete generations: %#v", loaded)
	}
	if err := os.WriteFile(filepath.Join(root, identityCurrentFile), []byte("gen-9999999999999999-deadbeef\n"), 0600); err != nil {
		t.Fatalf("point at incomplete generation: %v", err)
	}
	loaded, err = LoadClientIdentity(dataDir)
	if err != nil || loaded == nil {
		t.Fatalf("load after incomplete pointer: identity=%#v err=%v", loaded, err)
	}
	partial := filepath.Join(root, "gen-9999999999999998-deadbeef")
	if err := os.MkdirAll(partial, 0700); err != nil {
		t.Fatalf("create incomplete generation: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, identityCurrentFile), []byte("gen-9999999999999998-deadbeef\n"), 0600); err != nil {
		t.Fatalf("point at partial generation: %v", err)
	}
	loaded, err = LoadClientIdentity(dataDir)
	if err != nil || loaded == nil {
		t.Fatalf("load after partial generation: identity=%#v err=%v", loaded, err)
	}
}

func TestPendingClientIdentityPromotesAfterActivation(t *testing.T) {
	dataDir := t.TempDir()
	certPEM, keyPEM := testIdentityMaterial(t, "pending")
	expires := time.Now().Add(24 * time.Hour)
	identity, err := BuildClientIdentity("pending-credential", expires, certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build identity: %v", err)
	}
	identity.TenantID = "tenant-1"
	if err := SavePendingClientIdentity(dataDir, identity, certPEM, keyPEM); err != nil {
		t.Fatalf("save pending identity: %v", err)
	}
	loadedPending, err := LoadPendingClientIdentity(dataDir)
	if err != nil || loadedPending == nil {
		t.Fatalf("load pending identity: %v", err)
	}
	if loadedPending.TenantID != "tenant-1" {
		t.Fatalf("pending tenant was not persisted: %q", loadedPending.TenantID)
	}
	if err := PromotePendingClientIdentity(dataDir); err != nil {
		t.Fatalf("promote pending identity: %v", err)
	}
	loadedActive, err := LoadClientIdentity(dataDir)
	if err != nil || loadedActive == nil {
		t.Fatalf("load promoted identity: %v", err)
	}
	if loadedActive.CredentialID != "pending-credential" || loadedActive.TenantID != "tenant-1" {
		t.Fatalf("unexpected promoted identity: %#v", loadedActive)
	}
	if pending, err := LoadPendingClientIdentity(dataDir); err != nil || pending != nil {
		t.Fatalf("pending identity was not cleared: identity=%#v err=%v", pending, err)
	}
}

func TestLegacyIdentityRemainsReadableAndPromotable(t *testing.T) {
	dataDir := t.TempDir()
	certPEM, keyPEM := testIdentityMaterial(t, "legacy")
	meta := identityMetadata{CredentialID: "legacy-credential", TenantID: "legacy-tenant", ExpiresAt: time.Now().Add(24 * time.Hour)}
	metaPEM, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("marshal legacy metadata: %v", err)
	}
	paths := identityPaths(dataDir, clientIdentityPendingSuffix)
	if err := os.WriteFile(paths.key, keyPEM, 0600); err != nil {
		t.Fatalf("write legacy key: %v", err)
	}
	if err := os.WriteFile(paths.cert, certPEM, 0600); err != nil {
		t.Fatalf("write legacy certificate: %v", err)
	}
	if err := os.WriteFile(paths.meta, metaPEM, 0600); err != nil {
		t.Fatalf("write legacy metadata: %v", err)
	}
	loaded, err := LoadPendingClientIdentity(dataDir)
	if err != nil || loaded == nil || loaded.CredentialID != meta.CredentialID {
		t.Fatalf("legacy identity was not readable: identity=%#v err=%v", loaded, err)
	}
	if err := PromotePendingClientIdentity(dataDir); err != nil {
		t.Fatalf("promote legacy identity: %v", err)
	}
	active, err := LoadClientIdentity(dataDir)
	if err != nil || active == nil || active.CredentialID != meta.CredentialID || active.TenantID != meta.TenantID {
		t.Fatalf("legacy identity was not migrated: identity=%#v err=%v", active, err)
	}
}

func TestIdentityDirectorySyncFailureIsReturnedAndPreviousIdentitySurvives(t *testing.T) {
	dataDir := t.TempDir()
	oldCert, oldKey := testIdentityMaterial(t, "old")
	newCert, newKey := testIdentityMaterial(t, "new")
	expires := time.Now().Add(24 * time.Hour)
	if err := SaveClientIdentity(dataDir, "old-credential", expires, oldCert, oldKey); err != nil {
		t.Fatalf("save baseline identity: %v", err)
	}
	originalSync := syncIdentityDirectory
	syncIdentityDirectory = func(string) error { return errors.New("simulated directory sync failure") }
	err := SaveClientIdentity(dataDir, "new-credential", expires, newCert, newKey)
	syncIdentityDirectory = originalSync
	if err == nil {
		t.Fatal("expected directory sync failure to be returned")
	}
	loaded, loadErr := LoadClientIdentity(dataDir)
	if loadErr != nil || loaded == nil {
		t.Fatalf("previous complete identity was not recoverable: identity=%#v err=%v", loaded, loadErr)
	}
	if loaded.CredentialID != "old-credential" && loaded.CredentialID != "new-credential" {
		t.Fatalf("unexpected identity after sync failure: %#v", loaded)
	}
}
