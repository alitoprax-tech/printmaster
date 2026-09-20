package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
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

func TestSaveClientIdentityRollsBackOnReplacementFailure(t *testing.T) {
	dataDir := t.TempDir()
	oldCert, oldKey := testIdentityMaterial(t, "old")
	newCert, newKey := testIdentityMaterial(t, "new")
	expires := time.Now().Add(24 * time.Hour)
	if err := SaveClientIdentity(dataDir, "old-credential", expires, oldCert, oldKey); err != nil {
		t.Fatalf("save initial identity: %v", err)
	}

	originalRename := renameIdentityFile
	renameIdentityFile = func(oldPath, newPath string) error {
		if strings.HasSuffix(newPath, clientIdentityCertFile+clientIdentityBackupSuffix) {
			return fmt.Errorf("injected certificate backup failure")
		}
		return os.Rename(oldPath, newPath)
	}
	defer func() { renameIdentityFile = originalRename }()

	if err := SaveClientIdentity(dataDir, "new-credential", expires, newCert, newKey); err == nil {
		t.Fatal("expected replacement failure")
	}
	loaded, err := LoadClientIdentity(dataDir)
	if err != nil {
		t.Fatalf("load identity after failed replacement: %v", err)
	}
	if loaded == nil || loaded.CredentialID != "old-credential" {
		t.Fatalf("failed replacement lost active identity: %#v", loaded)
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
