package updateauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSignedManifestRejectsTamperingAndUntrustedAuthority(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	sum := sha256.Sum256([]byte("binary"))
	m := Manifest{ManifestVersion: "2", Component: "agent", Version: "1.2.3", Platform: "windows", Arch: "amd64", Channel: "stable", SHA256: hex.EncodeToString(sum[:]), SizeBytes: 6, GeneratedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "offline-key"}
	if err := Sign(&m, key, now); err != nil {
		t.Fatal(err)
	}
	target := Target{"agent", "windows", "amd64", "stable"}
	keys := Keyring{"offline-key": pub}
	if err := keys.Verify(&m, target, now); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Manifest){
		func(m *Manifest) { m.Version = "1.2.4" }, func(m *Manifest) { m.SizeBytes++ },
		func(m *Manifest) { m.SHA256 = hex.EncodeToString(make([]byte, 32)) },
		func(m *Manifest) { m.Component = "server" }, func(m *Manifest) { m.Platform = "linux" },
		func(m *Manifest) { m.Arch = "arm64" }, func(m *Manifest) { m.Channel = "dev" },
		func(m *Manifest) { m.KeyID = "server-controlled" }, func(m *Manifest) { m.Signature = "" },
		func(m *Manifest) { m.Version = "../../malware" }, func(m *Manifest) { m.ExpiresAt = now.Add(-time.Second) },
		func(m *Manifest) { m.GeneratedAt = now.Add(time.Hour) },
	} {
		copy := m
		mutate(&copy)
		if keys.Verify(&copy, target, now) == nil {
			t.Fatal("tampered manifest accepted")
		}
	}
	if (Keyring{}).Verify(&m, target, now) == nil {
		t.Fatal("untrusted key accepted")
	}
	copy := m
	copy.DownloadURL = "/local/relay"
	if err := keys.Verify(&copy, target, now); err != nil {
		t.Fatal("relay URL should not affect the signed artifact")
	}
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("binary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(path, &m); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("binary-extra"), 0600); err != nil {
		t.Fatal(err)
	}
	if VerifyFile(path, &m) == nil {
		t.Fatal("oversized artifact accepted")
	}
}

func TestMissingAndMalformedKeyringFailClosed(t *testing.T) {
	if _, err := LoadKeyring(""); err == nil {
		t.Fatal("missing keyring accepted")
	}
	for _, body := range []string{`{"keys":{}}`, `{"keys":{"key":"invalid"}}`, `{"keys":{}} {}`} {
		path := filepath.Join(t.TempDir(), "keys.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadKeyring(path); err == nil {
			t.Fatal("invalid keyring accepted")
		}
	}
}
