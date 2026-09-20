package releases

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"printmaster/common/updateauth"
	"printmaster/server/storage"
)

func TestOfflineManifestRequiresIndependentKeyAndMatchingArtifact(t *testing.T) {
	store, err := storage.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	now := time.Now().UTC()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	trustPath := filepath.Join(t.TempDir(), "trust.json")
	doc, _ := json.Marshal(map[string]interface{}{"keys": map[string]string{"offline": base64.StdEncoding.EncodeToString(pub)}})
	if err := os.WriteFile(trustPath, doc, 0600); err != nil {
		t.Fatal(err)
	}
	manifest := updateauth.Manifest{ManifestVersion: "2", Component: "agent", Version: "1.2.3", Platform: "windows", Arch: "amd64", Channel: "stable", SHA256: strings.Repeat("ab", 32), SizeBytes: 6, GeneratedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "offline", DownloadURL: "https://untrusted.example/artifact"}
	if err := updateauth.Sign(&manifest, key, now); err != nil {
		t.Fatal(err)
	}
	writeManifest := func() {
		t.Helper()
		body, _ := json.Marshal(manifest)
		if err := os.WriteFile(filepath.Join(dir, "release.json"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	writeManifest()
	mgr, err := NewManager(store, nil, ManagerOptions{SignedManifestDir: dir, TrustFile: trustPath, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	get := func() (*AgentUpdateManifest, error) {
		return mgr.GetLatestManifest(ctx, "agent", "windows", "amd64", "stable")
	}
	if _, err := get(); err == nil {
		t.Fatal("missing artifact accepted")
	}
	artifact := &storage.ReleaseArtifact{Component: "agent", Version: "1.2.3", Platform: "windows", Arch: "amd64", Channel: "stable", SHA256: manifest.SHA256, SizeBytes: 6, SourceURL: "https://example.com/agent", CachePath: filepath.Join(t.TempDir(), "agent.exe")}
	if err := store.UpsertReleaseArtifact(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	got, err := get()
	if err != nil {
		t.Fatal(err)
	}
	if got.DownloadURL != "" {
		t.Fatal("untrusted transport hint was retained")
	}
	if err := (updateauth.Keyring{"offline": pub}).Verify(got, updateauth.Target{Component: "agent", Platform: "windows", Arch: "amd64", Channel: "stable"}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetActiveSigningKey(ctx); err == nil {
		t.Fatal("offline serving created a runtime private key")
	}
	artifact.SizeBytes = 7
	if err := store.UpsertReleaseArtifact(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := get(); err == nil {
		t.Fatal("changed cached artifact accepted")
	}
	artifact.SizeBytes = 6
	if err := store.UpsertReleaseArtifact(ctx, artifact); err != nil {
		t.Fatal(err)
	}
	manifest.Signature = ""
	writeManifest()
	if _, err := get(); err == nil {
		t.Fatal("unsigned manifest accepted")
	}
	manifest.ExpiresAt = now.Add(-time.Hour)
	writeManifest()
	if _, err := get(); err == nil {
		t.Fatal("expired manifest accepted")
	}
}
