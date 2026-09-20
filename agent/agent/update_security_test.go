package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"printmaster/common/updateauth"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
)

func TestUpdatesRequireOfflineSignatureAndKeepTokenOnServer(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := filepath.Join(t.TempDir(), "trust.json")
	doc, _ := json.Marshal(map[string]interface{}{"keys": map[string]string{"offline": base64.StdEncoding.EncodeToString(pub)}})
	if err := os.WriteFile(trust, doc, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PRINTMASTER_UPDATE_TRUST_FILE", trust)
	now := time.Now().UTC()
	hash := sha256.Sum256([]byte("binary"))
	manifest := UpdateManifest{ManifestVersion: "2", Component: "agent", Version: "1.2.3", Platform: runtime.GOOS, Arch: runtime.GOARCH, Channel: "stable", SHA256: hex.EncodeToString(hash[:]), SizeBytes: 6, GeneratedAt: now, ExpiresAt: now.Add(time.Hour), KeyID: "offline"}
	if err := updateauth.Sign(&manifest, key, now); err != nil {
		t.Fatal(err)
	}
	var attackerHits atomic.Int32
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { attackerHits.Add(1) }))
	defer attacker.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer agent-secret" {
			t.Error("agent authentication missing")
			w.WriteHeader(401)
			return
		}
		switch r.URL.Path {
		case "/api/v1/agents/update/manifest":
			json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "manifest": manifest})
		case "/artifact":
			w.Write([]byte("binary"))
		case "/oversized":
			w.Write([]byte("binary-extra-content"))
		case "/redirect":
			http.Redirect(w, r, attacker.URL, http.StatusFound)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client := NewServerClient(server.URL, "agent", "agent-secret")
	manifest.DownloadURL = server.URL + "/artifact"
	verified, err := client.GetLatestManifest(context.Background(), "agent", runtime.GOOS, runtime.GOARCH, "stable")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "update.bin")
	if n, err := client.DownloadArtifact(context.Background(), verified, path, 0); err != nil || n != 6 {
		t.Fatalf("signed download failed: %v", err)
	}
	for _, url := range []string{attacker.URL, server.URL + "/redirect", server.URL + "/oversized"} {
		copy := *verified
		copy.DownloadURL = url
		if _, err := client.DownloadArtifact(context.Background(), &copy, path, 0); err == nil {
			t.Fatalf("unsafe download accepted: %s", url)
		}
	}
	if attackerHits.Load() != 0 {
		t.Fatal("credential-bearing request reached another origin")
	}
	manifest.Signature = ""
	if _, err := client.GetLatestManifest(context.Background(), "agent", runtime.GOOS, runtime.GOARCH, "stable"); err == nil {
		t.Fatal("unsigned manifest accepted")
	}
	t.Setenv("PRINTMASTER_UPDATE_TRUST_FILE", "")
	noTrust := NewServerClient(server.URL, "agent", "agent-secret")
	if _, err := noTrust.DownloadArtifact(context.Background(), verified, path, 0); err == nil {
		t.Fatal("download accepted without locally installed trust")
	}
}

func TestServerClientRejectsInvalidCustomCAAndInsecureVerification(t *testing.T) {
	client := NewServerClientWithName("https://server.example", "agent", "", "token", filepath.Join(t.TempDir(), "missing-ca.pem"), false)
	if _, err := client.Heartbeat(context.Background(), ""); err == nil {
		t.Fatal("missing custom CA fell back to system roots")
	}
	insecure := NewServerClientWithName("https://server.example", "agent", "", "token", "", true)
	if insecure.IsInsecureSkipVerify() {
		t.Fatal("client reports certificate verification disabled")
	}
	if _, err := insecure.Heartbeat(context.Background(), ""); err == nil {
		t.Fatal("insecure TLS verification configuration was accepted")
	}
}
