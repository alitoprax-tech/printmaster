package releases

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"printmaster/server/storage"
)

func TestReleaseURLAllowlist(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://api.github.com/repos/mstrhakr/printmaster/releases",
		"https://objects.githubusercontent.com/release?sig=test",
		"https://release-assets.githubusercontent.com/release",
		"http://127.0.0.1:1234/test",
	} {
		if !isAllowedReleaseURL(raw) {
			t.Fatalf("expected release URL to be allowed: %s", raw)
		}
	}
	for _, raw := range []string{
		"http://github.com/releases",
		"https://attacker.example/release",
		"https://evil.github.com/release",
		"https://evil.githubusercontent.com/release",
		"https://169.254.169.254/latest",
		"https://github.com@attacker.example/release",
		"https://github.com/release#fragment",
	} {
		if isAllowedReleaseURL(raw) {
			t.Fatalf("expected release URL to be rejected: %s", raw)
		}
	}
}

func TestReleaseIntakeRedirectAllowlist(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://objects.githubusercontent.com/release",
		"https://release-assets.githubusercontent.com/release",
		"http://127.0.0.1:1234/release",
	} {
		req := httptest.NewRequest(http.MethodGet, raw, nil)
		if err := checkReleaseIntakeRedirect(req, nil); err != nil {
			t.Fatalf("expected redirect to be allowed: %s: %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://github.com/release",
		"https://attacker.example/release",
		"https://evil.github.com/release",
		"https://evil.githubusercontent.com/release",
		"https://10.0.0.1/release",
	} {
		req := httptest.NewRequest(http.MethodGet, raw, nil)
		if err := checkReleaseIntakeRedirect(req, nil); err == nil {
			t.Fatalf("expected redirect to be rejected: %s", raw)
		}
	}
}

func TestBuildDescriptorRejectsPathLikeAssetNames(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		"printmaster-agent-v1.2.3-windows-amd64.exe/../../outside",
		"printmaster-agent-v1.2.3-windows-amd64.exe\\..\\outside",
		"printmaster-agent-v1.2.3-windows-amd64.exe\n",
	} {
		if _, ok := buildDescriptor("agent", "1.2.3", name); ok {
			t.Fatalf("path-like asset name was accepted: %q", name)
		}
	}
	if desc, ok := buildDescriptor("agent", "1.2.3", "printmaster-agent-v1.2.3-windows-amd64.exe"); !ok || desc.fileName == "" {
		t.Fatal("valid release asset was rejected")
	}
}

func TestIntakeWorkerCachesArtifacts(t *testing.T) {
	t.Parallel()

	mux := http.NewServeMux()
	var downloadURL string
	downloadHits := 0

	mux.HandleFunc("/repos/test-owner/printmaster/releases", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		payload := `[
            {
                "tag_name": "server-v0.9.16",
                "draft": false,
                "prerelease": false,
                "body": "notes",
                "published_at": "2025-11-20T12:00:00Z",
                "assets": [
                    {
                        "name": "printmaster-server-v0.9.16-windows-amd64.exe",
                        "browser_download_url": "` + downloadURL + `",
                        "size": 11,
                        "updated_at": "2025-11-20T12:00:00Z"
                    }
                ]
            }
        ]`
		_, _ = w.Write([]byte(payload))
	})

	mux.HandleFunc("/downloads/server", func(w http.ResponseWriter, r *http.Request) {
		downloadHits++
		_, _ = w.Write([]byte("printmaster"))
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	downloadURL = server.URL + "/downloads/server"

	store, err := storage.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatalf("failed to init store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	worker, err := NewIntakeWorker(store, nil, Options{
		CacheDir:     t.TempDir(),
		RepoOwner:    "test-owner",
		RepoName:     "printmaster",
		BaseAPIURL:   server.URL,
		HTTPClient:   server.Client(),
		PollInterval: time.Hour,
		UserAgent:    "test",
	})
	if err != nil {
		t.Fatalf("failed to create worker: %v", err)
	}

	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("run once failed: %v", err)
	}

	art, err := store.GetReleaseArtifact(context.Background(), "server", "0.9.16", "windows", "amd64")
	if err != nil {
		t.Fatalf("artifact not persisted: %v", err)
	}
	if art.CachePath == "" {
		t.Fatalf("expected cache path to be set")
	}
	if _, err := os.Stat(art.CachePath); err != nil {
		t.Fatalf("cached file missing: %v", err)
	}

	firstHits := downloadHits
	if err := worker.RunOnce(context.Background()); err != nil {
		t.Fatalf("second run failed: %v", err)
	}
	if downloadHits != firstHits {
		t.Fatalf("expected cached artifact to skip download")
	}

}
