package autoupdate

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidatePostUpdateWithHealthCheckRejectsRemoteURL(t *testing.T) {
	t.Parallel()

	manager := &Manager{}
	for _, raw := range []string{
		"https://169.254.169.254/latest/meta-data",
		"http://attacker.example/health",
		"file:///etc/passwd",
		"http://127.0.0.1:8080/health?token=secret",
	} {
		if err := manager.ValidatePostUpdateWithHealthCheck(raw, time.Second); err == nil {
			t.Fatalf("expected health URL %q to be rejected", raw)
		}
	}
}

func TestValidatePostUpdateWithHealthCheckAllowsLoopback(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"version":"1.2.3"}`))
	}))
	t.Cleanup(server.Close)

	manager := &Manager{clock: time.Now}
	if err := manager.ValidatePostUpdateWithHealthCheck(server.URL, time.Second); err != nil {
		t.Fatalf("loopback health check failed: %v", err)
	}
}
