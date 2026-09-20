package requestauth

import (
	"net/http/httptest"
	"testing"
)

func TestBrowserOriginBoundary(t *testing.T) {
	for _, tc := range []struct {
		origin, site string
		allowed      bool
	}{
		{"", "", true}, {"http://127.0.0.1:8080", "same-origin", true},
		{"https://attacker.example", "cross-site", false}, {"null", "", false},
		{"http://127.0.0.1:9000", "", false}, {"", "same-site", false},
	} {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8080/settings", nil)
		r.Header.Set("Origin", tc.origin)
		r.Header.Set("Sec-Fetch-Site", tc.site)
		if BrowserRequestAllowed(r) != tc.allowed {
			t.Fatalf("unexpected result for origin %q site %q", tc.origin, tc.site)
		}
	}
	if LoopbackHost("attacker.example:8080") || !LoopbackHost("[::1]:8080") || !LoopbackHost("localhost:8080") {
		t.Fatal("invalid loopback host policy")
	}
}
