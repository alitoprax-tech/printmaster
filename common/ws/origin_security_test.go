package ws

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWebSocketRejectsCrossOriginBrowser(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, e := UpgradeHTTP(w, r)
		if e == nil {
			c.Close()
		}
	}))
	defer s.Close()
	for _, origin := range []string{"https://attacker.example", s.URL, ""} {
		h := http.Header{}
		if origin != "" {
			h.Set("Origin", origin)
		}
		c, resp, err := Dial("ws"+strings.TrimPrefix(s.URL, "http"), h, nil, time.Second)
		if c != nil {
			c.Close()
		}
		if resp != nil && resp.Body != nil {
			resp.Body.Close()
		}
		if origin == "https://attacker.example" {
			if err == nil || resp == nil || resp.StatusCode != 403 {
				t.Fatal("cross-origin accepted")
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
}
