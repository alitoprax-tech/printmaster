package requestauth

import (
	"net"
	"net/http"
	"net/url"
	"strings"
)

// BrowserRequestAllowed rejects cross-origin browser requests before authentication.
// Native clients without browser metadata can still use bearer authentication.
func BrowserRequestAllowed(r *http.Request) bool {
	if site := r.Header.Get("Sec-Fetch-Site"); site == "cross-site" || site == "same-site" {
		return false
	}
	for _, header := range []string{"Origin", "Referer"} {
		if value := r.Header.Get(header); value != "" {
			u, err := url.Parse(value)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || !strings.EqualFold(u.Host, r.Host) {
				return false
			}
		}
	}
	return true
}

// LoopbackHost prevents DNS rebinding from turning a remote hostname into local admin.
func LoopbackHost(host string) bool {
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}
