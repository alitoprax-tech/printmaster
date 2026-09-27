package main

import (
	"bytes"
	"io"
	"net"
	"testing"
)

func TestValidatePrinterProxyTarget(t *testing.T) {
	tests := []struct {
		name      string
		rawURL    string
		deviceIP  string
		wantError bool
		wantHost  string
	}{
		{name: "matching IPv4", rawURL: "http://192.168.10.20/", deviceIP: "192.168.10.20", wantHost: "192.168.10.20"},
		{name: "matching IPv6", rawURL: "https://[fd00::20]/ui", deviceIP: "fd00::20", wantHost: "[fd00::20]"},
		{name: "host mismatch", rawURL: "http://127.0.0.1/", deviceIP: "192.168.10.20", wantError: true},
		{name: "hostname rejected", rawURL: "http://printer.example/", deviceIP: "192.168.10.20", wantError: true},
		{name: "userinfo rejected", rawURL: "http://user:pass@192.168.10.20/", deviceIP: "192.168.10.20", wantError: true},
		{name: "query rejected", rawURL: "http://192.168.10.20/?next=http://127.0.0.1", deviceIP: "192.168.10.20", wantError: true},
		{name: "unsupported scheme", rawURL: "ftp://192.168.10.20/", deviceIP: "192.168.10.20", wantError: true},
		{name: "loopback device", rawURL: "http://127.0.0.1/", deviceIP: "127.0.0.1", wantError: true},
		{name: "link local device", rawURL: "http://169.254.10.20/", deviceIP: "169.254.10.20", wantError: true},
		{name: "invalid port", rawURL: "http://192.168.10.20:70000/", deviceIP: "192.168.10.20", wantError: true},
		{name: "ssh port", rawURL: "http://192.168.10.20:22/", deviceIP: "192.168.10.20", wantError: true},
		{name: "smb port", rawURL: "http://192.168.10.20:445/", deviceIP: "192.168.10.20", wantError: true},
		{name: "rdp port", rawURL: "http://192.168.10.20:3389/", deviceIP: "192.168.10.20", wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := validatePrinterProxyTarget(tt.rawURL, tt.deviceIP)
			if tt.wantError {
				if err == nil {
					t.Fatalf("expected validation error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected validation error: %v", err)
			}
			if got.Host != tt.wantHost {
				t.Fatalf("canonical host = %q, want %q", got.Host, tt.wantHost)
			}
		})
	}
}

func TestProxyStreamingBodyFailsOnOverflow(t *testing.T) {
	body := &boundedProxyBody{ReadCloser: io.NopCloser(bytes.NewReader([]byte("1234"))), remaining: 3}
	if _, err := io.ReadAll(body); err == nil {
		t.Fatal("oversized streaming response was silently truncated")
	}
}

func TestPrinterProxyExtraPortsAndFinalDial(t *testing.T) {
	t.Setenv("PRINTMASTER_PRINTER_PROXY_PORTS", "8443,invalid,0,65536")
	target, err := validatePrinterProxyTarget("https://192.168.10.20:8443/ui", "192.168.10.20")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		addr    string
		allowed bool
	}{
		{"192.168.10.20:8443", true},
		{"192.168.10.21:8443", false},
		{"127.0.0.1:8443", false},
		{"192.168.10.20:22", false},
		{"192.168.10.20:443", false},
		{"printer.local:8443", false},
	} {
		if got := validatePrinterProxyDial(tc.addr, target) == nil; got != tc.allowed {
			t.Fatalf("dial %q allowed=%v, want %v", tc.addr, got, tc.allowed)
		}
	}
	t.Setenv("PRINTMASTER_PRINTER_PROXY_PORTS", "")
	if _, err := validatePrinterProxyTarget("https://192.168.10.20:8443/ui", "192.168.10.20"); err == nil {
		t.Fatal("custom port accepted without local configuration")
	}
}

func TestPrinterProxyRedirectCannotPivot(t *testing.T) {
	base, err := validatePrinterProxyTarget("http://192.168.10.20/", "192.168.10.20")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		location string
		allowed  bool
	}{
		{"/ui/login", true},
		{"http://192.168.10.20/ui", true},
		{"http://192.168.10.1/admin", false},
		{"http://127.0.0.1/admin", false},
		{"http://169.254.169.254/latest/meta-data/", false},
		{"http://192.168.10.20:22/", false},
		{"http://192.168.10.20:445/", false},
		{"http://192.168.10.20:3389/", false},
		{"https://192.168.10.20/", false},
		{"http://printer.local/", false},
	} {
		if _, err := validatePrinterProxyRedirect(base, tc.location, "192.168.10.20"); (err == nil) != tc.allowed {
			t.Fatalf("redirect %q allowed=%v, want %v", tc.location, err == nil, tc.allowed)
		}
	}
}

func TestBuildPrinterProxyURLIPv6(t *testing.T) {
	got := buildPrinterProxyURL("http", "fd00::20", "8080")
	if got != "http://[fd00::20]:8080" {
		t.Fatalf("URL = %q", got)
	}
	if net.ParseIP("fd00::20") == nil {
		t.Fatal("test IP should parse")
	}
}
