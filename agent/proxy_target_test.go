package main

import (
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
		{name: "matching IPv6", rawURL: "https://[fd00::20]:8443/ui", deviceIP: "fd00::20", wantHost: "[fd00::20]:8443"},
		{name: "host mismatch", rawURL: "http://127.0.0.1/", deviceIP: "192.168.10.20", wantError: true},
		{name: "hostname rejected", rawURL: "http://printer.example/", deviceIP: "192.168.10.20", wantError: true},
		{name: "userinfo rejected", rawURL: "http://user:pass@192.168.10.20/", deviceIP: "192.168.10.20", wantError: true},
		{name: "query rejected", rawURL: "http://192.168.10.20/?next=http://127.0.0.1", deviceIP: "192.168.10.20", wantError: true},
		{name: "unsupported scheme", rawURL: "ftp://192.168.10.20/", deviceIP: "192.168.10.20", wantError: true},
		{name: "loopback device", rawURL: "http://127.0.0.1/", deviceIP: "127.0.0.1", wantError: true},
		{name: "link local device", rawURL: "http://169.254.10.20/", deviceIP: "169.254.10.20", wantError: true},
		{name: "invalid port", rawURL: "http://192.168.10.20:70000/", deviceIP: "192.168.10.20", wantError: true},
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

func TestBuildPrinterProxyURLIPv6(t *testing.T) {
	got := buildPrinterProxyURL("http", "fd00::20", "8080")
	if got != "http://[fd00::20]:8080" {
		t.Fatalf("URL = %q", got)
	}
	if net.ParseIP("fd00::20") == nil {
		t.Fatal("test IP should parse")
	}
}
