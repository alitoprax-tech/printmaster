package main

import (
	"bytes"
	"compress/gzip"
	"net/http"
	"testing"
)

func TestBrowserProxyIsDisabledUnlessExplicitlyConfigured(t *testing.T) {
	previous := serverConfig
	t.Cleanup(func() { serverConfig = previous })
	serverConfig = DefaultConfig()
	if browserProxyEnabled() {
		t.Fatal("browser proxy is enabled by default")
	}
	serverConfig.Server.BrowserProxyEnabled = true
	if !browserProxyEnabled() {
		t.Fatal("explicit browser proxy configuration was ignored")
	}
}

func TestPrinterProxyRejectsGzipExpansionBomb(t *testing.T) {
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	chunk := bytes.Repeat([]byte("x"), 64<<10)
	for i := 0; i < (maxProxyDecompressedBodySize/(64<<10))+1; i++ {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := decompressProxyGzip(compressed.Bytes()); err == nil {
		t.Fatal("compressed printer response expanded past the limit")
	}
}

func TestProxyResponseHeadersDiscardCookieAndPolicy(t *testing.T) {
	headers := make(http.Header)
	copySafeProxyResponseHeaders(headers, map[string]interface{}{
		"Content-Type":            "text/html",
		"Set-Cookie":              "pm_session=attacker; Path=/",
		"Content-Security-Policy": "script-src *",
		"Location":                "https://attacker.example/",
		"X-Frame-Options":         "ALLOWALL",
		"X-Test-With-Newline":     "safe\r\nInjected: true",
	})
	if headers.Get("Content-Type") != "text/html" {
		t.Fatal("safe content type was not preserved")
	}
	for _, forbidden := range []string{"Set-Cookie", "Content-Security-Policy", "Location", "X-Frame-Options", "X-Test-With-Newline"} {
		if headers.Get(forbidden) != "" {
			t.Fatalf("unsafe header forwarded: %s=%q", forbidden, headers.Get(forbidden))
		}
	}
}

func TestReadBoundedProxyBody(t *testing.T) {
	if _, err := readBoundedProxyBody(bytes.NewReader([]byte("12345")), 4); err == nil {
		t.Fatal("oversized proxy body was accepted")
	}
	body, err := readBoundedProxyBody(bytes.NewReader([]byte("1234")), 4)
	if err != nil || string(body) != "1234" {
		t.Fatalf("bounded body read failed: %q, %v", body, err)
	}
}
