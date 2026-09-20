package main

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestAgentReadRedirectLineEnforcesHeaderBudget(t *testing.T) {
	t.Parallel()

	remaining := 4
	_, err := readRedirectLine(bufio.NewReader(strings.NewReader("hello\n")), &remaining)
	if !errors.Is(err, bufio.ErrBufferFull) {
		t.Fatalf("expected bounded redirect line to fail with ErrBufferFull, got %v", err)
	}
}

func TestAgentSanitizeRedirectPath(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		input string
		want  string
	}{
		{input: "", want: "/"},
		{input: "https://evil.example/", want: "/"},
		{input: "/ok\r\nLocation: https://evil.example/", want: "/"},
		{input: `/\\evil.example/`, want: "/"},
		{input: "/dashboard?tab=agents", want: "/dashboard?tab=agents"},
	} {
		t.Run(tc.input, func(t *testing.T) {
			if got := sanitizeRedirectPath(tc.input); got != tc.want {
				t.Fatalf("sanitizeRedirectPath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestAgentSanitizeRedirectHost(t *testing.T) {
	t.Parallel()

	const fallback = "localhost:8443"
	for _, input := range []string{
		"",
		"evil.example\r\nLocation: https://evil.example/",
		"https://evil.example",
		"user@evil.example",
		"[not-an-ipv6]:443",
		"2001:db8::1",
	} {
		t.Run(input, func(t *testing.T) {
			if got := sanitizeRedirectHost(input, "8443"); got != fallback {
				t.Fatalf("sanitizeRedirectHost(%q) = %q, want %q", input, got, fallback)
			}
		})
	}

	for _, tc := range []struct {
		input string
		want  string
	}{
		{input: "example.com", want: "example.com:8443"},
		{input: "example.com:443", want: "example.com:443"},
		{input: "[2001:db8::1]:443", want: "[2001:db8::1]:443"},
	} {
		if got := sanitizeRedirectHost(tc.input, "8443"); got != tc.want {
			t.Fatalf("sanitizeRedirectHost(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestAgentRedirectListenerNormalizesPort(t *testing.T) {
	t.Parallel()

	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = inner.Close() })

	listener := newHTTPRedirectListener(inner, "8443\r\nLocation: https://evil.example")
	redirect, ok := listener.(*httpRedirectListener)
	if !ok {
		t.Fatalf("listener has type %T, want *httpRedirectListener", listener)
	}
	if redirect.httpsPort != "443" {
		t.Fatalf("normalized port = %q, want 443", redirect.httpsPort)
	}
}
