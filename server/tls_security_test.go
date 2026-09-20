package main

import (
	"bufio"
	"errors"
	"strings"
	"testing"
)

func TestReadRedirectLineEnforcesHeaderBudget(t *testing.T) {
	t.Parallel()

	remaining := 4
	_, err := readRedirectLine(bufio.NewReader(strings.NewReader("hello\n")), &remaining)
	if !errors.Is(err, bufio.ErrBufferFull) {
		t.Fatalf("expected bounded redirect line to fail with ErrBufferFull, got %v", err)
	}
}

func TestReadRedirectLinePreservesCompleteLine(t *testing.T) {
	t.Parallel()

	remaining := 32
	line, err := readRedirectLine(bufio.NewReader(strings.NewReader("Host: example.com\r\n")), &remaining)
	if err != nil {
		t.Fatalf("readRedirectLine returned error: %v", err)
	}
	if line != "Host: example.com\r\n" {
		t.Fatalf("unexpected line %q", line)
	}
	if remaining != 13 {
		t.Fatalf("remaining budget = %d, want 13", remaining)
	}
}

func TestSanitizeRedirectPathRejectsAmbiguousTargets(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: "/"},
		{name: "absolute URL", input: "https://evil.example/", want: "/"},
		{name: "protocol relative", input: "//evil.example/", want: "//evil.example/"},
		{name: "backslash normalized by browsers", input: `/\\evil.example/`, want: "/"},
		{name: "header injection", input: "/ok\r\nLocation: https://evil.example/", want: "/"},
		{name: "normal path", input: "/dashboard?tab=agents", want: "/dashboard?tab=agents"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeRedirectPath(tc.input); got != tc.want {
				t.Fatalf("sanitizeRedirectPath(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestSanitizeRedirectHostRejectsHeaderInjection(t *testing.T) {
	t.Parallel()

	const fallback = "localhost:9443"
	cases := []string{
		"",
		"evil.example\r\nLocation: https://evil.example/",
		"https://evil.example",
		"user@evil.example",
		"[not-an-ipv6]:443",
		"2001:db8::1",
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			if got := sanitizeRedirectHost(input, 9443); got != fallback {
				t.Fatalf("sanitizeRedirectHost(%q) = %q, want %q", input, got, fallback)
			}
		})
	}

	for _, tc := range []struct {
		input string
		want  string
	}{
		{input: "example.com", want: "example.com:9443"},
		{input: "example.com:443", want: "example.com:443"},
		{input: "[2001:db8::1]:443", want: "[2001:db8::1]:443"},
	} {
		if got := sanitizeRedirectHost(tc.input, 9443); got != tc.want {
			t.Fatalf("sanitizeRedirectHost(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
