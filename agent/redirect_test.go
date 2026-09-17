package main

import "testing"

func TestIsSafeReturnPath(t *testing.T) {
	safe := []string{"/", "/dashboard", "/devices?filter=all", "/a/b/c"}
	for _, p := range safe {
		if !isSafeReturnPath(p) {
			t.Errorf("expected %q to be safe", p)
		}
	}

	unsafe := []string{
		"",
		"http://evil.com",
		"https://evil.com/x",
		"//evil.com",
		"/\\evil.com",
		"/\tevil.com",
		"/\r/evil.com",
		"/\n/evil.com",
		"javascript://evil.com",
		"/ok/but/has\x00null",
	}
	for _, p := range unsafe {
		if isSafeReturnPath(p) {
			t.Errorf("expected %q to be rejected as unsafe", p)
		}
	}
}
