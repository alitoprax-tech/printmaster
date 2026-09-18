package main

import (
	"strings"
	"testing"
)

// TestRewriteExistingBaseTag_KyoceraDoubleQuoted covers the Command Center RX
// regression: the device ships <base href="/"> so relative asset requests
// (knockout, stub.js, base.js, index.viewmodel.js) must be rewritten to stay
// under the proxy prefix instead of escaping to the server's root routes.
func TestRewriteExistingBaseTag_KyoceraDoubleQuoted(t *testing.T) {
	content := `<html><head><base href="/"><script src="js/stub.js"></script></head><body></body></html>`
	out, changed := rewriteExistingBaseTag(content, "/proxy/RH28Y00024", "192.168.0.152")
	if !changed {
		t.Fatalf("expected base tag to be rewritten")
	}
	want := `<base href="/proxy/RH28Y00024/">`
	if !strings.Contains(out, want) {
		t.Fatalf("expected rewritten base href %q in output, got: %s", want, out)
	}
}

func TestRewriteExistingBaseTag_SingleQuoted(t *testing.T) {
	content := `<html><head><base href='/some/dir/'></head></html>`
	out, changed := rewriteExistingBaseTag(content, "/proxy/SERIAL1", "device.local")
	if !changed {
		t.Fatalf("expected base tag to be rewritten")
	}
	want := `<base href='/proxy/SERIAL1/some/dir/'>`
	if !strings.Contains(out, want) {
		t.Fatalf("expected rewritten base href %q in output, got: %s", want, out)
	}
}

func TestRewriteExistingBaseTag_AbsoluteSameHostURL(t *testing.T) {
	content := `<head><base href="http://192.168.0.152/app/"></head>`
	out, changed := rewriteExistingBaseTag(content, "/proxy/SERIAL2", "192.168.0.152")
	if !changed {
		t.Fatalf("expected base tag to be rewritten")
	}
	want := `<base href="/proxy/SERIAL2/app/">`
	if !strings.Contains(out, want) {
		t.Fatalf("expected rewritten base href %q in output, got: %s", want, out)
	}
}

func TestRewriteExistingBaseTag_DifferentHostLeftAlone(t *testing.T) {
	content := `<head><base href="http://cdn.example.com/assets/"></head>`
	out, changed := rewriteExistingBaseTag(content, "/proxy/SERIAL3", "192.168.0.152")
	if changed {
		t.Fatalf("expected different-host base href to be left untouched")
	}
	if out != content {
		t.Fatalf("expected content unchanged, got: %s", out)
	}
}

func TestRewriteExistingBaseTag_AlreadyRewrittenLeftAlone(t *testing.T) {
	content := `<head><base href="/proxy/SERIAL4/"></head>`
	out, changed := rewriteExistingBaseTag(content, "/proxy/SERIAL4", "192.168.0.152")
	if changed {
		t.Fatalf("expected already-rewritten base href to be left untouched")
	}
	if out != content {
		t.Fatalf("expected content unchanged, got: %s", out)
	}
}

func TestRewriteExistingBaseTag_RelativeHrefLeftAlone(t *testing.T) {
	content := `<head><base href="app/"></head>`
	out, changed := rewriteExistingBaseTag(content, "/proxy/SERIAL5", "192.168.0.152")
	if changed {
		t.Fatalf("expected relative base href to be left untouched")
	}
	if out != content {
		t.Fatalf("expected content unchanged, got: %s", out)
	}
}

func TestRewriteExistingBaseTag_NoBaseTag(t *testing.T) {
	content := `<head><title>No base here</title></head>`
	out, changed := rewriteExistingBaseTag(content, "/proxy/SERIAL6", "192.168.0.152")
	if changed {
		t.Fatalf("expected no-op when there is no <base> tag")
	}
	if out != content {
		t.Fatalf("expected content unchanged, got: %s", out)
	}
}

func TestRewriteExistingBaseTag_NoHrefAttribute(t *testing.T) {
	content := `<head><base target="_blank"></head>`
	out, changed := rewriteExistingBaseTag(content, "/proxy/SERIAL7", "192.168.0.152")
	if changed {
		t.Fatalf("expected no-op when <base> has no href attribute")
	}
	if out != content {
		t.Fatalf("expected content unchanged, got: %s", out)
	}
}
