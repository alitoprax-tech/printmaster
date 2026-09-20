package main

import (
	"io"
	"strings"
	"testing"
)

func TestReadBoundedProxyResponseRejectsOversizedBody(t *testing.T) {
	t.Parallel()
	body := io.NopCloser(strings.NewReader(strings.Repeat("x", maxAgentProxyResponseBodySize+1)))
	if _, err := readBoundedProxyResponse(body); err == nil {
		t.Fatal("expected oversized proxy response to be rejected")
	}
}

func TestBoundedProxyBodyStopsAtConfiguredLimit(t *testing.T) {
	t.Parallel()
	body := &boundedProxyBody{
		ReadCloser: io.NopCloser(strings.NewReader(strings.Repeat("x", maxAgentProxyResponseBodySize+1024))),
		remaining:  maxAgentProxyResponseBodySize,
	}
	data, err := io.ReadAll(body)
	if err != nil {
		t.Fatalf("read bounded proxy body: %v", err)
	}
	if len(data) != maxAgentProxyResponseBodySize {
		t.Fatalf("bounded body length = %d, want %d", len(data), maxAgentProxyResponseBodySize)
	}
}
