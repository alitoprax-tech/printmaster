package main

import (
	"testing"
	"time"

	wscommon "printmaster/common/ws"
)

func TestAgentTrafficQuotasAndWindowReset(t *testing.T) {
	now := time.Now()
	id := "quota-test-agent"
	for i := 0; i < maxAgentHTTPRequestsPerMinute; i++ {
		if !reserveAgentTraffic(id, now, 1, 0, 0) {
			t.Fatalf("legitimate request %d rejected", i)
		}
	}
	if reserveAgentTraffic(id, now, 1, 0, 0) {
		t.Fatal("HTTP flood accepted")
	}
	if !reserveAgentTraffic(id, now.Add(61*time.Second), 1, 0, 0) {
		t.Fatal("quota did not reset")
	}
	if reserveAgentTraffic(id, now.Add(61*time.Second), maxAgentHTTPBytesPerMinute+1, 0, 0) {
		t.Fatal("byte flood accepted")
	}
	if reserveAgentTraffic(id, now.Add(61*time.Second), 0, maxAgentWritesPerMinute+1, 0) {
		t.Fatal("DB write flood accepted")
	}
	if reserveAgentTraffic(id, now.Add(61*time.Second), 0, 0, maxAgentWSBytesPerMinute+1) {
		t.Fatal("WS byte flood accepted")
	}
	if reserveAgentTraffic("", now, 1, 0, 0) {
		t.Fatal("unidentified Agent got quota")
	}
}

func TestAgentWebSocketMessageSizeByType(t *testing.T) {
	for _, tc := range []struct {
		typ                string
		accepted, rejected int
	}{
		{wscommon.MessageTypeHeartbeat, 16 << 10, (16 << 10) + 1},
		{wscommon.MessageTypeJobProgress, 32 << 10, (32 << 10) + 1},
		{wscommon.MessageTypeProxyStreamChunk, 512 << 10, (512 << 10) + 1},
		{wscommon.MessageTypeProxyResponse, 8 << 20, (8 << 20) + 1},
	} {
		if !agentWSMessageSizeAllowed(tc.typ, tc.accepted) || agentWSMessageSizeAllowed(tc.typ, tc.rejected) {
			t.Fatalf("wrong size limit for %s", tc.typ)
		}
	}
	if agentWSMessageSizeAllowed("remote_shell", 10) || agentWSMessageSizeAllowed(wscommon.MessageTypeHeartbeat, 0) {
		t.Fatal("invalid WS message admitted")
	}
}

func TestAgentProxyOutstandingQuota(t *testing.T) {
	id := "quota-proxy-agent"
	ids := make([]string, 0, maxOutstandingAgentProxies)
	defer func() {
		proxyRequestsLock.Lock()
		for _, key := range ids {
			delete(proxyRequests, key)
		}
		proxyRequestsLock.Unlock()
	}()
	for i := 0; i < maxOutstandingAgentProxies; i++ {
		key := registerProxyRequest(id, make(chan wscommon.Message, 1))
		if key == "" {
			t.Fatalf("proxy request %d rejected", i)
		}
		ids = append(ids, key)
	}
	if key := registerProxyRequest(id, make(chan wscommon.Message, 1)); key != "" {
		t.Fatal("unbounded proxy session accepted")
	}
	if key := registerProxyRequest("different-proxy-agent", make(chan wscommon.Message, 1)); key == "" {
		t.Fatal("quota leaked across Agents")
	} else {
		proxyRequestsLock.Lock()
		delete(proxyRequests, key)
		proxyRequestsLock.Unlock()
	}
}
