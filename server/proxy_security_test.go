package main

import (
	"net/http/httptest"
	wscommon "printmaster/common/ws"
	"testing"
)

func TestProxyResponsesRequireOriginalAgentAndConnection(t *testing.T) {
	conn, replacement := &wscommon.Conn{}, &wscommon.Conn{}
	ch := make(chan wscommon.Message, 1)
	proxyRequestsLock.Lock()
	proxyRequests["security-test"] = pendingProxy{agentID: "owner", connection: conn, responses: ch}
	proxyRequestsLock.Unlock()
	t.Cleanup(func() { proxyRequestsLock.Lock(); delete(proxyRequests, "security-test"); proxyRequestsLock.Unlock() })
	msg := wscommon.Message{Data: map[string]interface{}{"request_id": "security-test"}}
	for _, h := range []func(string, *wscommon.Conn, wscommon.Message){handleWSProxyResponse, handleWSProxyStreamChunk, handleWSProxyStreamEnd} {
		h("attacker", conn, msg)
		h("owner", replacement, msg)
		if len(ch) != 0 {
			t.Fatal("foreign or stale connection injected response")
		}
	}
	handleWSProxyResponse("owner", conn, msg)
	if len(ch) != 1 {
		t.Fatal("legitimate response was lost")
	}
}

func TestProxyDoesNotForwardServerCredentialsOrClaimedIdentity(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("Authorization", "Bearer private-session")
	r.Header.Set("Cookie", "pm_session=private-session")
	r.Header.Set("X-Printmaster-Role", "admin")
	r.Header.Set("Accept", "text/html")
	h := trustedProxyHeaders(r)
	if len(h) != 1 || h["Accept"] != "text/html" {
		t.Fatal("forwarded credentials or unauthenticated principal")
	}
}
