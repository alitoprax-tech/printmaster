package main

import (
	"net/http"
	"sync"
	"time"

	wscommon "printmaster/common/ws"
	"printmaster/server/storage"
)

const (
	maxAgentHTTPRequestsPerMinute = 120
	maxAgentHTTPBytesPerMinute    = 16 << 20
	maxAgentWritesPerMinute       = 2000
	maxAgentWSMessagesPerMinute   = 1200
	maxAgentWSBytesPerMinute      = 32 << 20
	maxAgentReconnectsPerMinute   = 20
	maxOutstandingAgentProxies    = 8
)

type agentTrafficWindow struct {
	start        time.Time
	httpRequests int
	httpBytes    int64
	writes       int
	wsMessages   int
	wsBytes      int64
	connections  int
}

func reserveAgentConnection(agentID string, now time.Time) bool {
	if agentID == "" {
		return false
	}
	agentTraffic.Lock()
	defer agentTraffic.Unlock()
	w := agentTraffic.windows[agentID]
	if w.start.IsZero() || now.Sub(w.start) >= time.Minute || now.Before(w.start) {
		w = agentTrafficWindow{start: now}
	}
	if w.connections >= maxAgentReconnectsPerMinute {
		return false
	}
	w.connections++
	agentTraffic.windows[agentID] = w
	return true
}

func admitAgentHTTPRequest(w http.ResponseWriter, r *http.Request, agent *storage.Agent) bool {
	if agent == nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return false
	}
	bytes := r.ContentLength
	if bytes < 0 {
		bytes = maxRequestBodySize
	}
	if bytes == 0 {
		bytes = 1
	}
	if !reserveAgentTraffic(agent.AgentID, time.Now(), bytes, 0, 0) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Agent request quota exceeded", http.StatusTooManyRequests)
		return false
	}
	return true
}

func reserveAgentWrites(w http.ResponseWriter, agentID string, count int) bool {
	if !reserveAgentTraffic(agentID, time.Now(), 0, count, 0) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "Agent write quota exceeded", http.StatusTooManyRequests)
		return false
	}
	return true
}

var agentTraffic = struct {
	sync.Mutex
	windows map[string]agentTrafficWindow
}{windows: make(map[string]agentTrafficWindow)}

func reserveAgentTraffic(agentID string, now time.Time, httpBytes int64, writes int, wsBytes int64) bool {
	if agentID == "" || httpBytes < 0 || writes < 0 || wsBytes < 0 || httpBytes > maxAgentHTTPBytesPerMinute || writes > maxAgentWritesPerMinute || wsBytes > maxAgentWSBytesPerMinute {
		return false
	}
	agentTraffic.Lock()
	defer agentTraffic.Unlock()
	w := agentTraffic.windows[agentID]
	if w.start.IsZero() || now.Sub(w.start) >= time.Minute || now.Before(w.start) {
		w = agentTrafficWindow{start: now}
	}
	if httpBytes > 0 {
		w.httpRequests++
		w.httpBytes += httpBytes
	}
	w.writes += writes
	if wsBytes > 0 {
		w.wsMessages++
		w.wsBytes += wsBytes
	}
	if w.httpRequests > maxAgentHTTPRequestsPerMinute || w.httpBytes > maxAgentHTTPBytesPerMinute || w.writes > maxAgentWritesPerMinute || w.wsMessages > maxAgentWSMessagesPerMinute || w.wsBytes > maxAgentWSBytesPerMinute {
		return false
	}
	agentTraffic.windows[agentID] = w
	return true
}

func agentWSMessageSizeAllowed(messageType string, size int) bool {
	if size <= 0 {
		return false
	}
	limit := 0
	switch messageType {
	case wscommon.MessageTypeHeartbeat, wscommon.MessageTypeDeviceDeleted:
		limit = 16 << 10
	case wscommon.MessageTypeJobProgress, wscommon.MessageTypeUpdateProgress, wscommon.MessageTypeProxyStreamEnd:
		limit = 32 << 10
	case wscommon.MessageTypeProxyStreamChunk:
		limit = 512 << 10
	case wscommon.MessageTypeProxyResponse:
		// Some older Agents return non-streamed printer responses. Retain that
		// path until a streaming-only rollout; the per-minute byte quota still
		// bounds repeated full-size frames from a compromised Agent.
		limit = 8 << 20
	default:
		return false
	}
	return size <= limit
}
