package main

import (
	"errors"
	"fmt"
	"sync"
	"time"

	wscommon "printmaster/common/ws"
)

func validateAgentProtocolConfig(cfg *Config, now time.Time) error {
	if cfg == nil || cfg.Security.AgentProtocolLegacyUntil == "" {
		return nil
	}
	until, err := time.Parse(time.RFC3339, cfg.Security.AgentProtocolLegacyUntil)
	if err != nil || !until.After(now) || until.After(now.Add(14*24*time.Hour)) {
		return fmt.Errorf("security.agent_protocol_legacy_until must be an RFC3339 deadline within 14 days")
	}
	return nil
}

func legacyAgentStateMessageAllowed(cfg *Config, msg wscommon.Message, now time.Time) bool {
	if cfg == nil || cfg.Security.AgentProtocolLegacyUntil == "" || msg.Data == nil {
		return false
	}
	if _, hasID := msg.Data["message_id"]; hasID {
		return false
	}
	if _, hasExpiry := msg.Data["expires_at"]; hasExpiry {
		return false
	}
	until, err := time.Parse(time.RFC3339, cfg.Security.AgentProtocolLegacyUntil)
	return err == nil && now.Before(until) && !msg.Timestamp.IsZero() && !now.Before(msg.Timestamp.Add(-30*time.Second)) && now.Sub(msg.Timestamp) <= time.Minute
}

var agentMessageReplay = struct {
	sync.Mutex
	seen map[string]map[string]time.Time
}{seen: make(map[string]map[string]time.Time)}

// Device deletion is a state-changing Agent notification. Require a bounded,
// fresh ID and reject duplicates on reconnect as well as within one socket.
func validateAgentStateMessage(agentID string, msg wscommon.Message, now time.Time) error {
	if agentID == "" || msg.Data == nil {
		return errors.New("missing Agent identity or data")
	}
	id, ok := msg.Data["message_id"].(string)
	if !ok || len(id) < 16 || len(id) > 128 {
		return errors.New("invalid Agent message ID")
	}
	expiryText, ok := msg.Data["expires_at"].(string)
	if !ok || msg.Timestamp.IsZero() {
		return errors.New("missing Agent message timestamps")
	}
	expiry, err := time.Parse(time.RFC3339Nano, expiryText)
	if err != nil || now.Before(msg.Timestamp.Add(-30*time.Second)) || now.Sub(msg.Timestamp) > time.Minute || !expiry.After(now) || expiry.After(msg.Timestamp.Add(2*time.Minute)) {
		return errors.New("expired Agent message")
	}
	agentMessageReplay.Lock()
	defer agentMessageReplay.Unlock()
	perAgent := agentMessageReplay.seen[agentID]
	if perAgent == nil {
		perAgent = make(map[string]time.Time)
	}
	for key, until := range perAgent {
		if !now.Before(until) {
			delete(perAgent, key)
		}
	}
	if _, exists := perAgent[id]; exists {
		return errors.New("replayed Agent message")
	}
	if len(perAgent) >= 1024 {
		return errors.New("Agent replay cache full")
	}
	perAgent[id] = expiry
	agentMessageReplay.seen[agentID] = perAgent
	return nil
}
