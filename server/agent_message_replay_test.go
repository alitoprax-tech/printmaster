package main

import (
	"testing"
	"time"

	wscommon "printmaster/common/ws"
)

func TestAgentStateMessageIdentityExpiryAndReplay(t *testing.T) {
	now := time.Now().UTC()
	makeMessage := func(id string) wscommon.Message {
		return wscommon.Message{
			Type: wscommon.MessageTypeDeviceDeleted, Timestamp: now,
			Data: map[string]interface{}{"serial": "DEVICE-1", "message_id": id, "expires_at": now.Add(time.Minute).Format(time.RFC3339Nano)},
		}
	}
	msg := makeMessage("agent-replay-test-00001")
	if err := validateAgentStateMessage("agent-a", msg, now); err != nil {
		t.Fatal(err)
	}
	if err := validateAgentStateMessage("agent-a", msg, now); err == nil {
		t.Fatal("same Agent replay accepted")
	}
	if err := validateAgentStateMessage("agent-b", msg, now); err != nil {
		t.Fatalf("replay state leaked across Agents: %v", err)
	}
	if err := validateAgentStateMessage("agent-c", msg, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired state change accepted")
	}
	missing := makeMessage("agent-replay-test-00002")
	delete(missing.Data, "message_id")
	if err := validateAgentStateMessage("agent-a", missing, now); err == nil {
		t.Fatal("missing message ID accepted")
	}
	future := makeMessage("agent-replay-test-00003")
	future.Timestamp = now.Add(time.Hour)
	if err := validateAgentStateMessage("agent-a", future, now); err == nil {
		t.Fatal("future message accepted")
	}
}

func TestLegacyAgentStateMessageHasBoundedMigration(t *testing.T) {
	now := time.Now().UTC()
	cfg := DefaultConfig()
	legacy := wscommon.Message{Type: wscommon.MessageTypeDeviceDeleted, Timestamp: now, Data: map[string]interface{}{"serial": "OLD"}}
	if legacyAgentStateMessageAllowed(cfg, legacy, now) {
		t.Fatal("legacy message accepted by default")
	}
	cfg.Security.AgentProtocolLegacyUntil = now.Add(24 * time.Hour).Format(time.RFC3339)
	if err := validateAgentProtocolConfig(cfg, now); err != nil {
		t.Fatal(err)
	}
	if !legacyAgentStateMessageAllowed(cfg, legacy, now) {
		t.Fatal("explicit migration failed")
	}
	if legacyAgentStateMessageAllowed(cfg, legacy, now.Add(25*time.Hour)) {
		t.Fatal("expired migration continued")
	}
	legacy.Data["message_id"] = "attacker-replay-test-0001"
	if legacyAgentStateMessageAllowed(cfg, legacy, now) {
		t.Fatal("malformed modern message fell back to legacy")
	}
	cfg.Security.AgentProtocolLegacyUntil = now.Add(30 * 24 * time.Hour).Format(time.RFC3339)
	if validateAgentProtocolConfig(cfg, now) == nil {
		t.Fatal("unbounded compatibility deadline accepted")
	}
}
