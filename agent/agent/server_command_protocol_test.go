package agent

import (
	"testing"
	"time"

	wscommon "printmaster/common/ws"
)

func TestServerCommandLifetimeAndReplay(t *testing.T) {
	ws := NewWSClient("wss://agents.example.com/api/v1/agents/ws", "", false)
	now := time.Now().UTC()
	makeCommand := func(id string) wscommon.Message {
		return wscommon.Message{Type: wscommon.MessageTypeCommand, Data: map[string]interface{}{
			"command": "check_update", "message_id": id,
			"issued_at": now.Format(time.RFC3339Nano), "expires_at": now.Add(time.Minute).Format(time.RFC3339Nano),
		}}
	}
	msg := makeCommand("unique-command-id-00001")
	if command, err := ws.validateServerCommand(msg, now); err != nil || command != "check_update" {
		t.Fatalf("legitimate command rejected: %s, %v", command, err)
	}
	if _, err := ws.validateServerCommand(msg, now); err == nil {
		t.Fatal("duplicate command replay accepted")
	}
	if _, err := ws.validateServerCommand(msg, now.Add(2*time.Minute)); err == nil {
		t.Fatal("expired command accepted")
	}
	missing := makeCommand("unique-command-id-00002")
	delete(missing.Data, "message_id")
	if _, err := ws.validateServerCommand(missing, now); err == nil {
		t.Fatal("missing ID accepted")
	}
	wrong := makeCommand("unique-command-id-00003")
	wrong.Data["command"] = "powershell"
	if _, err := ws.validateServerCommand(wrong, now); err == nil {
		t.Fatal("arbitrary command accepted")
	}
	future := makeCommand("unique-command-id-00004")
	future.Data["issued_at"] = now.Add(5 * time.Minute).Format(time.RFC3339Nano)
	if _, err := ws.validateServerCommand(future, now); err == nil {
		t.Fatal("future command accepted")
	}
}
