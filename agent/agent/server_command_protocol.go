package agent

import (
	"errors"
	"time"

	wscommon "printmaster/common/ws"
)

// A command is a small, short-lived, single-use action. Replays are rejected
// across reconnects within this process. The bounded expiry also limits the
// replay window after a process restart; persistent replay state is a future
// protocol-version migration, not an excuse to accept missing metadata.
func (ws *WSClient) validateServerCommand(msg wscommon.Message, now time.Time) (string, error) {
	if ws == nil || msg.Type != wscommon.MessageTypeCommand || msg.Data == nil {
		return "", errors.New("invalid command envelope")
	}
	command, ok := msg.Data["command"].(string)
	if !ok {
		return "", errors.New("missing command")
	}
	switch command {
	case "check_update", "cancel_update", "force_update", "restart":
	default:
		return "", errors.New("unsupported command")
	}
	id, ok := msg.Data["message_id"].(string)
	if !ok || len(id) < 16 || len(id) > 128 {
		return "", errors.New("invalid command ID")
	}
	issuedText, ok := msg.Data["issued_at"].(string)
	if !ok {
		return "", errors.New("missing command issued_at")
	}
	expiresText, ok := msg.Data["expires_at"].(string)
	if !ok {
		return "", errors.New("missing command expires_at")
	}
	issued, err := time.Parse(time.RFC3339Nano, issuedText)
	if err != nil {
		return "", errors.New("invalid command issued_at")
	}
	expires, err := time.Parse(time.RFC3339Nano, expiresText)
	if err != nil || !expires.After(issued) || expires.After(issued.Add(2*time.Minute)) || now.Before(issued.Add(-30*time.Second)) || !now.Before(expires) {
		return "", errors.New("expired or invalid command lifetime")
	}
	ws.commandReplayMu.Lock()
	defer ws.commandReplayMu.Unlock()
	if ws.commandReplay == nil {
		ws.commandReplay = make(map[string]time.Time)
	}
	for key, expiry := range ws.commandReplay {
		if !now.Before(expiry) {
			delete(ws.commandReplay, key)
		}
	}
	if _, seen := ws.commandReplay[id]; seen {
		return "", errors.New("replayed command ID")
	}
	if len(ws.commandReplay) >= 1024 {
		return "", errors.New("command replay cache full")
	}
	ws.commandReplay[id] = expires
	return command, nil
}
