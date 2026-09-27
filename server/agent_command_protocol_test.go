package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"printmaster/server/storage"
)

func TestAgentCommandRejectsUnknownAndReservedOverrides(t *testing.T) {
	for _, body := range []string{
		`{"command":"powershell"}`,
		`{"command":"check_update","data":{"command":"force_update"}}`,
		`{"command":"check_update","data":{"message_id":"attacker-id"}}`,
		`{"command":"check_update","data":{"reason":"` + strings.Repeat("x", 4097) + `"}}`,
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/agents/command/agent1", strings.NewReader(body))
		r = r.WithContext(contextWithPrincipal(r.Context(), &storage.User{ID: 1, Role: storage.RoleAdmin}))
		w := httptest.NewRecorder()
		handleAgentCommand(w, r)
		if w.Code != http.StatusBadRequest {
			t.Fatalf("unexpected command status %d", w.Code)
		}
	}
}
