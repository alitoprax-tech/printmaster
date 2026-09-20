package tenancy

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"printmaster/server/storage"
)

func TestHTTPEnrollmentDoesNotConsumeTokenOnFailedRegistration(t *testing.T) {
	s, err := storage.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	previous := dbStore
	dbStore = s
	defer func() { dbStore = previous }()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &storage.Tenant{ID: "enrollment", Name: "Test"}); err != nil {
		t.Fatal(err)
	}
	_, raw, err := s.CreateJoinToken(ctx, "enrollment", 5, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterAgent(ctx, &storage.Agent{AgentID: "existing", Token: "original"}); err != nil {
		t.Fatal(err)
	}
	request := func(id string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"token": raw, "agent_id": id})
		rw := httptest.NewRecorder()
		handleRegisterWithToken(rw, httptest.NewRequest(http.MethodPost, "/api/v1/agents/register-with-token", bytes.NewReader(body)))
		return rw
	}
	if rw := request("existing"); rw.Code == http.StatusOK {
		t.Fatal("existing identity overwritten")
	}
	if rw := request("new"); rw.Code != http.StatusOK {
		t.Fatalf("failed enrollment burned token: %d", rw.Code)
	}
	if rw := request("replay"); rw.Code == http.StatusOK {
		t.Fatal("token replay accepted")
	}
	if agent, err := s.GetAgent(ctx, "existing"); err != nil || agent.Token != "" {
		t.Fatal("original credential changed")
	}
}

func TestEnrollmentRejectsOversizedAndTrailingDocuments(t *testing.T) {
	for _, body := range []string{`{"token":"x","agent_id":"y"} {}`, `{"token":"` + strings.Repeat("x", 65<<10) + `","agent_id":"y"}`} {
		rw := httptest.NewRecorder()
		handleRegisterWithToken(rw, httptest.NewRequest(http.MethodPost, "/api/v1/agents/register-with-token", strings.NewReader(body)))
		if rw.Code != http.StatusBadRequest {
			t.Fatalf("unsafe JSON accepted: %d", rw.Code)
		}
	}
}
