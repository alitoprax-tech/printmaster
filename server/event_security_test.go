package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"printmaster/server/storage"
	"testing"
)

func TestEventsRespectTenantOwnership(t *testing.T) {
	s, err := storage.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	for _, id := range []string{"a", "b"} {
		if err := s.CreateTenant(ctx, &storage.Tenant{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
		if err := s.RegisterAgent(ctx, &storage.Agent{AgentID: "agent-" + id, TenantID: id, Token: "token-" + id}); err != nil {
			t.Fatal(err)
		}
	}
	viewer := newPrincipal(&storage.User{Role: storage.RoleViewer, TenantID: "a"})
	for _, tc := range []struct {
		data    map[string]interface{}
		allowed bool
	}{
		{map[string]interface{}{"agent_id": "agent-a"}, true},
		{map[string]interface{}{"agent_id": "agent-b", "tenant_id": "a"}, false},
		{map[string]interface{}{"agent_id": "missing", "tenant_id": "a"}, false},
		{map[string]interface{}{"tenant_id": "a"}, true},
		{map[string]interface{}{"tenant_id": "b"}, false},
		{map[string]interface{}{"message": "internal log"}, false},
	} {
		if eventVisibleToPrincipal(ctx, s, viewer, tc.data) != tc.allowed {
			t.Fatalf("invalid visibility for %v", tc.data)
		}
	}
	if !eventVisibleToPrincipal(ctx, s, newPrincipal(&storage.User{Role: storage.RoleAdmin}), nil) {
		t.Fatal("admin lost fleet visibility")
	}
	if eventVisibleToPrincipal(ctx, s, nil, nil) {
		t.Fatal("anonymous visibility")
	}
}

func TestReportEndpointsRejectNonAdministrators(t *testing.T) {
	for _, role := range []storage.Role{storage.RoleViewer, storage.RoleOperator} {
		for _, handler := range []func(http.ResponseWriter, *http.Request){handleReports, handleReport, handleReportRunsCollection, handleReportSchedulesCollection, handleSchedule, handleReportRunResult, handleReportSummary} {
			r := httptest.NewRequest("GET", "/api/v1/reports", nil)
			r = r.WithContext(contextWithPrincipal(r.Context(), &storage.User{Role: role, TenantID: "a"}))
			w := httptest.NewRecorder()
			handler(w, r)
			if w.Code != 403 {
				t.Fatalf("role %s got %d", role, w.Code)
			}
		}
	}
}
