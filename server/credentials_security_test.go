package main

import (
	"context"
	"errors"
	"net/http/httptest"
	"printmaster/server/storage"
	"strings"
	"testing"
)

type credentialsOwnershipFailureStore struct{ storage.Store }

func (s credentialsOwnershipFailureStore) GetAgent(context.Context, string) (*storage.Agent, error) {
	return nil, errors.New("simulated ownership lookup failure")
}

func TestDeviceCredentialsEnforceRoleAndTenantBeforeWriting(t *testing.T) {
	s, err := storage.NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	previous := serverStore
	serverStore = s
	defer func() { serverStore = previous }()
	ctx := context.Background()
	for _, id := range []string{"a", "b"} {
		if err := s.CreateTenant(ctx, &storage.Tenant{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
		if err := s.RegisterAgent(ctx, &storage.Agent{AgentID: "credential-agent-" + id, Token: "test-" + id, TenantID: id}); err != nil {
			t.Fatal(err)
		}
		if err := s.UpsertDevice(ctx, &storage.Device{Serial: "credential-printer-" + id, AgentID: "credential-agent-" + id}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name          string
		role          storage.Role
		tenant        string
		method        string
		failOwnership bool
		want          int
	}{
		{"viewer-own-write", storage.RoleViewer, "a", "POST", false, 403},
		{"viewer-other-write", storage.RoleViewer, "b", "POST", false, 403},
		{"operator-own-write", storage.RoleOperator, "a", "POST", false, 200},
		{"operator-other-write", storage.RoleOperator, "b", "POST", false, 403},
		{"admin-write", storage.RoleAdmin, "b", "POST", false, 200},
		{"viewer-own-read", storage.RoleViewer, "a", "GET", false, 200},
		{"viewer-other-read", storage.RoleViewer, "b", "GET", false, 403},
		{"lookup-error-read", storage.RoleAdmin, "a", "GET", true, 403},
		{"lookup-error-write", storage.RoleAdmin, "a", "POST", true, 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverStore = s
			if err := s.UpsertDeviceCredentials(ctx, &storage.DeviceCredentials{Serial: "credential-printer-a", Username: "original", AuthType: "basic", TenantID: "a"}); err != nil {
				t.Fatal(err)
			}
			if tc.failOwnership {
				serverStore = credentialsOwnershipFailureStore{Store: s}
			}
			r := httptest.NewRequest(tc.method, "/device/webui-credentials?serial=credential-printer-a", strings.NewReader(`{"serial":"credential-printer-a","username":"changed","auth_type":"basic","auto_login":true}`))
			r = r.WithContext(contextWithPrincipal(r.Context(), &storage.User{Username: tc.name, Role: tc.role, TenantID: tc.tenant}))
			w := httptest.NewRecorder()
			handleDeviceCredentials(w, r)
			if w.Code != tc.want {
				t.Fatalf("got %d want %d", w.Code, tc.want)
			}
			stored, err := s.GetDeviceCredentials(ctx, "credential-printer-a")
			if err != nil {
				t.Fatal(err)
			}
			wantUser := "original"
			if tc.method == "POST" && tc.want == 200 {
				wantUser = "changed"
			}
			if stored.Username != wantUser {
				t.Fatalf("persisted username %q want %q", stored.Username, wantUser)
			}
		})
	}
}
