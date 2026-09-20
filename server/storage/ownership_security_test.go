package storage

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestAgentAndDeviceOwnershipCannotBeReassigned(t *testing.T) {
	s, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	for _, id := range []string{"tenant-a", "tenant-b"} {
		if err := s.CreateTenant(ctx, &Tenant{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	a := &Agent{AgentID: "a", Token: "secret-a", TenantID: "tenant-a"}
	if err := s.RegisterAgent(ctx, a); err != nil {
		t.Fatal(err)
	}
	b := &Agent{AgentID: "b", Token: "secret-b", TenantID: "tenant-b"}
	if err := s.RegisterAgent(ctx, b); err != nil {
		t.Fatal(err)
	}
	if err := s.RegisterAgent(ctx, &Agent{AgentID: "a", Token: "stolen", TenantID: "tenant-b"}); err == nil {
		t.Fatal("agent takeover accepted")
	}
	got, err := s.GetAgent(ctx, "a")
	if err != nil || got.Token != "secret-a" || got.TenantID != "tenant-a" {
		t.Fatal("agent identity changed")
	}
	if err := s.UpsertDevice(ctx, &Device{Serial: "shared-serial", AgentID: "a", Model: "original"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDevice(ctx, &Device{Serial: "shared-serial", AgentID: "b", Model: "forged"}); err == nil {
		t.Fatal("device takeover accepted")
	}
	d, err := s.GetDevice(ctx, "shared-serial")
	if err != nil || d.AgentID != "a" || d.Model != "original" {
		t.Fatal("device changed")
	}
	if err := s.SaveMetrics(ctx, &MetricsSnapshot{Serial: d.Serial, AgentID: "b", Timestamp: time.Now()}); err == nil {
		t.Fatal("foreign metrics accepted")
	}
	if err := s.SaveMetrics(ctx, &MetricsSnapshot{Serial: d.Serial, AgentID: "a", Timestamp: time.Now()}); err != nil {
		t.Fatal(err)
	}
}

func TestAgentBoundDeviceDeleteCannotCrossOwnership(t *testing.T) {
	s, err := NewSQLiteStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	for _, agentID := range []string{"delete-owner-a", "delete-owner-b"} {
		if err := s.RegisterAgent(ctx, &Agent{AgentID: agentID, Token: agentID + "-token"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.UpsertDevice(ctx, &Device{Serial: "delete-a", AgentID: "delete-owner-a"}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertDevice(ctx, &Device{Serial: "delete-b", AgentID: "delete-owner-b"}); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteDeviceForAgent(ctx, "delete-b", "delete-owner-a", false); err == nil {
		t.Fatal("foreign agent deleted another agent's device")
	}
	if _, err := s.GetDevice(ctx, "delete-b"); err != nil {
		t.Fatalf("foreign device was removed: %v", err)
	}
	if err := s.DeleteDeviceForAgent(ctx, "delete-a", "delete-owner-a", false); err != nil {
		t.Fatalf("owner could not delete device: %v", err)
	}
	if _, err := s.GetDevice(ctx, "delete-a"); err == nil {
		t.Fatal("owned device still exists after delete")
	}
}

func TestSingleUseJoinTokenHasOneConcurrentWinner(t *testing.T) {
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "join.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &Tenant{ID: "tenant", Name: "Test"}); err != nil {
		t.Fatal(err)
	}
	_, raw, err := s.CreateJoinToken(ctx, "tenant", 5, true)
	if err != nil {
		t.Fatal(err)
	}
	var winners atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if _, err := s.ValidateJoinToken(ctx, raw); err == nil {
				winners.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if winners.Load() != 1 {
		t.Fatalf("token used %d times", winners.Load())
	}
}

func TestJoinTokenValidationRejectsOversizedInputBeforeHashing(t *testing.T) {
	if isValidTokenFormat(strings.Repeat("x", 4097)) {
		t.Fatal("oversized join token was accepted")
	}
	if !isValidTokenFormat(strings.Repeat("x", 4096)) {
		t.Fatal("maximum-sized join token was rejected")
	}
}
