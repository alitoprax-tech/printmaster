package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestEnrollmentAtomicity(t *testing.T) {
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "enrollment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	checkEnrollmentAtomicity(t, s)
}

// Shared with the PostgreSQL integration suite so both dialects exercise the
// same ownership, rollback and concurrent-consumption contract.
func checkEnrollmentAtomicity(t *testing.T, s Store) {
	t.Helper()
	ctx := context.Background()
	for _, id := range []string{"enrollment-a", "enrollment-b"} {
		if err := s.CreateTenant(ctx, &Tenant{ID: id, Name: id}); err != nil {
			t.Fatal(err)
		}
	}
	_, raw, err := s.CreateJoinToken(ctx, "enrollment-a", 5, true)
	if err != nil {
		t.Fatal(err)
	}
	original := &Agent{AgentID: "existing-enrollment", Token: "original-secret", TenantID: "enrollment-b"}
	if err := s.RegisterAgent(ctx, original); err != nil {
		t.Fatal(err)
	}
	if _, err := s.EnrollAgent(ctx, raw, &Agent{AgentID: original.AgentID, Token: "replacement-secret"}); err == nil {
		t.Fatal("existing agent taken over")
	}
	stored, err := s.GetAgent(ctx, original.AgentID)
	if err != nil || stored.Token != "" || stored.TenantID != original.TenantID {
		t.Fatal("failed enrollment changed original identity")
	}
	// The failed write must not burn the one-time token.
	fresh := &Agent{AgentID: "fresh-enrollment", Token: "new-secret", TenantID: "enrollment-b"}
	if _, err := s.EnrollAgent(ctx, raw, fresh); err != nil {
		t.Fatalf("token lost after failed registration: %v", err)
	}
	if fresh.ID == 0 || fresh.TenantID != "enrollment-a" {
		t.Fatal("enrollment did not bind database ID and token tenant")
	}
	if _, err := s.EnrollAgent(ctx, raw, &Agent{AgentID: "replay-enrollment", Token: "another-secret"}); err == nil {
		t.Fatal("consumed token replayed")
	}
	if _, err := s.GetAgent(ctx, "replay-enrollment"); err == nil {
		t.Fatal("failed replay persisted an agent")
	}

	_, raceToken, err := s.CreateJoinToken(ctx, "enrollment-a", 5, true)
	if err != nil {
		t.Fatal(err)
	}
	var wins atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			if _, err := s.EnrollAgent(ctx, raceToken, &Agent{AgentID: fmt.Sprintf("race-enrollment-%d", i), Token: fmt.Sprintf("race-secret-%d", i)}); err == nil {
				wins.Add(1)
			} else {
				t.Logf("concurrent attempt %d rejected: %v", i, err)
			}
		}(i)
	}
	close(start)
	wg.Wait()
	if wins.Load() != 1 {
		t.Fatalf("concurrent enrollment winners: %d", wins.Load())
	}
	registeredCount := 0
	for i := 0; i < 4; i++ {
		if _, err := s.GetAgent(ctx, fmt.Sprintf("race-enrollment-%d", i)); err == nil {
			registeredCount++
		}
	}
	if registeredCount != 1 {
		t.Fatalf("race persisted %d agents", registeredCount)
	}

	_, reusable, err := s.CreateJoinToken(ctx, "enrollment-a", 5, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err := s.EnrollAgent(ctx, reusable, &Agent{AgentID: fmt.Sprintf("reusable-enrollment-%d", i), Token: fmt.Sprintf("reusable-secret-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
}
