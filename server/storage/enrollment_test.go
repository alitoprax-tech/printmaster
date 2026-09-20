package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestMTLSEnrollmentAttemptIdempotencyAndReplayBinding(t *testing.T) {
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "mtls-enrollment.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &Tenant{ID: "attempt-tenant", Name: "attempt-tenant"}); err != nil {
		t.Fatal(err)
	}
	_, token, err := s.CreateJoinToken(ctx, "attempt-tenant", 5, true)
	if err != nil {
		t.Fatal(err)
	}
	const publicKeyHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const csrHash = "1111111111111111111111111111111111111111111111111111111111111111"
	issued := atomic.Int32{}
	issuer := func(join *JoinToken, agent *Agent) (*AgentCredential, []byte, error) {
		issued.Add(1)
		now := time.Now().UTC()
		return &AgentCredential{CredentialID: fmt.Sprintf("attempt-credential-%d", issued.Load()), AgentID: agent.AgentID, TenantID: join.TenantID, CertificateSerial: fmt.Sprintf("serial-%d", issued.Load()), PublicKeySHA256: publicKeyHash, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, []byte("public-certificate"), nil
	}
	agent := &Agent{AgentID: "attempt-agent", Name: "attempt-agent", Hostname: "host", Platform: "windows", Version: "1", ProtocolVersion: "1", Status: "active", RegisteredAt: time.Now().UTC(), LastSeen: time.Now().UTC()}
	const attemptID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, firstCredential, firstCert, err := s.EnrollAgentWithCredentialAttempt(ctx, token, agent, attemptID, csrHash, publicKeyHash, "", issuer)
	if err != nil {
		t.Fatalf("first attempt: %v", err)
	}
	if string(firstCert) != "public-certificate" || firstCredential == nil {
		t.Fatal("first enrollment returned incomplete result")
	}
	_, replayCredential, replayCert, err := s.EnrollAgentWithCredentialAttempt(ctx, "consumed-token-is-allowed-for-exact-replay", &Agent{AgentID: agent.AgentID}, attemptID, csrHash, publicKeyHash, "attempt-tenant", issuer)
	if err != nil {
		t.Fatalf("exact enrollment replay: %v", err)
	}
	if replayCredential.CredentialID != firstCredential.CredentialID || string(replayCert) != string(firstCert) || issued.Load() != 1 {
		t.Fatalf("replay issued a different credential: first=%s replay=%s issued=%d", firstCredential.CredentialID, replayCredential.CredentialID, issued.Load())
	}
	if _, _, _, err := s.EnrollAgentWithCredentialAttempt(ctx, "", &Agent{AgentID: agent.AgentID}, attemptID, "2222222222222222222222222222222222222222222222222222222222222222", publicKeyHash, "", issuer); err == nil {
		t.Fatal("same attempt accepted a different public key binding")
	}
	if _, _, _, err := s.EnrollAgentWithCredentialAttempt(ctx, "", &Agent{AgentID: "other-agent"}, attemptID, csrHash, publicKeyHash, "", issuer); err == nil {
		t.Fatal("same attempt accepted a different Agent")
	}
	if _, _, _, err := s.EnrollAgentWithCredentialAttempt(ctx, "", &Agent{AgentID: agent.AgentID}, attemptID, csrHash, publicKeyHash, "other-tenant", issuer); err == nil {
		t.Fatal("same attempt accepted a different tenant context")
	}
	if _, _, _, err := s.EnrollAgentWithCredentialAttempt(ctx, token, &Agent{AgentID: "new-agent"}, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", csrHash, publicKeyHash, "", issuer); err == nil {
		t.Fatal("consumed join token accepted a different attempt")
	}
	var credentialCount, attemptCount int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM agent_credentials").Scan(&credentialCount); err != nil {
		t.Fatal(err)
	}
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM agent_enrollment_attempts").Scan(&attemptCount); err != nil {
		t.Fatal(err)
	}
	if credentialCount != 1 || attemptCount != 1 {
		t.Fatalf("unexpected logical enrollment count: credentials=%d attempts=%d", credentialCount, attemptCount)
	}
}

func TestMTLSEnrollmentAttemptConcurrentDuplicate(t *testing.T) {
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "mtls-enrollment-race.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	if err := s.CreateTenant(ctx, &Tenant{ID: "race-tenant", Name: "race-tenant"}); err != nil {
		t.Fatal(err)
	}
	_, token, err := s.CreateJoinToken(ctx, "race-tenant", 5, true)
	if err != nil {
		t.Fatal(err)
	}
	const publicKeyHash = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	const csrHash = "3333333333333333333333333333333333333333333333333333333333333333"
	const attemptID = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	issued := atomic.Int32{}
	issuer := func(join *JoinToken, agent *Agent) (*AgentCredential, []byte, error) {
		issued.Add(1)
		now := time.Now().UTC()
		return &AgentCredential{CredentialID: fmt.Sprintf("race-credential-%d", issued.Load()), AgentID: agent.AgentID, TenantID: join.TenantID, CertificateSerial: fmt.Sprintf("race-serial-%d", issued.Load()), PublicKeySHA256: publicKeyHash, IssuedAt: now, ExpiresAt: now.Add(time.Hour)}, []byte("race-certificate"), nil
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	var successes atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			agent := &Agent{AgentID: "race-attempt-agent", Name: "race", Hostname: "host", Platform: "windows", Version: "1", ProtocolVersion: "1", Status: "active", RegisteredAt: time.Now().UTC(), LastSeen: time.Now().UTC()}
			if _, _, _, err := s.EnrollAgentWithCredentialAttempt(ctx, token, agent, attemptID, csrHash, publicKeyHash, "", issuer); err == nil {
				successes.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	var credentialCount, attemptCount int
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM agent_credentials").Scan(&credentialCount); err != nil {
		t.Fatal(err)
	}
	if err := s.DB().QueryRow("SELECT COUNT(*) FROM agent_enrollment_attempts").Scan(&attemptCount); err != nil {
		t.Fatal(err)
	}
	if credentialCount != 1 || attemptCount != 1 || issued.Load() != 1 || successes.Load() == 0 {
		t.Fatalf("concurrent duplicate created unexpected state: successes=%d issued=%d credentials=%d attempts=%d", successes.Load(), issued.Load(), credentialCount, attemptCount)
	}
}
