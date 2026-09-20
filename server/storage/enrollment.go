package storage

import (
	"context"
	"fmt"
	"time"
)

// EnrollAgent binds token consumption and registration in one transaction. Hash
// verification happens before the write transaction; mutable token state is then
// checked again under a conditional UPDATE lock before any agent can be written.
func (s *BaseStore) EnrollAgent(ctx context.Context, rawToken string, agent *Agent) (*JoinToken, error) {
	if agent == nil || agent.AgentID == "" || agent.Token == "" {
		return nil, fmt.Errorf("agent identity and credential required")
	}
	join, err := s.validateJoinToken(ctx, rawToken, false)
	if err != nil {
		return nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	query := fmt.Sprintf(`UPDATE join_tokens
		SET revoked = CASE WHEN one_time = %s THEN %s ELSE revoked END, used_at = ?
		WHERE id = ? AND token_hash = ? AND tenant_id = ? AND revoked = %s AND expires_at > ?`,
		s.dialect.BoolValue(true), s.dialect.BoolValue(true), s.dialect.BoolValue(false))
	result, err := tx.ExecContext(ctx, s.query(query), now, join.ID, join.TokenHash, join.TenantID, now)
	if err != nil {
		return nil, err
	}
	if n, err := result.RowsAffected(); err != nil {
		return nil, err
	} else if n != 1 {
		return nil, &TokenValidationError{Err: ErrTokenRevoked}
	}
	registered := *agent
	registered.TenantID = join.TenantID // Caller-supplied tenant never controls enrollment.
	upsert := func(ctx context.Context, query string, args ...interface{}) (int64, error) {
		var id int64
		err := tx.QueryRowContext(ctx, s.query(query)+" RETURNING id", args...).Scan(&id)
		return id, err
	}
	if err := s.registerAgent(ctx, &registered, upsert); err != nil {
		return nil, fmt.Errorf("register agent: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	*agent = registered
	return join, nil
}
