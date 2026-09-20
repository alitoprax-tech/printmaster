package storage

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// EnrollAgentWithCredential consumes the join token and creates the agent and
// its first certificate identity in one transaction. The issuer runs only after
// the token has been checked under the transaction's write lock, so a failed
// issuance cannot consume a one-time token.
func (s *BaseStore) EnrollAgentWithCredential(ctx context.Context, rawToken string, agent *Agent, issuer AgentCredentialIssuer) (*JoinToken, *AgentCredential, error) {
	if agent == nil || strings.TrimSpace(agent.AgentID) == "" {
		return nil, nil, fmt.Errorf("agent identity required")
	}
	if issuer == nil {
		return nil, nil, fmt.Errorf("credential issuer required")
	}
	join, err := s.validateJoinToken(ctx, rawToken, false)
	if err != nil {
		return nil, nil, err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	now := time.Now().UTC()
	query := fmt.Sprintf(`UPDATE join_tokens
		SET revoked = CASE WHEN one_time = %s THEN %s ELSE revoked END, used_at = ?
		WHERE id = ? AND token_hash = ? AND tenant_id = ? AND revoked = %s AND expires_at > ?`,
		s.dialect.BoolValue(true), s.dialect.BoolValue(true), s.dialect.BoolValue(false))
	result, err := tx.ExecContext(ctx, s.query(query), now, join.ID, join.TokenHash, join.TenantID, now)
	if err != nil {
		return nil, nil, err
	}
	if n, err := result.RowsAffected(); err != nil {
		return nil, nil, err
	} else if n != 1 {
		return nil, nil, &TokenValidationError{Err: ErrTokenRevoked}
	}

	registered := *agent
	registered.TenantID = join.TenantID
	registered.Token = ""
	credential, err := issuer(join, &registered)
	if err != nil {
		return nil, nil, fmt.Errorf("issue agent certificate: %w", err)
	}
	if credential == nil {
		return nil, nil, fmt.Errorf("issuer returned nil credential")
	}
	credential.AgentID = registered.AgentID
	credential.TenantID = registered.TenantID
	if err := validateAgentCredential(credential); err != nil {
		return nil, nil, err
	}

	upsert := func(ctx context.Context, query string, args ...interface{}) (int64, error) {
		var id int64
		if err := tx.QueryRowContext(ctx, s.query(query)+" RETURNING id", args...).Scan(&id); err != nil {
			return 0, err
		}
		return id, nil
	}
	if err := s.registerAgent(ctx, &registered, upsert); err != nil {
		return nil, nil, fmt.Errorf("register agent: %w", err)
	}
	if err := insertAgentCredential(ctx, s.query, tx.ExecContext, credential); err != nil {
		return nil, nil, fmt.Errorf("store agent certificate identity: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, err
	}
	*agent = registered
	return join, credential, nil
}

func validateAgentCredential(credential *AgentCredential) error {
	if credential == nil || strings.TrimSpace(credential.CredentialID) == "" ||
		strings.TrimSpace(credential.AgentID) == "" || strings.TrimSpace(credential.TenantID) == "" ||
		strings.TrimSpace(credential.CertificateSerial) == "" || strings.TrimSpace(credential.PublicKeySHA256) == "" {
		return fmt.Errorf("incomplete agent credential")
	}
	if credential.IssuedAt.IsZero() || credential.ExpiresAt.IsZero() || !credential.ExpiresAt.After(credential.IssuedAt) {
		return fmt.Errorf("invalid agent credential lifetime")
	}
	return nil
}

// insertAgentCredential is shared by transactional enrollment and normal
// rotation. query converts placeholders for PostgreSQL; exec is supplied by
// either *sql.DB or *sql.Tx.
func insertAgentCredential(ctx context.Context, query func(string) string, exec func(context.Context, string, ...interface{}) (sql.Result, error), credential *AgentCredential) error {
	if err := validateAgentCredential(credential); err != nil {
		return err
	}
	_, err := exec(ctx, query(`
		INSERT INTO agent_credentials (
			credential_id, agent_id, tenant_id, certificate_serial,
			public_key_sha256, issued_at, expires_at, revoked_at, revoke_reason
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`), credential.CredentialID, credential.AgentID, credential.TenantID,
		credential.CertificateSerial, credential.PublicKeySHA256, credential.IssuedAt,
		credential.ExpiresAt, credential.RevokedAt, credential.RevokeReason)
	return err
}

// CreateAgentCredential stores a newly issued identity during rotation.
func (s *BaseStore) CreateAgentCredential(ctx context.Context, credential *AgentCredential) error {
	return insertAgentCredential(ctx, s.query, s.db.ExecContext, credential)
}

// GetAgentCredential retrieves a credential by its opaque public identifier.
func (s *BaseStore) GetAgentCredential(ctx context.Context, credentialID string) (*AgentCredential, error) {
	var credential AgentCredential
	var revokedAt sql.NullTime
	var revokeReason sql.NullString
	err := s.queryRowContext(ctx, `
		SELECT credential_id, agent_id, tenant_id, certificate_serial,
		       public_key_sha256, issued_at, expires_at, revoked_at, revoke_reason
		FROM agent_credentials WHERE credential_id = ?
	`, credentialID).Scan(&credential.CredentialID, &credential.AgentID, &credential.TenantID,
		&credential.CertificateSerial, &credential.PublicKeySHA256, &credential.IssuedAt,
		&credential.ExpiresAt, &revokedAt, &revokeReason)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("agent credential not found")
	}
	if err != nil {
		return nil, err
	}
	if revokedAt.Valid {
		v := revokedAt.Time
		credential.RevokedAt = &v
	}
	credential.RevokeReason = revokeReason.String
	return &credential, nil
}

// RevokeAgentCredential makes both new handshakes and active-connection
// revalidation fail. WebSocket cleanup is performed by the HTTP layer.
func (s *BaseStore) RevokeAgentCredential(ctx context.Context, credentialID, reason string) error {
	if strings.TrimSpace(credentialID) == "" {
		return fmt.Errorf("credential id required")
	}
	_, err := s.execContext(ctx, `UPDATE agent_credentials SET revoked_at = ?, revoke_reason = ? WHERE credential_id = ? AND revoked_at IS NULL`, time.Now().UTC(), strings.TrimSpace(reason), credentialID)
	return err
}

// RevokeOtherAgentCredentials retires older identities after the agent has
// successfully installed and authenticated with a replacement certificate.
func (s *BaseStore) RevokeOtherAgentCredentials(ctx context.Context, agentID, keepCredentialID, reason string) error {
	if strings.TrimSpace(agentID) == "" || strings.TrimSpace(keepCredentialID) == "" {
		return fmt.Errorf("agent and credential ids required")
	}
	_, err := s.execContext(ctx, `UPDATE agent_credentials SET revoked_at = ?, revoke_reason = ? WHERE agent_id = ? AND credential_id <> ? AND revoked_at IS NULL`, time.Now().UTC(), strings.TrimSpace(reason), agentID, keepCredentialID)
	return err
}

// ClearLegacyAgentToken retires the bearer hash after migration activation.
func (s *BaseStore) ClearLegacyAgentToken(ctx context.Context, agentID string) error {
	if strings.TrimSpace(agentID) == "" {
		return fmt.Errorf("agent id required")
	}
	_, err := s.execContext(ctx, `UPDATE agents SET token = '', legacy_token_hash = '' WHERE agent_id = ?`, agentID)
	return err
}

// migrateLegacyAgentTokens upgrades pre-P0-01 databases without exposing the
// old bearer value after startup. It is idempotent and intentionally does not
// log token material.
func (s *BaseStore) migrateLegacyAgentTokens() error {
	rows, err := s.db.QueryContext(context.Background(), s.query(`SELECT agent_id, token FROM agents WHERE COALESCE(token, '') <> '' AND COALESCE(legacy_token_hash, '') = ''`))
	if err != nil {
		return fmt.Errorf("read legacy agent tokens: %w", err)
	}
	type legacyToken struct{ agentID, token string }
	var pending []legacyToken
	for rows.Next() {
		var v legacyToken
		if err := rows.Scan(&v.agentID, &v.token); err != nil {
			rows.Close()
			return fmt.Errorf("scan legacy agent token: %w", err)
		}
		pending = append(pending, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate legacy agent tokens: %w", err)
	}
	rows.Close()
	for _, v := range pending {
		if _, err := s.execContext(context.Background(), `UPDATE agents SET legacy_token_hash = ?, token = '' WHERE agent_id = ? AND token = ?`, hashLegacyAgentToken(v.token), v.agentID, v.token); err != nil {
			return fmt.Errorf("migrate legacy agent token: %w", err)
		}
	}
	return nil
}
