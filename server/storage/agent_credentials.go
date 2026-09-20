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

// EnrollAgentWithCredentialAttempt performs first mTLS enrollment with a
// durable, replay-bound attempt ID. The lookup happens before token
// validation, so an exact retry can recover after the one-time token has been
// consumed. A new attempt consumes the token and stores the public certificate
// and binding in the same transaction as the credential and Agent row.
func (s *BaseStore) EnrollAgentWithCredentialAttempt(ctx context.Context, rawToken string, agent *Agent, attemptID, csrSHA256, publicKeySHA256, requestedTenantID string, issuer AgentEnrollmentIssuer) (*JoinToken, *AgentCredential, []byte, error) {
	if agent == nil || strings.TrimSpace(agent.AgentID) == "" {
		return nil, nil, nil, fmt.Errorf("agent identity required")
	}
	attemptID = strings.TrimSpace(attemptID)
	csrSHA256 = strings.ToLower(strings.TrimSpace(csrSHA256))
	publicKeySHA256 = strings.ToLower(strings.TrimSpace(publicKeySHA256))
	requestedTenantID = strings.TrimSpace(requestedTenantID)
	if !validEnrollmentAttemptID(attemptID) || !validEnrollmentHex(csrSHA256) || !validEnrollmentHex(publicKeySHA256) {
		return nil, nil, nil, fmt.Errorf("enrollment attempt, CSR and public key bindings required")
	}
	if issuer == nil {
		return nil, nil, nil, fmt.Errorf("credential issuer required")
	}
	if existing, err := s.getEnrollmentAttempt(ctx, attemptID); err == nil {
		credential, cert, replayErr := s.validateEnrollmentReplay(ctx, existing, agent.AgentID, csrSHA256, publicKeySHA256, requestedTenantID)
		if replayErr != nil {
			return nil, nil, nil, replayErr
		}
		return nil, credential, cert, nil
	} else if err != sql.ErrNoRows {
		return nil, nil, nil, err
	}

	join, err := s.validateJoinToken(ctx, rawToken, false)
	if err != nil {
		return nil, nil, nil, err
	}
	if requestedTenantID != "" && requestedTenantID != join.TenantID {
		return nil, nil, nil, fmt.Errorf("requested tenant does not match join token")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	defer tx.Rollback()
	// A concurrent duplicate may have committed while token validation ran.
	if existing, existingErr := s.getEnrollmentAttemptTx(ctx, tx, attemptID); existingErr == nil {
		if requestedTenantID != "" && requestedTenantID != existing.TenantID {
			return nil, nil, nil, fmt.Errorf("requested tenant does not match enrollment attempt")
		}
		if existing.AgentID != agent.AgentID || !strings.EqualFold(existing.CSRSHA256, csrSHA256) || !strings.EqualFold(existing.PublicKeySHA256, publicKeySHA256) {
			return nil, nil, nil, fmt.Errorf("enrollment attempt binding mismatch")
		}
		if err := tx.Rollback(); err != nil && err != sql.ErrTxDone {
			return nil, nil, nil, err
		}
		credential, cert, replayErr := s.validateEnrollmentReplay(ctx, existing, agent.AgentID, csrSHA256, publicKeySHA256, requestedTenantID)
		if replayErr != nil {
			return nil, nil, nil, replayErr
		}
		return nil, credential, cert, nil
	} else if existingErr != sql.ErrNoRows {
		return nil, nil, nil, existingErr
	}

	now := time.Now().UTC()
	query := fmt.Sprintf(`UPDATE join_tokens
		SET revoked = CASE WHEN one_time = %s THEN %s ELSE revoked END, used_at = ?
		WHERE id = ? AND token_hash = ? AND tenant_id = ? AND revoked = %s AND expires_at > ?`,
		s.dialect.BoolValue(true), s.dialect.BoolValue(true), s.dialect.BoolValue(false))
	result, err := tx.ExecContext(ctx, s.query(query), now, join.ID, join.TokenHash, join.TenantID, now)
	if err != nil {
		return nil, nil, nil, err
	}
	if n, err := result.RowsAffected(); err != nil {
		return nil, nil, nil, err
	} else if n != 1 {
		// Another request may have won the one-time token race. If it was this
		// exact attempt, return its durable certificate; otherwise reject the
		// replay and never issue a second credential.
		_ = tx.Rollback()
		if existing, lookupErr := s.getEnrollmentAttempt(ctx, attemptID); lookupErr == nil {
			credential, cert, replayErr := s.validateEnrollmentReplay(ctx, existing, agent.AgentID, csrSHA256, publicKeySHA256, requestedTenantID)
			if replayErr != nil {
				return nil, nil, nil, replayErr
			}
			return nil, credential, cert, nil
		}
		return nil, nil, nil, &TokenValidationError{Err: ErrTokenRevoked}
	}

	registered := *agent
	registered.TenantID = join.TenantID
	registered.Token = ""
	credential, certificatePEM, err := issuer(join, &registered)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("issue agent certificate: %w", err)
	}
	if credential == nil || len(certificatePEM) == 0 {
		return nil, nil, nil, fmt.Errorf("issuer returned incomplete credential")
	}
	credential.AgentID = registered.AgentID
	credential.TenantID = registered.TenantID
	if !strings.EqualFold(credential.PublicKeySHA256, publicKeySHA256) {
		return nil, nil, nil, fmt.Errorf("certificate public key does not match enrollment attempt")
	}
	if err := validateAgentCredential(credential); err != nil {
		return nil, nil, nil, err
	}
	upsert := func(ctx context.Context, query string, args ...interface{}) (int64, error) {
		var id int64
		if err := tx.QueryRowContext(ctx, s.query(query)+" RETURNING id", args...).Scan(&id); err != nil {
			return 0, err
		}
		return id, nil
	}
	if err := s.registerAgent(ctx, &registered, upsert); err != nil {
		return nil, nil, nil, fmt.Errorf("register agent: %w", err)
	}
	if err := insertAgentCredential(ctx, s.query, tx.ExecContext, credential); err != nil {
		return nil, nil, nil, fmt.Errorf("store agent certificate identity: %w", err)
	}
	if err := insertEnrollmentAttempt(ctx, s.query, tx.ExecContext, &AgentEnrollmentAttempt{AttemptID: attemptID, AgentID: registered.AgentID, TenantID: registered.TenantID, CSRSHA256: csrSHA256, PublicKeySHA256: publicKeySHA256, CredentialID: credential.CredentialID, CertificatePEM: certificatePEM, CreatedAt: now}); err != nil {
		return nil, nil, nil, fmt.Errorf("store enrollment attempt: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, nil, nil, err
	}
	*agent = registered
	return join, credential, certificatePEM, nil
}

func validEnrollmentHex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func validEnrollmentAttemptID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && r != '-' && r != '_' && r != '.' && r != '~' {
			return false
		}
	}
	return true
}

func (s *BaseStore) validateEnrollmentReplay(ctx context.Context, attempt *AgentEnrollmentAttempt, agentID, csrSHA256, publicKeySHA256, requestedTenantID string) (*AgentCredential, []byte, error) {
	if attempt == nil || attempt.AgentID != agentID || !strings.EqualFold(attempt.CSRSHA256, csrSHA256) || !strings.EqualFold(attempt.PublicKeySHA256, publicKeySHA256) {
		return nil, nil, fmt.Errorf("enrollment attempt binding mismatch")
	}
	if requestedTenantID != "" && requestedTenantID != attempt.TenantID {
		return nil, nil, fmt.Errorf("requested tenant does not match enrollment attempt")
	}
	credential, err := s.GetAgentCredential(ctx, attempt.CredentialID)
	if err != nil {
		return nil, nil, err
	}
	if credential.AgentID != attempt.AgentID || credential.TenantID != attempt.TenantID || !strings.EqualFold(credential.PublicKeySHA256, attempt.PublicKeySHA256) {
		return nil, nil, fmt.Errorf("stored enrollment credential binding mismatch")
	}
	if credential.RevokedAt != nil {
		return nil, nil, fmt.Errorf("enrollment credential revoked")
	}
	if len(attempt.CertificatePEM) == 0 {
		return nil, nil, fmt.Errorf("stored enrollment certificate unavailable")
	}
	return credential, append([]byte(nil), attempt.CertificatePEM...), nil
}

func (s *BaseStore) getEnrollmentAttempt(ctx context.Context, attemptID string) (*AgentEnrollmentAttempt, error) {
	return scanEnrollmentAttempt(s.queryRowContext(ctx, `
		SELECT attempt_id, agent_id, tenant_id, csr_sha256, public_key_sha256, credential_id, certificate_pem, created_at
		FROM agent_enrollment_attempts WHERE attempt_id = ?
	`, attemptID))
}

func (s *BaseStore) getEnrollmentAttemptTx(ctx context.Context, tx *sql.Tx, attemptID string) (*AgentEnrollmentAttempt, error) {
	query := `
		SELECT attempt_id, agent_id, tenant_id, csr_sha256, public_key_sha256, credential_id, certificate_pem, created_at
		FROM agent_enrollment_attempts WHERE attempt_id = ?`
	if s.dialect.Name() == "postgres" {
		query += " FOR UPDATE"
	}
	return scanEnrollmentAttempt(tx.QueryRowContext(ctx, s.query(query), attemptID))
}

func scanEnrollmentAttempt(row interface{ Scan(...interface{}) error }) (*AgentEnrollmentAttempt, error) {
	var attempt AgentEnrollmentAttempt
	if err := row.Scan(&attempt.AttemptID, &attempt.AgentID, &attempt.TenantID, &attempt.CSRSHA256, &attempt.PublicKeySHA256, &attempt.CredentialID, &attempt.CertificatePEM, &attempt.CreatedAt); err != nil {
		return nil, err
	}
	return &attempt, nil
}

func insertEnrollmentAttempt(ctx context.Context, query func(string) string, exec func(context.Context, string, ...interface{}) (sql.Result, error), attempt *AgentEnrollmentAttempt) error {
	if attempt == nil || strings.TrimSpace(attempt.AttemptID) == "" || strings.TrimSpace(attempt.AgentID) == "" || strings.TrimSpace(attempt.TenantID) == "" || strings.TrimSpace(attempt.CSRSHA256) == "" || strings.TrimSpace(attempt.CredentialID) == "" || len(attempt.CertificatePEM) == 0 {
		return fmt.Errorf("incomplete enrollment attempt")
	}
	_, err := exec(ctx, query(`
		INSERT INTO agent_enrollment_attempts (
			attempt_id, agent_id, tenant_id, csr_sha256, public_key_sha256,
			credential_id, certificate_pem, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`), attempt.AttemptID, attempt.AgentID, attempt.TenantID, attempt.CSRSHA256, attempt.PublicKeySHA256, attempt.CredentialID, string(attempt.CertificatePEM), attempt.CreatedAt)
	return err
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
