//go:build integration

package storage

import "testing"

func TestPostgresEnrollmentAtomicity(t *testing.T) {
	WithPostgresStore(t, func(t *testing.T, s *PostgresStore) { checkEnrollmentAtomicity(t, s) })
}
