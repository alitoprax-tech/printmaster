package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
)

func TestSQLiteAppliesSecurityPragmasToEveryConnection(t *testing.T) {
	s, err := NewSQLiteStore(filepath.Join(t.TempDir(), "pragmas.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	first, err := s.DB().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := s.DB().Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	for _, conn := range []*sql.Conn{first, second} {
		var timeout, foreignKeys int
		var journal string
		if err := conn.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&timeout); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRowContext(ctx, "PRAGMA foreign_keys").Scan(&foreignKeys); err != nil {
			t.Fatal(err)
		}
		if err := conn.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&journal); err != nil {
			t.Fatal(err)
		}
		if timeout != 30000 || foreignKeys != 1 || journal != "wal" {
			t.Fatalf("ineffective pragmas: timeout=%d foreign_keys=%d journal=%s", timeout, foreignKeys, journal)
		}
	}
}
