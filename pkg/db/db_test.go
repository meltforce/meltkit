package db

import (
	"testing"
	"testing/fstest"
)

func TestWithPgvectorOption(t *testing.T) {
	var o options
	WithPgvector()(&o)
	if !o.pgvector {
		t.Error("WithPgvector() did not set pgvector flag")
	}
}

func TestRunMigrationsInvalidDSN(t *testing.T) {
	fs := fstest.MapFS{}
	err := RunMigrations("not-a-valid-dsn", fs)
	if err == nil {
		t.Error("expected error for invalid DSN")
	}
}

func TestRunMigrationsEmptyFS(t *testing.T) {
	fs := fstest.MapFS{}
	// Empty FS with valid-looking DSN still fails at migrator creation (no DB),
	// but we're testing that it doesn't panic.
	err := RunMigrations("postgres://user:pass@localhost:5432/db", fs)
	if err == nil {
		// It's expected to fail because there's no actual DB.
		// The point is it doesn't panic and handles the error.
		t.Log("unexpectedly succeeded (maybe a DB is running)")
	}
}
