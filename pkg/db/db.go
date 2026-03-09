package db

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	pgvector "github.com/pgvector/pgvector-go/pgx"
)

// DB wraps a pgxpool.Pool.
type DB struct {
	Pool *pgxpool.Pool
}

// Option configures DB creation.
type Option func(*options)

type options struct {
	pgvector bool
}

// WithPgvector enables pgvector type registration on each connection.
func WithPgvector() Option {
	return func(o *options) {
		o.pgvector = true
	}
}

// New creates a new database connection pool.
func New(ctx context.Context, dsn string, opts ...Option) (*DB, error) {
	var o options
	for _, opt := range opts {
		opt(&o)
	}

	config, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parsing dsn: %w", err)
	}

	if o.pgvector {
		config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			return pgvector.RegisterTypes(ctx, conn)
		}
	}

	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("creating pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pinging database: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Close closes the connection pool.
func (db *DB) Close() {
	db.Pool.Close()
}

// RunMigrations runs database migrations from an embedded filesystem.
func RunMigrations(dsn string, migrationsFS fs.FS) error {
	source, err := iofs.New(migrationsFS, ".")
	if err != nil {
		return fmt.Errorf("creating migration source: %w", err)
	}
	m, err := migrate.NewWithSourceInstance("iofs", source, dsn)
	if err != nil {
		return fmt.Errorf("creating migrator: %w", err)
	}
	defer func() { _, _ = m.Close() }()

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("running migrations: %w", err)
	}
	return nil
}
