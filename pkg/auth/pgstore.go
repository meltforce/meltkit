package auth

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/meltforce/meltkit/pkg/db"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// MigrationsTable is the golang-migrate version table of the auth schema,
// kept apart from the app's own numbering.
const MigrationsTable = "auth_schema_migrations"

// Migrations returns the SQL migrations of the auth tables.
func Migrations() fs.FS {
	sub, _ := fs.Sub(migrationsFS, "migrations")
	return sub
}

// RunMigrations applies Migrations to the database at dsn (URL form),
// recording versions in MigrationsTable.
func RunMigrations(dsn string) error {
	u, err := url.Parse(dsn)
	if err != nil || u.Scheme == "" {
		return fmt.Errorf("auth migrations: dsn must be a postgres:// URL")
	}
	q := u.Query()
	q.Set("x-migrations-table", MigrationsTable)
	u.RawQuery = q.Encode()
	return db.RunMigrations(u.String(), Migrations())
}

// Querier is the subset of *pgxpool.Pool that PgxStore uses.
type Querier interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PgxStore implements Store on PostgreSQL.
type PgxStore struct {
	q Querier
}

// NewPgxStore returns a Store backed by q, typically a *pgxpool.Pool.
func NewPgxStore(q Querier) *PgxStore {
	return &PgxStore{q: q}
}

var (
	_ Store      = (*PgxStore)(nil)
	_ TokenStore = (*PgxStore)(nil)
)

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func uniqueViolation(err error) error {
	var pe *pgconn.PgError
	if errors.As(err, &pe) && pe.Code == "23505" {
		return ErrExists
	}
	return err
}

func affected(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

const sessionCols = `id, token_hash, user_id, method, login, display_name, created_at, expires_at, last_used_at, client_ip, user_agent`

func scanSession(row pgx.Row) (Session, error) {
	var s Session
	err := row.Scan(&s.ID, &s.TokenHash, &s.UserID, &s.Method, &s.Login, &s.DisplayName,
		&s.CreatedAt, &s.ExpiresAt, &s.LastUsedAt, &s.ClientIP, &s.UserAgent)
	return s, err
}

func (p *PgxStore) CreateSession(ctx context.Context, s *Session) error {
	return p.q.QueryRow(ctx, `
		INSERT INTO auth_sessions (token_hash, user_id, method, login, display_name, created_at, expires_at, last_used_at, client_ip, user_agent)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id`,
		s.TokenHash, s.UserID, s.Method, s.Login, s.DisplayName, s.CreatedAt, s.ExpiresAt, s.LastUsedAt, s.ClientIP, s.UserAgent,
	).Scan(&s.ID)
}

func (p *PgxStore) GetSession(ctx context.Context, tokenHash []byte, now time.Time) (Session, error) {
	s, err := scanSession(p.q.QueryRow(ctx,
		`SELECT `+sessionCols+` FROM auth_sessions WHERE token_hash = $1 AND expires_at > $2`, tokenHash, now))
	return s, notFound(err)
}

func (p *PgxStore) TouchSession(ctx context.Context, id int64, lastUsed time.Time) error {
	_, err := p.q.Exec(ctx, `UPDATE auth_sessions SET last_used_at = $2 WHERE id = $1`, id, lastUsed)
	return err
}

func (p *PgxStore) DeleteSessionByHash(ctx context.Context, tokenHash []byte) error {
	_, err := p.q.Exec(ctx, `DELETE FROM auth_sessions WHERE token_hash = $1`, tokenHash)
	return err
}

func (p *PgxStore) DeleteSession(ctx context.Context, userID, id int64) error {
	return affected(p.q.Exec(ctx, `DELETE FROM auth_sessions WHERE id = $1 AND user_id = $2`, id, userID))
}

func (p *PgxStore) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := p.q.Exec(ctx, `DELETE FROM auth_sessions WHERE user_id = $1`, userID)
	return err
}

func (p *PgxStore) DeleteExpiredSessions(ctx context.Context, now time.Time) error {
	_, err := p.q.Exec(ctx, `DELETE FROM auth_sessions WHERE expires_at <= $1`, now)
	return err
}

func (p *PgxStore) ListSessions(ctx context.Context, userID int64, now time.Time) ([]Session, error) {
	rows, err := p.q.Query(ctx,
		`SELECT `+sessionCols+` FROM auth_sessions WHERE user_id = $1 AND expires_at > $2 ORDER BY last_used_at DESC`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Session
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *PgxStore) GetIdentity(ctx context.Context, issuer, subject string) (IdentityLink, error) {
	l := IdentityLink{Issuer: issuer, Subject: subject}
	err := p.q.QueryRow(ctx,
		`SELECT user_id, email, created_at FROM auth_identities WHERE issuer = $1 AND subject = $2`, issuer, subject,
	).Scan(&l.UserID, &l.Email, &l.CreatedAt)
	return l, notFound(err)
}

func (p *PgxStore) CreateIdentity(ctx context.Context, l IdentityLink) error {
	_, err := p.q.Exec(ctx,
		`INSERT INTO auth_identities (issuer, subject, user_id, email) VALUES ($1, $2, $3, $4)`,
		l.Issuer, l.Subject, l.UserID, l.Email)
	return uniqueViolation(err)
}

func (p *PgxStore) UserHasIdentity(ctx context.Context, userID int64) (bool, error) {
	var has bool
	err := p.q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM auth_identities WHERE user_id = $1)`, userID).Scan(&has)
	return has, err
}

func (p *PgxStore) ListIdentities(ctx context.Context, userID int64) ([]IdentityLink, error) {
	rows, err := p.q.Query(ctx,
		`SELECT issuer, subject, user_id, email, created_at FROM auth_identities WHERE user_id = $1 ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IdentityLink
	for rows.Next() {
		var l IdentityLink
		if err := rows.Scan(&l.Issuer, &l.Subject, &l.UserID, &l.Email, &l.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func (p *PgxStore) DeleteIdentity(ctx context.Context, userID int64, issuer, subject string) error {
	return affected(p.q.Exec(ctx,
		`DELETE FROM auth_identities WHERE issuer = $1 AND subject = $2 AND user_id = $3`, issuer, subject, userID))
}

func (p *PgxStore) CreateOIDCLink(ctx context.Context, stateHash []byte, userID int64, expiresAt time.Time) error {
	_, err := p.q.Exec(ctx, `
		WITH expired AS (DELETE FROM auth_oidc_links WHERE expires_at <= now())
		INSERT INTO auth_oidc_links (state_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
		stateHash, userID, expiresAt)
	return err
}

func (p *PgxStore) ConsumeOIDCLink(ctx context.Context, stateHash []byte, now time.Time) (int64, error) {
	var uid int64
	var exp time.Time
	err := p.q.QueryRow(ctx,
		`DELETE FROM auth_oidc_links WHERE state_hash = $1 RETURNING user_id, expires_at`, stateHash).Scan(&uid, &exp)
	if err != nil {
		return 0, notFound(err)
	}
	if !exp.After(now) {
		return 0, ErrNotFound
	}
	return uid, nil
}

const passwordCols = `user_id, username, hash, failed_attempts, last_failed_at`

func scanPassword(row pgx.Row) (PasswordRecord, error) {
	var r PasswordRecord
	var last *time.Time
	if err := row.Scan(&r.UserID, &r.Username, &r.Hash, &r.FailedAttempts, &last); err != nil {
		return PasswordRecord{}, notFound(err)
	}
	if last != nil {
		r.LastFailedAt = *last
	}
	return r, nil
}

func (p *PgxStore) GetPasswordByUsername(ctx context.Context, username string) (PasswordRecord, error) {
	return scanPassword(p.q.QueryRow(ctx,
		`SELECT `+passwordCols+` FROM auth_passwords WHERE lower(username) = lower($1)`, username))
}

func (p *PgxStore) GetPasswordByUserID(ctx context.Context, userID int64) (PasswordRecord, error) {
	return scanPassword(p.q.QueryRow(ctx,
		`SELECT `+passwordCols+` FROM auth_passwords WHERE user_id = $1`, userID))
}

func (p *PgxStore) CreatePassword(ctx context.Context, r PasswordRecord) error {
	_, err := p.q.Exec(ctx,
		`INSERT INTO auth_passwords (user_id, username, hash) VALUES ($1, $2, $3)`, r.UserID, r.Username, r.Hash)
	return uniqueViolation(err)
}

func (p *PgxStore) UpdatePasswordHash(ctx context.Context, userID int64, hash string) error {
	return affected(p.q.Exec(ctx,
		`UPDATE auth_passwords SET hash = $2, updated_at = now() WHERE user_id = $1`, userID, hash))
}

func (p *PgxStore) RecordLoginFailure(ctx context.Context, userID int64, at time.Time) error {
	_, err := p.q.Exec(ctx,
		`UPDATE auth_passwords SET failed_attempts = failed_attempts + 1, last_failed_at = $2 WHERE user_id = $1`, userID, at)
	return err
}

func (p *PgxStore) ResetLoginFailures(ctx context.Context, userID int64) error {
	_, err := p.q.Exec(ctx,
		`UPDATE auth_passwords SET failed_attempts = 0, last_failed_at = NULL WHERE user_id = $1`, userID)
	return err
}

func (p *PgxStore) DeleteUser(ctx context.Context, userID int64) error {
	// One statement, so the deletes commit together.
	_, err := p.q.Exec(ctx, `
		WITH s AS (DELETE FROM auth_sessions WHERE user_id = $1),
		     i AS (DELETE FROM auth_identities WHERE user_id = $1),
		     l AS (DELETE FROM auth_oidc_links WHERE user_id = $1),
		     t AS (DELETE FROM auth_tokens WHERE user_id = $1)
		DELETE FROM auth_passwords WHERE user_id = $1`, userID)
	return err
}

const tokenCols = `id, token_hash, user_id, name, scopes, created_at, expires_at, last_used_at`

func scanToken(row pgx.Row) (Token, error) {
	var t Token
	var exp, last *time.Time
	if err := row.Scan(&t.ID, &t.TokenHash, &t.UserID, &t.Name, &t.Scopes, &t.CreatedAt, &exp, &last); err != nil {
		return Token{}, err
	}
	if exp != nil {
		t.ExpiresAt = *exp
	}
	if last != nil {
		t.LastUsedAt = *last
	}
	return t, nil
}

// nullTime maps the zero time to NULL.
func nullTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func (p *PgxStore) CreateToken(ctx context.Context, t *Token) error {
	return p.q.QueryRow(ctx, `
		INSERT INTO auth_tokens (token_hash, user_id, name, scopes, created_at, expires_at, last_used_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id`,
		t.TokenHash, t.UserID, t.Name, t.Scopes, t.CreatedAt, nullTime(t.ExpiresAt), nullTime(t.LastUsedAt),
	).Scan(&t.ID)
}

func (p *PgxStore) GetToken(ctx context.Context, tokenHash []byte, now time.Time) (Token, error) {
	t, err := scanToken(p.q.QueryRow(ctx,
		`SELECT `+tokenCols+` FROM auth_tokens WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > $2)`, tokenHash, now))
	return t, notFound(err)
}

func (p *PgxStore) TouchToken(ctx context.Context, id int64, lastUsed time.Time) error {
	_, err := p.q.Exec(ctx, `UPDATE auth_tokens SET last_used_at = $2 WHERE id = $1`, id, lastUsed)
	return err
}

func (p *PgxStore) ListTokens(ctx context.Context, userID int64) ([]Token, error) {
	rows, err := p.q.Query(ctx, `SELECT `+tokenCols+` FROM auth_tokens WHERE user_id = $1 ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Token
	for rows.Next() {
		t, err := scanToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *PgxStore) DeleteToken(ctx context.Context, userID, id int64) error {
	return affected(p.q.Exec(ctx, `DELETE FROM auth_tokens WHERE id = $1 AND user_id = $2`, id, userID))
}
