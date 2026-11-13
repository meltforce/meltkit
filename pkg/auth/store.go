package auth

import (
	"context"
	"errors"
	"time"
)

// ErrNotFound is returned by a Store when the requested row does not exist.
var ErrNotFound = errors.New("auth: not found")

// ErrExists is returned by a Store when a unique key is already taken.
var ErrExists = errors.New("auth: already exists")

// Session is one browser login.
type Session struct {
	ID          int64     `json:"id"`
	TokenHash   []byte    `json:"-"` // SHA-256 of the cookie token
	UserID      int64     `json:"user_id"`
	Method      string    `json:"method"`
	Login       string    `json:"login"`
	DisplayName string    `json:"display_name"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
	ClientIP    string    `json:"client_ip"`
	UserAgent   string    `json:"user_agent"`
}

// IdentityLink maps an OIDC (issuer, subject) to an app user.
type IdentityLink struct {
	Issuer  string
	Subject string
	UserID  int64
	Email   string
}

// PasswordRecord is a local password account.
type PasswordRecord struct {
	UserID         int64
	Username       string
	Hash           string // PHC-formatted argon2id hash
	FailedAttempts int
	LastFailedAt   time.Time // zero if never
}

// Store persists sessions, identities and passwords. NewPgxStore is the
// PostgreSQL implementation.
type Store interface {
	CreateSession(ctx context.Context, s *Session) error // sets s.ID
	// GetSession returns the session with this token hash whose expiry lies
	// after now, or ErrNotFound.
	GetSession(ctx context.Context, tokenHash []byte, now time.Time) (Session, error)
	TouchSession(ctx context.Context, id int64, lastUsed time.Time) error
	DeleteSessionByHash(ctx context.Context, tokenHash []byte) error
	// DeleteSession deletes the session only if it belongs to userID;
	// otherwise it returns ErrNotFound.
	DeleteSession(ctx context.Context, userID, id int64) error
	DeleteUserSessions(ctx context.Context, userID int64) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) error
	ListSessions(ctx context.Context, userID int64, now time.Time) ([]Session, error)

	GetIdentity(ctx context.Context, issuer, subject string) (IdentityLink, error)
	CreateIdentity(ctx context.Context, l IdentityLink) error // ErrExists on (issuer, subject)
	UserHasIdentity(ctx context.Context, userID int64) (bool, error)

	GetPasswordByUsername(ctx context.Context, username string) (PasswordRecord, error) // case-insensitive
	GetPasswordByUserID(ctx context.Context, userID int64) (PasswordRecord, error)
	CreatePassword(ctx context.Context, r PasswordRecord) error // ErrExists on user ID or username
	UpdatePasswordHash(ctx context.Context, userID int64, hash string) error
	RecordLoginFailure(ctx context.Context, userID int64, at time.Time) error
	ResetLoginFailures(ctx context.Context, userID int64) error

	// DeleteUser removes every session, identity and password of userID.
	DeleteUser(ctx context.Context, userID int64) error
}
