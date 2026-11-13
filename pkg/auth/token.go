package auth

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Personal access token scopes.
const (
	// ScopeMCP admits a token to an MCP endpoint (Middleware(WithScope(ScopeMCP))).
	ScopeMCP = "mcp"
	// ScopeAPI admits a token to the app's REST API (Middleware(WithScope(ScopeAPI))).
	// A session satisfies ScopeAPI.
	ScopeAPI = "api"
)

// DefaultTokenPrefix applies when neither Config.TokenPrefix nor
// WithTokenPrefix sets one.
const DefaultTokenPrefix = "meltkit"

const maxTokenNameBytes = 128

var tokenPrefixRE = regexp.MustCompile(`^[a-z][a-z0-9]{0,31}$`)

// ErrTokensUnsupported is returned by the token functions when the Store does
// not implement TokenStore.
var ErrTokensUnsupported = errors.New("auth: store does not implement TokenStore")

// ErrInvalidTokenRequest is returned by CreateToken for an empty or overlong
// name, an empty or unknown scope, or an expiry that is not in the future.
var ErrInvalidTokenRequest = errors.New("auth: invalid token request")

// Token is a personal access token. Only the SHA-256 of its secret is stored.
type Token struct {
	ID         int64     `json:"id"`
	TokenHash  []byte    `json:"-"`
	UserID     int64     `json:"user_id"`
	Name       string    `json:"name"`
	Scopes     []string  `json:"scopes"`
	CreatedAt  time.Time `json:"created_at"`
	ExpiresAt  time.Time `json:"expires_at"`   // zero: no expiry
	LastUsedAt time.Time `json:"last_used_at"` // zero: never used
}

// HasScope reports whether the token carries scope.
func (t Token) HasScope(scope string) bool {
	return slices.Contains(t.Scopes, scope)
}

// TokenStore persists personal access tokens. A Store that implements it
// enables the token functions and bearer authentication; its DeleteUser also
// deletes the user's tokens. PgxStore implements it.
type TokenStore interface {
	CreateToken(ctx context.Context, t *Token) error // sets t.ID
	// GetToken returns the token with this hash that has no expiry or whose
	// expiry lies after now, or ErrNotFound.
	GetToken(ctx context.Context, tokenHash []byte, now time.Time) (Token, error)
	TouchToken(ctx context.Context, id int64, lastUsed time.Time) error
	// ListTokens returns every token of userID, expired ones included.
	ListTokens(ctx context.Context, userID int64) ([]Token, error)
	// DeleteToken deletes the token only if it belongs to userID; otherwise
	// it returns ErrNotFound.
	DeleteToken(ctx context.Context, userID, id int64) error
}

// WithTokenPrefix sets the app prefix of personal access tokens, which then
// read "<prefix>_pat_<random>". It overrides Config.TokenPrefix. The prefix is
// 1 to 32 lower-case letters and digits, starting with a letter.
func WithTokenPrefix(prefix string) Option {
	return func(a *Auth) { a.tokenPrefix = prefix }
}

func (a *Auth) tokenStore() (TokenStore, error) {
	ts, ok := a.store.(TokenStore)
	if !ok {
		return nil, ErrTokensUnsupported
	}
	return ts, nil
}

func (a *Auth) tokenMarker() string { return a.tokenPrefix + "_pat_" }

// CreateToken creates a personal access token for userID and returns its
// secret, which is not stored and cannot be retrieved again. scopes holds
// ScopeMCP, ScopeAPI or both; a zero expiresAt means no expiry.
func (a *Auth) CreateToken(ctx context.Context, userID int64, name string, scopes []string, expiresAt time.Time) (string, Token, error) {
	ts, err := a.tokenStore()
	if err != nil {
		return "", Token{}, err
	}
	if userID <= 0 {
		return "", Token{}, fmt.Errorf("%w: user ID %d", ErrInvalidTokenRequest, userID)
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxTokenNameBytes || !utf8.ValidString(name) {
		return "", Token{}, fmt.Errorf("%w: name must have 1 to %d bytes of UTF-8", ErrInvalidTokenRequest, maxTokenNameBytes)
	}
	var sc []string
	for _, s := range scopes {
		if s != ScopeMCP && s != ScopeAPI {
			return "", Token{}, fmt.Errorf("%w: unknown scope %q", ErrInvalidTokenRequest, s)
		}
		if !slices.Contains(sc, s) {
			sc = append(sc, s)
		}
	}
	if len(sc) == 0 {
		return "", Token{}, fmt.Errorf("%w: at least one scope is required", ErrInvalidTokenRequest)
	}
	slices.Sort(sc)
	now := a.now()
	if !expiresAt.IsZero() && !expiresAt.After(now) {
		return "", Token{}, fmt.Errorf("%w: expiry lies in the past", ErrInvalidTokenRequest)
	}
	secret := a.tokenMarker() + randomToken()
	t := Token{
		TokenHash: hashToken(secret),
		UserID:    userID,
		Name:      name,
		Scopes:    sc,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}
	if err := ts.CreateToken(ctx, &t); err != nil {
		return "", Token{}, err
	}
	return secret, t, nil
}

// ListTokens returns the personal access tokens of userID, expired ones
// included.
func (a *Auth) ListTokens(ctx context.Context, userID int64) ([]Token, error) {
	ts, err := a.tokenStore()
	if err != nil {
		return nil, err
	}
	return ts.ListTokens(ctx, userID)
}

// RevokeToken deletes one token of userID. It returns ErrNotFound when the
// token does not exist or belongs to another user.
func (a *Auth) RevokeToken(ctx context.Context, userID, tokenID int64) error {
	ts, err := a.tokenStore()
	if err != nil {
		return err
	}
	return ts.DeleteToken(ctx, userID, tokenID)
}

// lookupToken returns the unexpired token whose secret is secret. A secret
// without this app's prefix is not looked up.
func (a *Auth) lookupToken(ctx context.Context, secret string) (Token, bool, error) {
	ts, err := a.tokenStore()
	if err != nil {
		return Token{}, false, nil
	}
	if !strings.HasPrefix(secret, a.tokenMarker()) || len(secret) > 256 {
		return Token{}, false, nil
	}
	t, err := ts.GetToken(ctx, hashToken(secret), a.now())
	if errors.Is(err, ErrNotFound) {
		return Token{}, false, nil
	}
	if err != nil {
		return Token{}, false, err
	}
	return t, true, nil
}

// touchToken updates last_used_at at most once per touchInterval.
func (a *Auth) touchToken(ctx context.Context, t Token) {
	now := a.now()
	if now.Sub(t.LastUsedAt) < touchInterval {
		return
	}
	ts, err := a.tokenStore()
	if err != nil {
		return
	}
	if err := ts.TouchToken(ctx, t.ID, now); err != nil {
		a.log.Warn("auth: updating token last use failed", "error", err)
	}
}
