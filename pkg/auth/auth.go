// Package auth authenticates browser users through sessions, local passwords
// and an OIDC provider. It returns a verified identity; user rows, roles and
// account policy stay in the app, which answers them through UserResolver.
//
// Wiring:
//
//	a, err := auth.New(cfg.Auth, auth.NewPgxStore(db.Pool), resolver)
//	router.Handle("/auth/*", a.Handler())
//	router.With(a.Middleware()).Mount("/api", api)
//
// The tables are created by RunMigrations.
package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

// Identity is a verified login.
type Identity struct {
	Method        string // MethodOIDC or MethodPassword
	Issuer        string // OIDC issuer, empty for password
	Subject       string // OIDC sub or local username
	Email         string
	EmailVerified bool
	Name          string
	// UserID is the app user this identity is already linked to: always set
	// for a password login, set for an OIDC login whose (issuer, subject) is
	// known or that link_by_email matched, 0 for a first OIDC login.
	UserID int64
}

// ErrNoAccount refuses a login. UserResolver.Resolve returns it when the
// account policy denies an account or the user is disabled.
var ErrNoAccount = errors.New("auth: no account")

// UserResolver maps identities to app users.
type UserResolver interface {
	// Resolve is called for every successful authentication. It returns the
	// app user to log in, creating one if the account policy allows it, or
	// ErrNoAccount. When id.UserID is non-zero, the returned ID must equal it.
	Resolve(ctx context.Context, id Identity) (userID int64, err error)
}

// LoginLookup is implemented by a UserResolver when OIDC link_by_email is on.
type LoginLookup interface {
	// UserIDByLogin returns the app user whose login equals login, or
	// ErrNoAccount.
	UserIDByLogin(ctx context.Context, login string) (int64, error)
}

// Auth serves the /auth endpoints and the session middleware.
type Auth struct {
	cfg       Config
	base      baseURL
	proxies   []netip.Prefix
	store     Store
	users     UserResolver
	log       *slog.Logger
	loginPath string
	now       func() time.Time

	limiter *limiter
	hashSem chan struct{}
	oidc    *oidcClient
}

// Option configures New.
type Option func(*Auth)

// WithLogger sets the logger.
func WithLogger(log *slog.Logger) Option {
	return func(a *Auth) { a.log = log }
}

// WithHTTPClient sets the client for requests to the OIDC provider.
func WithHTTPClient(c *http.Client) Option {
	return func(a *Auth) {
		if a.oidc != nil {
			a.oidc.httpClient = c
		}
	}
}

// WithLoginPath sets the app's login page, to which a failed OIDC callback
// redirects with an `error` query parameter. Default "/login".
func WithLoginPath(path string) Option {
	return func(a *Auth) { a.loginPath = path }
}

// WithLoginRateLimit sets how many failed password logins per username and
// per client IP are allowed within window. Defaults: 10, 50, 15 minutes.
func WithLoginRateLimit(perUser, perIP int, window time.Duration) Option {
	return func(a *Auth) { a.limiter = newLimiter(perUser, perIP, window) }
}

// New validates cfg and returns an Auth. It makes no network request; the
// OIDC provider is discovered on first use.
func New(cfg Config, store Store, users UserResolver, opts ...Option) (*Auth, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if store == nil || users == nil {
		return nil, fmt.Errorf("auth: store and user resolver are required")
	}
	if cfg.HasMethod(MethodOIDC) && cfg.OIDC.LinkByEmail {
		if _, ok := users.(LoginLookup); !ok {
			return nil, fmt.Errorf("auth.oidc.link_by_email requires a UserResolver that implements LoginLookup")
		}
	}
	base, _ := parseBaseURL(cfg.BaseURL)
	proxies, _ := parsePrefixes(cfg.TrustedProxies)
	a := &Auth{
		cfg:       cfg,
		base:      base,
		proxies:   proxies,
		store:     store,
		users:     users,
		log:       slog.Default(),
		loginPath: "/login",
		now:       time.Now,
		limiter:   newLimiter(10, 50, 15*time.Minute),
		hashSem:   make(chan struct{}, hashConcurrency),
	}
	if cfg.HasMethod(MethodOIDC) {
		a.oidc = newOIDCClient(cfg, base, http.DefaultClient)
	}
	for _, opt := range opts {
		opt(a)
	}
	return a, nil
}

// Handler serves GET /auth/methods, POST /auth/login, GET /auth/oidc/start,
// GET /auth/oidc/callback, POST /auth/logout and GET /auth/me. Mount it at
// /auth/* without stripping the prefix.
func (a *Auth) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/methods", a.handleMethods)
	mux.HandleFunc("POST /auth/logout", a.handleLogout)
	mux.HandleFunc("GET /auth/me", a.handleMe)
	if a.cfg.HasMethod(MethodPassword) {
		mux.HandleFunc("POST /auth/login", a.handleLogin)
	}
	if a.cfg.HasMethod(MethodOIDC) {
		mux.HandleFunc("GET /auth/oidc/start", a.handleOIDCStart)
		mux.HandleFunc("GET /auth/oidc/callback", a.handleOIDCCallback)
	}
	return mux
}

type methodInfo struct {
	Type        string `json:"type"`
	DisplayName string `json:"display_name,omitempty"`
	StartURL    string `json:"start_url,omitempty"`
}

func (a *Auth) handleMethods(w http.ResponseWriter, _ *http.Request) {
	var out []methodInfo
	for _, m := range a.cfg.Methods {
		switch m {
		case MethodOIDC:
			name := a.cfg.OIDC.DisplayName
			if name == "" {
				name = "Single sign-on"
			}
			out = append(out, methodInfo{Type: m, DisplayName: name, StartURL: "/auth/oidc/start"})
		case MethodPassword:
			out = append(out, methodInfo{Type: m})
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"methods": out})
}

// IsInitialAdmin reports whether id matches Config.InitialAdmin: the email of
// an OIDC login from the configured issuer, or a local username. The app
// grants admin only while no admin exists.
func (a *Auth) IsInitialAdmin(id Identity) bool {
	want := strings.TrimSpace(a.cfg.InitialAdmin)
	if want == "" {
		return false
	}
	switch id.Method {
	case MethodOIDC:
		return id.Issuer == a.cfg.OIDC.Issuer && id.Email != "" && strings.EqualFold(id.Email, want)
	case MethodPassword:
		return strings.EqualFold(id.Subject, want)
	}
	return false
}

// ListSessions returns the unexpired sessions of userID.
func (a *Auth) ListSessions(ctx context.Context, userID int64) ([]Session, error) {
	return a.store.ListSessions(ctx, userID, a.now())
}

// RevokeSession deletes one session of userID. It returns ErrNotFound when
// the session does not exist or belongs to another user.
func (a *Auth) RevokeSession(ctx context.Context, userID, sessionID int64) error {
	return a.store.DeleteSession(ctx, userID, sessionID)
}

// RevokeUserSessions deletes every session of userID.
func (a *Auth) RevokeUserSessions(ctx context.Context, userID int64) error {
	return a.store.DeleteUserSessions(ctx, userID)
}

// DeleteUser removes every session, identity and password of userID. The app
// calls it when it deletes the user, because the auth tables carry no foreign
// key into app tables.
func (a *Auth) DeleteUser(ctx context.Context, userID int64) error {
	return a.store.DeleteUser(ctx, userID)
}

// resolve calls the UserResolver and enforces its contract.
func (a *Auth) resolve(ctx context.Context, id Identity) (int64, error) {
	uid, err := a.users.Resolve(ctx, id)
	if err != nil {
		return 0, err
	}
	if uid <= 0 {
		return 0, fmt.Errorf("auth: resolver returned user ID %d", uid)
	}
	if id.UserID != 0 && uid != id.UserID {
		return 0, fmt.Errorf("auth: resolver returned user %d for identity linked to user %d", uid, id.UserID)
	}
	return uid, nil
}
