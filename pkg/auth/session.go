package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/meltforce/meltkit/pkg/middleware"
)

const touchInterval = time.Minute

type ctxKey int

const (
	sessionKey ctxKey = iota
	tokenKey
)

// SessionFromContext returns the session that Middleware authenticated.
func SessionFromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionKey).(Session)
	return s, ok
}

// cookieName prefixes name with __Host-. The prefix requires Secure, so an
// http base URL on a loopback host uses the plain name.
func (a *Auth) cookieName(name string) string {
	if a.base.secure {
		return "__Host-" + name
	}
	return name
}

func (a *Auth) sessionCookieName() string { return a.cookieName("session") }

func (a *Auth) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		Secure:   a.base.secure,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

func randomToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	return base64.RawURLEncoding.EncodeToString(b)
}

// sameOrigin reports whether the request's Origin header equals base_url.
func (a *Auth) sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		return false
	}
	u, err := url.Parse(o)
	if err != nil || u.Path != "" {
		return false
	}
	n, ok := normalizeOrigin(u)
	return ok && n == a.base.origin
}

func isSafeMethod(m string) bool {
	return m == http.MethodGet || m == http.MethodHead || m == http.MethodOptions
}

// currentSession returns the session named by the request's cookie.
func (a *Auth) currentSession(r *http.Request) (Session, bool, error) {
	c, err := r.Cookie(a.sessionCookieName())
	if err != nil || c.Value == "" {
		return Session{}, false, nil
	}
	s, err := a.store.GetSession(r.Context(), hashToken(c.Value), a.now())
	if errors.Is(err, ErrNotFound) {
		return Session{}, false, nil
	}
	if err != nil {
		return Session{}, false, err
	}
	return s, true, nil
}

// MiddlewareOption configures Middleware.
type MiddlewareOption func(*mwOptions)

type mwOptions struct {
	fallback func(http.Handler) http.Handler
	scopes   []string
}

// WithFallback passes a request that carries neither a bearer token nor a
// valid session to fallback instead of answering 401. vimmary uses it to keep
// Tailscale WhoIs as a second path during migration.
func WithFallback(fallback func(http.Handler) http.Handler) MiddlewareOption {
	return func(o *mwOptions) { o.fallback = fallback }
}

// WithScope requires scope (ScopeMCP or ScopeAPI) of every request. A personal
// access token without it answers 403. A session satisfies ScopeAPI only, so
// under WithScope(ScopeMCP) the session cookie is ignored and the request
// needs a token. Several WithScope options require all their scopes.
func WithScope(scope string) MiddlewareOption {
	return func(o *mwOptions) { o.scopes = append(o.scopes, scope) }
}

// sessionScopes are the scopes a session cookie satisfies.
var sessionScopes = []string{ScopeAPI}

func (o *mwOptions) sessionAllowed() bool {
	for _, s := range o.scopes {
		if !slices.Contains(sessionScopes, s) {
			return false
		}
	}
	return true
}

// TokenFromContext returns the personal access token that Middleware
// authenticated.
func TokenFromContext(ctx context.Context) (Token, bool) {
	t, ok := ctx.Value(tokenKey).(Token)
	return t, ok
}

// bearerToken returns the credentials of an "Authorization: Bearer" header.
func bearerToken(r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	scheme, cred, _ := strings.Cut(h, " ")
	if !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	return strings.TrimSpace(cred), true
}

func writeBearerError(w http.ResponseWriter, status int, code, scope, msg string) {
	v := `Bearer error="` + code + `"`
	if scope != "" {
		v += `, scope="` + scope + `"`
	}
	w.Header().Set("WWW-Authenticate", v)
	writeError(w, status, msg)
}

// Middleware authenticates a request by a personal access token in
// "Authorization: Bearer" or by its session cookie, and stores the user in the
// context, where middleware.UserIDFromContext, middleware.UserInfoFromContext,
// SessionFromContext and TokenFromContext read it.
//
// A bearer request ignores the cookie and needs no Origin. An invalid,
// expired or revoked token answers 401 with WWW-Authenticate: Bearer and never
// reaches the fallback; a token without a scope that WithScope requires
// answers 403. A state-changing request that carries a session cookie must
// send an Origin equal to base_url; otherwise it answers 403. A request
// without credentials answers 401, or goes to the fallback.
func (a *Auth) Middleware(opts ...MiddlewareOption) func(http.Handler) http.Handler {
	var o mwOptions
	for _, opt := range opts {
		opt(&o)
	}
	useSession := o.sessionAllowed()
	return func(next http.Handler) http.Handler {
		var unauth http.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("WWW-Authenticate", "Bearer")
			writeError(w, http.StatusUnauthorized, "unauthenticated")
		})
		if o.fallback != nil {
			unauth = o.fallback(next)
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret, ok := bearerToken(r); ok {
				a.serveBearer(w, r, next, secret, o.scopes)
				return
			}
			if !useSession {
				unauth.ServeHTTP(w, r)
				return
			}
			if _, err := r.Cookie(a.sessionCookieName()); err == nil && !isSafeMethod(r.Method) && !a.sameOrigin(r) {
				writeError(w, http.StatusForbidden, "origin mismatch")
				return
			}
			s, ok, err := a.currentSession(r)
			if err != nil {
				a.log.Error("auth: session lookup failed", "error", err)
				writeError(w, http.StatusInternalServerError, "session lookup failed")
				return
			}
			if !ok {
				unauth.ServeHTTP(w, r)
				return
			}
			a.touch(r.Context(), s)
			ctx := middleware.WithUser(r.Context(), int(s.UserID), middleware.UserInfo{
				Login:       s.Login,
				DisplayName: s.DisplayName,
			})
			ctx = context.WithValue(ctx, sessionKey, s)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func (a *Auth) serveBearer(w http.ResponseWriter, r *http.Request, next http.Handler, secret string, scopes []string) {
	t, ok, err := a.lookupToken(r.Context(), secret)
	if err != nil {
		a.log.Error("auth: token lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, "token lookup failed")
		return
	}
	if !ok {
		writeBearerError(w, http.StatusUnauthorized, "invalid_token", "", "invalid token")
		return
	}
	for _, sc := range scopes {
		if !t.HasScope(sc) {
			writeBearerError(w, http.StatusForbidden, "insufficient_scope", strings.Join(scopes, " "), "insufficient scope")
			return
		}
	}
	a.touchToken(r.Context(), t)
	ctx := middleware.WithUser(r.Context(), int(t.UserID), middleware.UserInfo{})
	ctx = context.WithValue(ctx, tokenKey, t)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// touch updates last_used_at at most once per touchInterval.
func (a *Auth) touch(ctx context.Context, s Session) {
	now := a.now()
	if now.Sub(s.LastUsedAt) < touchInterval {
		return
	}
	if err := a.store.TouchSession(ctx, s.ID, now); err != nil {
		a.log.Warn("auth: updating session last use failed", "error", err)
	}
}

// startSession creates a session for userID, sets its cookie and deletes the
// session the request arrived with, if any.
func (a *Auth) startSession(w http.ResponseWriter, r *http.Request, userID int64, id Identity) (Session, error) {
	ctx := r.Context()
	if c, err := r.Cookie(a.sessionCookieName()); err == nil && c.Value != "" {
		if err := a.store.DeleteSessionByHash(ctx, hashToken(c.Value)); err != nil {
			a.log.Warn("auth: deleting previous session failed", "error", err)
		}
	}
	if err := a.store.DeleteExpiredSessions(ctx, a.now()); err != nil {
		a.log.Warn("auth: deleting expired sessions failed", "error", err)
	}

	login := id.Subject
	if id.Method == MethodOIDC && id.Email != "" {
		login = id.Email
	}
	name := id.Name
	if name == "" {
		name = login
	}
	token := randomToken()
	now := a.now()
	ttl := a.cfg.sessionTTL()
	s := Session{
		TokenHash:   hashToken(token),
		UserID:      userID,
		Method:      id.Method,
		Login:       login,
		DisplayName: name,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		LastUsedAt:  now,
		ClientIP:    a.clientIP(r).String(),
		UserAgent:   truncate(r.UserAgent(), 512),
	}
	if err := a.store.CreateSession(ctx, &s); err != nil {
		return Session{}, err
	}
	a.setCookie(w, a.sessionCookieName(), token, int(ttl/time.Second))
	return s, nil
}

func (a *Auth) handleLogout(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin mismatch")
		return
	}
	if c, err := r.Cookie(a.sessionCookieName()); err == nil && c.Value != "" {
		if err := a.store.DeleteSessionByHash(r.Context(), hashToken(c.Value)); err != nil {
			a.log.Error("auth: deleting session failed", "error", err)
			writeError(w, http.StatusInternalServerError, "logout failed")
			return
		}
	}
	a.setCookie(w, a.sessionCookieName(), "", -1)
	w.WriteHeader(http.StatusNoContent)
}

type meResponse struct {
	UserID           int64     `json:"user_id"`
	Method           string    `json:"method"`
	Login            string    `json:"login"`
	DisplayName      string    `json:"display_name"`
	SessionID        int64     `json:"session_id"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
}

func (a *Auth) handleMe(w http.ResponseWriter, r *http.Request) {
	s, ok, err := a.currentSession(r)
	if err != nil {
		a.log.Error("auth: session lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, "session lookup failed")
		return
	}
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthenticated")
		return
	}
	a.touch(r.Context(), s)
	writeJSON(w, http.StatusOK, meResponse{
		UserID:           s.UserID,
		Method:           s.Method,
		Login:            s.Login,
		DisplayName:      s.DisplayName,
		SessionID:        s.ID,
		SessionExpiresAt: s.ExpiresAt,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// truncate cuts s to at most n bytes of valid UTF-8.
func truncate(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	return strings.ToValidUTF8(s, "")
}
