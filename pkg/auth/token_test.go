package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/meltforce/meltkit/pkg/middleware"
)

func withBearer(tok string) reqOpt {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

// tokenProtected answers with the user and the token the middleware stored.
func tokenProtected(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := middleware.UserIDFromContext(r)
		if !ok {
			t.Error("no user in context")
		}
		tok, hasToken := TokenFromContext(r.Context())
		_, hasSession := SessionFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{"uid": uid, "token": hasToken, "token_id": tok.ID, "session": hasSession})
	})
}

func mustCreateToken(t *testing.T, a *Auth, userID int64, scopes ...string) (string, Token) {
	t.Helper()
	secret, tok, err := a.CreateToken(context.Background(), userID, "juno", scopes, time.Time{})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	return secret, tok
}

func TestCreateToken(t *testing.T) {
	a, store, _ := newTestAuth(t, passwordConfig(), WithTokenPrefix("vimmary"))
	ctx := context.Background()
	exp := time.Now().Add(time.Hour)
	secret, tok, err := a.CreateToken(ctx, 7, "  tsmcp ", []string{ScopeMCP, ScopeAPI, ScopeMCP}, exp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secret, "vimmary_pat_") || len(secret) != len("vimmary_pat_")+43 {
		t.Errorf("secret = %q", secret)
	}
	if tok.ID == 0 || tok.UserID != 7 || tok.Name != "tsmcp" || !tok.ExpiresAt.Equal(exp) || !tok.LastUsedAt.IsZero() {
		t.Errorf("token = %+v", tok)
	}
	if strings.Join(tok.Scopes, ",") != "api,mcp" {
		t.Errorf("scopes = %v", tok.Scopes)
	}
	stored := store.tokens[tok.ID]
	if string(stored.TokenHash) != string(hashToken(secret)) || strings.Contains(string(stored.TokenHash), secret) {
		t.Error("stored hash does not equal SHA-256 of the secret")
	}
	if raw, _ := json.Marshal(tok); strings.Contains(string(raw), "hash") {
		t.Errorf("token JSON exposes the hash: %s", raw)
	}

	bad := []struct {
		name   string
		uid    int64
		tname  string
		scopes []string
		exp    time.Time
	}{
		{"no scope", 7, "x", nil, time.Time{}},
		{"unknown scope", 7, "x", []string{"admin"}, time.Time{}},
		{"empty name", 7, " ", []string{ScopeAPI}, time.Time{}},
		{"long name", 7, strings.Repeat("n", 129), []string{ScopeAPI}, time.Time{}},
		{"past expiry", 7, "x", []string{ScopeAPI}, time.Now().Add(-time.Second)},
		{"no user", 0, "x", []string{ScopeAPI}, time.Time{}},
	}
	for _, b := range bad {
		if _, _, err := a.CreateToken(ctx, b.uid, b.tname, b.scopes, b.exp); !errors.Is(err, ErrInvalidTokenRequest) {
			t.Errorf("%s: err = %v", b.name, err)
		}
	}

	list, err := a.ListTokens(ctx, 7)
	if err != nil || len(list) != 1 || list[0].ID != tok.ID {
		t.Errorf("ListTokens = %+v, %v", list, err)
	}
	if list, _ := a.ListTokens(ctx, 8); len(list) != 0 {
		t.Errorf("ListTokens of another user = %+v", list)
	}
}

func TestTokenPrefix(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig())
	if s, _ := mustCreateToken(t, a, 7, ScopeAPI); !strings.HasPrefix(s, DefaultTokenPrefix+"_pat_") {
		t.Errorf("default prefix: %q", s)
	}
	cfg := passwordConfig()
	cfg.TokenPrefix = "labtrak"
	a, _, _ = newTestAuth(t, cfg)
	if s, _ := mustCreateToken(t, a, 7, ScopeAPI); !strings.HasPrefix(s, "labtrak_pat_") {
		t.Errorf("config prefix: %q", s)
	}
	a, _, _ = newTestAuth(t, cfg, WithTokenPrefix("vimmary"))
	if s, _ := mustCreateToken(t, a, 7, ScopeAPI); !strings.HasPrefix(s, "vimmary_pat_") {
		t.Errorf("option must override config: %q", s)
	}
	for _, p := range []string{"Vimmary", "vim_mary", "1abc", strings.Repeat("a", 33)} {
		cfg := passwordConfig()
		cfg.TokenPrefix = p
		if err := cfg.Validate(); err == nil {
			t.Errorf("config prefix %q accepted", p)
		}
		if _, err := New(passwordConfig(), newMemStore(), &fakeResolver{}, WithTokenPrefix(p)); err == nil {
			t.Errorf("option prefix %q accepted", p)
		}
	}
}

func TestBearerAuth(t *testing.T) {
	a, store, _ := newTestAuth(t, passwordConfig(), WithTokenPrefix("vimmary"))
	secret, tok := mustCreateToken(t, a, 7, ScopeMCP)
	h := a.Middleware(WithScope(ScopeMCP))(tokenProtected(t))

	rec := do(h, "POST", "/mcp", "{}", withBearer(secret))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"uid":7`) || !strings.Contains(rec.Body.String(), `"token":true`) {
		t.Fatalf("POST bearer without Origin: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "POST", "/mcp", "{}", withBearer(secret), withOrigin("https://evil.example")); rec.Code != http.StatusOK {
		t.Errorf("bearer with foreign Origin: %d", rec.Code)
	}
	if rec := do(h, "GET", "/mcp", "", func(r *http.Request) { r.Header.Set("Authorization", "bearer "+secret) }); rec.Code != http.StatusOK {
		t.Errorf("lower-case scheme: %d", rec.Code)
	}

	used := store.tokens[tok.ID].LastUsedAt
	if used.IsZero() {
		t.Fatal("last_used_at not set")
	}
	do(h, "GET", "/mcp", "", withBearer(secret))
	if !store.tokens[tok.ID].LastUsedAt.Equal(used) {
		t.Error("last_used_at updated within touchInterval")
	}
	later := time.Now().Add(2 * touchInterval)
	a.now = func() time.Time { return later }
	do(h, "GET", "/mcp", "", withBearer(secret))
	if !store.tokens[tok.ID].LastUsedAt.Equal(later) {
		t.Error("last_used_at not updated after touchInterval")
	}
}

func TestBearerScope(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig())
	apiTok, _ := mustCreateToken(t, a, 7, ScopeAPI)
	both, _ := mustCreateToken(t, a, 7, ScopeAPI, ScopeMCP)

	mcp := a.Middleware(WithScope(ScopeMCP))(tokenProtected(t))
	rec := do(mcp, "GET", "/mcp", "", withBearer(apiTok))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("api token on mcp: %d", rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer error="insufficient_scope", scope="mcp"` {
		t.Errorf("WWW-Authenticate = %q", got)
	}
	if rec := do(mcp, "GET", "/mcp", "", withBearer(both)); rec.Code != http.StatusOK {
		t.Errorf("api+mcp token on mcp: %d", rec.Code)
	}
	api := a.Middleware(WithScope(ScopeAPI))(tokenProtected(t))
	if rec := do(api, "GET", "/api/x", "", withBearer(apiTok)); rec.Code != http.StatusOK {
		t.Errorf("api token on api: %d", rec.Code)
	}
	if rec := do(a.Middleware()(tokenProtected(t)), "GET", "/api/x", "", withBearer(apiTok)); rec.Code != http.StatusOK {
		t.Errorf("token without required scope: %d", rec.Code)
	}
}

func TestBearerInvalidSkipsFallback(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig(), WithTokenPrefix("vimmary"))
	secret, _ := mustCreateToken(t, a, 7, ScopeMCP)
	called := 0
	fallback := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called++
			next.ServeHTTP(w, r.WithContext(middleware.WithUser(r.Context(), 1, middleware.UserInfo{})))
		})
	}
	h := a.Middleware(WithScope(ScopeMCP), WithFallback(fallback))(tokenProtected(t))
	for name, tok := range map[string]string{
		"forged":       "vimmary_pat_" + randomToken(),
		"other prefix": strings.Replace(secret, "vimmary_", "labtrak_", 1),
		"empty":        "",
		"truncated":    secret[:len(secret)-1],
	} {
		rec := do(h, "POST", "/mcp", "{}", withBearer(tok))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != `Bearer error="invalid_token"` {
			t.Errorf("%s: WWW-Authenticate = %q", name, got)
		}
	}
	if called != 0 {
		t.Errorf("fallback called %d times for a bearer request", called)
	}
	if rec := do(h, "POST", "/mcp", "{}"); rec.Code != http.StatusOK || called != 1 {
		t.Errorf("no credentials must reach the fallback: %d called=%d", rec.Code, called)
	}
	if rec := do(h, "GET", "/mcp", "", func(r *http.Request) { r.Header.Set("Authorization", "Basic Zm9vOmJhcg==") }); rec.Code != http.StatusOK || called != 2 {
		t.Errorf("non-bearer Authorization must reach the fallback: %d called=%d", rec.Code, called)
	}
}

func TestBearerExpiredAndRevoked(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig())
	ctx := context.Background()
	h := a.Middleware()(tokenProtected(t))

	secret, _, err := a.CreateToken(ctx, 7, "short", []string{ScopeAPI}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if rec := do(h, "GET", "/api/x", "", withBearer(secret)); rec.Code != http.StatusOK {
		t.Fatalf("before expiry: %d", rec.Code)
	}
	a.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if rec := do(h, "GET", "/api/x", "", withBearer(secret)); rec.Code != http.StatusUnauthorized {
		t.Errorf("after expiry: %d", rec.Code)
	}
	a.now = time.Now

	secret, tok := mustCreateToken(t, a, 7, ScopeAPI)
	if err := a.RevokeToken(ctx, 8, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke another user's token: %v", err)
	}
	if rec := do(h, "GET", "/api/x", "", withBearer(secret)); rec.Code != http.StatusOK {
		t.Fatalf("before revoke: %d", rec.Code)
	}
	if err := a.RevokeToken(ctx, 7, tok.ID); err != nil {
		t.Fatal(err)
	}
	if rec := do(h, "GET", "/api/x", "", withBearer(secret)); rec.Code != http.StatusUnauthorized {
		t.Errorf("after revoke: %d", rec.Code)
	}
	if err := a.RevokeToken(ctx, 7, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke twice: %v", err)
	}
}

func TestSessionScopes(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig())
	c := passwordLogin(t, a)

	api := a.Middleware(WithScope(ScopeAPI))(tokenProtected(t))
	if rec := do(api, "GET", "/api/x", "", withCookie(c)); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"session":true`) {
		t.Errorf("session on api: %d %s", rec.Code, rec.Body)
	}
	if rec := do(api, "POST", "/api/x", "{}", withCookie(c)); rec.Code != http.StatusForbidden {
		t.Errorf("cookie POST without Origin: %d", rec.Code)
	}

	mcp := a.Middleware(WithScope(ScopeMCP))(tokenProtected(t))
	rec := do(mcp, "GET", "/mcp", "", withCookie(c))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") != "Bearer" {
		t.Errorf("session on mcp: %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}

	// A bearer token decides the identity even when a cookie is present.
	secret, tok := mustCreateToken(t, a, 9, ScopeAPI)
	rec = do(api, "POST", "/api/x", "{}", withCookie(c), withBearer(secret))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"uid":9`) || !strings.Contains(rec.Body.String(), `"session":false`) {
		t.Errorf("bearer with cookie: %d %s (token %d)", rec.Code, rec.Body, tok.ID)
	}
}

func TestDeleteUserRemovesTokens(t *testing.T) {
	a, store, _ := newTestAuth(t, passwordConfig())
	secret, _ := mustCreateToken(t, a, 7, ScopeAPI)
	mustCreateToken(t, a, 8, ScopeAPI)
	if err := a.DeleteUser(context.Background(), 7); err != nil {
		t.Fatal(err)
	}
	if len(store.tokens) != 1 {
		t.Errorf("tokens left = %d, want 1 (user 8)", len(store.tokens))
	}
	if rec := do(a.Middleware()(tokenProtected(t)), "GET", "/api/x", "", withBearer(secret)); rec.Code != http.StatusUnauthorized {
		t.Errorf("token after DeleteUser: %d", rec.Code)
	}
}

// sessionOnlyStore hides the TokenStore methods of memStore.
type sessionOnlyStore struct{ Store }

func TestTokensUnsupported(t *testing.T) {
	a, err := New(passwordConfig(), sessionOnlyStore{newMemStore()}, &fakeResolver{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, _, err := a.CreateToken(ctx, 7, "x", []string{ScopeAPI}, time.Time{}); !errors.Is(err, ErrTokensUnsupported) {
		t.Errorf("CreateToken: %v", err)
	}
	if _, err := a.ListTokens(ctx, 7); !errors.Is(err, ErrTokensUnsupported) {
		t.Errorf("ListTokens: %v", err)
	}
	if err := a.RevokeToken(ctx, 7, 1); !errors.Is(err, ErrTokensUnsupported) {
		t.Errorf("RevokeToken: %v", err)
	}
	if rec := do(a.Middleware()(tokenProtected(t)), "GET", "/api/x", "", withBearer("meltkit_pat_x")); rec.Code != http.StatusUnauthorized {
		t.Errorf("bearer without TokenStore: %d", rec.Code)
	}
}
