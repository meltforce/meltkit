package auth

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/meltforce/meltkit/pkg/middleware"
	"gopkg.in/yaml.v3"
)

const testBase = "https://app.example.com"

type fakeResolver struct {
	mu     sync.Mutex
	calls  []Identity
	logins map[string]int64
	nextID int64
	refuse bool
}

func (f *fakeResolver) Resolve(_ context.Context, id Identity) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, id)
	if f.refuse {
		return 0, ErrNoAccount
	}
	if id.UserID != 0 {
		return id.UserID, nil
	}
	f.nextID++
	return 100 + f.nextID, nil
}

func (f *fakeResolver) UserIDByLogin(_ context.Context, login string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.logins[strings.ToLower(login)]; ok {
		return id, nil
	}
	return 0, ErrNoAccount
}

func (f *fakeResolver) last() Identity {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[len(f.calls)-1]
}

func passwordConfig() Config {
	return Config{
		BaseURL:        testBase,
		Methods:        []string{MethodPassword},
		TrustedProxies: []string{"10.0.0.0/8"},
	}
}

func newTestAuth(t *testing.T, cfg Config, opts ...Option) (*Auth, *memStore, *fakeResolver) {
	t.Helper()
	store := newMemStore()
	res := &fakeResolver{logins: map[string]int64{}}
	opts = append([]Option{WithLoginRateLimit(3, 5, time.Minute), WithLogger(slog.New(slog.DiscardHandler))}, opts...)
	a, err := New(cfg, store, res, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a, store, res
}

type reqOpt func(*http.Request)

func withOrigin(o string) reqOpt { return func(r *http.Request) { r.Header.Set("Origin", o) } }
func withCookie(c *http.Cookie) reqOpt {
	return func(r *http.Request) { r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) }
}
func withRemote(addr string) reqOpt { return func(r *http.Request) { r.RemoteAddr = addr } }
func withXFF(v string) reqOpt       { return func(r *http.Request) { r.Header.Set("X-Forwarded-For", v) } }

func do(h http.Handler, method, path, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func cookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func loginBody(user, pw string) string {
	b, _ := json.Marshal(loginRequest{Username: user, Password: pw})
	return string(b)
}

const goodPassword = "correct horse battery"

// passwordLogin creates user 7 "alice" and logs in, returning the session cookie.
func passwordLogin(t *testing.T, a *Auth) *http.Cookie {
	t.Helper()
	if err := a.CreatePasswordUser(context.Background(), 7, "alice", goodPassword); err != nil {
		t.Fatalf("CreatePasswordUser: %v", err)
	}
	rec := do(a.Handler(), "POST", "/auth/login", loginBody("Alice", goodPassword), withOrigin(testBase))
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body %s", rec.Code, rec.Body)
	}
	c := cookie(rec, "__Host-session")
	if c == nil {
		t.Fatal("no session cookie")
	}
	if !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "" {
		t.Errorf("cookie attributes = %+v", c)
	}
	return c
}

func TestConfigValidate(t *testing.T) {
	ok := passwordConfig()
	tests := []struct {
		name string
		mod  func(*Config)
	}{
		{"missing base", func(c *Config) { c.BaseURL = "" }},
		{"http non-loopback", func(c *Config) { c.BaseURL = "http://app.example.com" }},
		{"path", func(c *Config) { c.BaseURL = "https://app.example.com/x" }},
		{"no methods", func(c *Config) { c.Methods = nil }},
		{"unknown method", func(c *Config) { c.Methods = []string{"magic"} }},
		{"bad proxy", func(c *Config) { c.TrustedProxies = []string{"nope"} }},
		{"oidc without issuer", func(c *Config) { c.Methods = []string{MethodOIDC}; c.OIDC.ClientID = "x" }},
	}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid config: %v", err)
	}
	for _, tt := range tests {
		c := passwordConfig()
		tt.mod(&c)
		if c.Validate() == nil {
			t.Errorf("%s: expected error", tt.name)
		}
	}
	c := passwordConfig()
	c.BaseURL = "http://localhost:8080"
	if err := c.Validate(); err != nil {
		t.Errorf("loopback http: %v", err)
	}
}

func TestConfigYAML(t *testing.T) {
	src := `
base_url: https://vimmary.example.com
methods: [oidc, password]
session_ttl: 720h
trusted_proxies: [172.16.0.0/12]
initial_admin: alice@example.com
oidc:
  issuer: https://idp.example.com
  client_id: vimmary
  display_name: Tailscale
  link_by_email: true
`
	var c Config
	if err := yaml.Unmarshal([]byte(src), &c); err != nil {
		t.Fatal(err)
	}
	if c.SessionTTL != 720*time.Hour || !c.OIDC.LinkByEmail || len(c.Methods) != 2 || c.OIDC.ClientID != "vimmary" {
		t.Errorf("config = %+v", c)
	}
	if err := c.Validate(); err != nil {
		t.Error(err)
	}
	if got := c.oidcScopes(); strings.Join(got, " ") != "openid email profile" {
		t.Errorf("default scopes = %v", got)
	}
}

func TestLinkByEmailRequiresLoginLookup(t *testing.T) {
	cfg := oidcConfig("https://idp.example.com")
	cfg.OIDC.LinkByEmail = true
	type plain struct{ UserResolver }
	if _, err := New(cfg, newMemStore(), plain{&fakeResolver{}}); err == nil {
		t.Fatal("expected error for resolver without LoginLookup")
	}
}

func TestPasswordHashRoundTrip(t *testing.T) {
	h := hashPasswordUnbounded(goodPassword)
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("hash = %s", h)
	}
	if ok, err := verifyPHC(h, goodPassword); err != nil || !ok {
		t.Fatalf("verify good: %v %v", ok, err)
	}
	if ok, _ := verifyPHC(h, goodPassword+"x"); ok {
		t.Fatal("verify bad password succeeded")
	}
	if _, err := verifyPHC("$argon2i$v=19$m=1,t=1,p=1$AA$AA", "x"); err == nil {
		t.Fatal("accepted argon2i")
	}
}

func TestPasswordLoginAndMe(t *testing.T) {
	a, store, res := newTestAuth(t, passwordConfig())
	c := passwordLogin(t, a)

	id := res.last()
	if id.Method != MethodPassword || id.Subject != "alice" || id.UserID != 7 {
		t.Errorf("identity = %+v", id)
	}
	rec := do(a.Handler(), "GET", "/auth/me", "", withCookie(c))
	if rec.Code != http.StatusOK {
		t.Fatalf("me status = %d", rec.Code)
	}
	var me meResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &me)
	if me.UserID != 7 || me.Method != MethodPassword || me.Login != "alice" {
		t.Errorf("me = %+v", me)
	}
	if n := len(store.sessions); n != 1 {
		t.Errorf("sessions = %d", n)
	}
	for _, s := range store.sessions {
		if string(s.TokenHash) == c.Value {
			t.Error("token stored in clear")
		}
	}
}

func TestPasswordLoginFailures(t *testing.T) {
	a, store, _ := newTestAuth(t, passwordConfig())
	if err := a.CreatePasswordUser(context.Background(), 7, "alice", goodPassword); err != nil {
		t.Fatal(err)
	}
	h := a.Handler()

	if rec := do(h, "POST", "/auth/login", loginBody("alice", "wrong password!"), withOrigin(testBase)); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: %d", rec.Code)
	}
	if store.passwords[7].FailedAttempts != 1 {
		t.Errorf("failed attempts = %d", store.passwords[7].FailedAttempts)
	}
	if rec := do(h, "POST", "/auth/login", loginBody("bob", goodPassword), withOrigin(testBase)); rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown user: %d", rec.Code)
	}
	if rec := do(h, "POST", "/auth/login", loginBody("alice", goodPassword), withOrigin("https://evil.example")); rec.Code != http.StatusForbidden {
		t.Errorf("foreign origin: %d", rec.Code)
	}
	if rec := do(h, "POST", "/auth/login", loginBody("alice", goodPassword)); rec.Code != http.StatusForbidden {
		t.Errorf("missing origin: %d", rec.Code)
	}
	if rec := do(h, "POST", "/auth/login", loginBody("alice", goodPassword), withOrigin(testBase)); rec.Code != http.StatusOK {
		t.Errorf("good login: %d", rec.Code)
	}
	if store.passwords[7].FailedAttempts != 0 {
		t.Errorf("failed attempts not reset: %d", store.passwords[7].FailedAttempts)
	}
}

func TestPasswordLoginRefusedByResolver(t *testing.T) {
	a, store, res := newTestAuth(t, passwordConfig())
	if err := a.CreatePasswordUser(context.Background(), 7, "alice", goodPassword); err != nil {
		t.Fatal(err)
	}
	res.refuse = true
	if rec := do(a.Handler(), "POST", "/auth/login", loginBody("alice", goodPassword), withOrigin(testBase)); rec.Code != http.StatusForbidden {
		t.Errorf("status = %d", rec.Code)
	}
	if len(store.sessions) != 0 {
		t.Error("session created for refused login")
	}
}

func TestRateLimitPerUsername(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig())
	if err := a.CreatePasswordUser(context.Background(), 7, "alice", goodPassword); err != nil {
		t.Fatal(err)
	}
	h := a.Handler()
	// Different IPs, same username: the username limit (3) applies.
	for i := range 3 {
		rec := do(h, "POST", "/auth/login", loginBody("alice", "wrong password!"), withOrigin(testBase), withRemote("192.0.2."+string(rune('1'+i))+":1234"))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	rec := do(h, "POST", "/auth/login", loginBody("ALICE", goodPassword), withOrigin(testBase), withRemote("192.0.2.9:1234"))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Fatalf("after limit: %d, Retry-After %q", rec.Code, rec.Header().Get("Retry-After"))
	}
	a.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if rec := do(h, "POST", "/auth/login", loginBody("alice", goodPassword), withOrigin(testBase)); rec.Code != http.StatusOK {
		t.Fatalf("after window: %d", rec.Code)
	}
}

func TestRateLimitPerIPIgnoresUntrustedXFF(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig())
	h := a.Handler()
	// Untrusted peer rotating X-Forwarded-For: all failures count against the peer.
	for i := range 5 {
		rec := do(h, "POST", "/auth/login", loginBody("user"+string(rune('a'+i)), "wrong password!"),
			withOrigin(testBase), withRemote("203.0.113.5:1000"), withXFF("198.51.100."+string(rune('1'+i))))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, rec.Code)
		}
	}
	rec := do(h, "POST", "/auth/login", loginBody("userz", "wrong password!"),
		withOrigin(testBase), withRemote("203.0.113.5:1000"), withXFF("198.51.100.200"))
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("untrusted peer not limited: %d", rec.Code)
	}

	// Trusted proxy: each forwarded client has its own budget.
	for i := range 6 {
		rec := do(h, "POST", "/auth/login", loginBody("v"+string(rune('a'+i)), "wrong password!"),
			withOrigin(testBase), withRemote("10.1.2.3:1000"), withXFF("198.51.100."+string(rune('1'+i))))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("trusted attempt %d: %d", i, rec.Code)
		}
	}
}

func TestClientIP(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig())
	tests := []struct {
		remote, xff, want string
	}{
		{"203.0.113.5:1", "198.51.100.1", "203.0.113.5"},
		{"10.0.0.1:1", "198.51.100.1", "198.51.100.1"},
		{"10.0.0.1:1", "1.1.1.1, 198.51.100.1, 10.0.0.2", "198.51.100.1"},
		{"10.0.0.1:1", "garbage", "10.0.0.1"},
		{"10.0.0.1:1", "", "10.0.0.1"},
		{"[::ffff:10.0.0.1]:1", "198.51.100.1", "198.51.100.1"},
	}
	for _, tt := range tests {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = tt.remote
		if tt.xff != "" {
			r.Header.Set("X-Forwarded-For", tt.xff)
		}
		if got := a.clientIP(r).String(); got != tt.want {
			t.Errorf("remote %s xff %q: got %s, want %s", tt.remote, tt.xff, got, tt.want)
		}
	}
}

func protected(t *testing.T) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := middleware.UserIDFromContext(r)
		if !ok {
			t.Error("no user in context")
		}
		info := middleware.UserInfoFromContext(r)
		_, hasSession := SessionFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{"uid": uid, "login": info.Login, "session": hasSession})
	})
}

func TestMiddleware(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig())
	c := passwordLogin(t, a)
	h := a.Middleware()(protected(t))

	rec := do(h, "GET", "/api/x", "", withCookie(c))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"uid":7`) || !strings.Contains(rec.Body.String(), `"login":"alice"`) {
		t.Fatalf("GET with session: %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "POST", "/api/x", "{}", withCookie(c), withOrigin(testBase)); rec.Code != http.StatusOK {
		t.Errorf("POST same origin: %d", rec.Code)
	}
	if rec := do(h, "POST", "/api/x", "{}", withCookie(c), withOrigin("https://evil.example")); rec.Code != http.StatusForbidden {
		t.Errorf("POST foreign origin: %d", rec.Code)
	}
	if rec := do(h, "DELETE", "/api/x", "", withCookie(c)); rec.Code != http.StatusForbidden {
		t.Errorf("DELETE without origin: %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/x", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("no cookie: %d", rec.Code)
	}
	if rec := do(h, "GET", "/api/x", "", withCookie(&http.Cookie{Name: "__Host-session", Value: "forged"})); rec.Code != http.StatusUnauthorized {
		t.Errorf("forged cookie: %d", rec.Code)
	}
}

func TestMiddlewareExpiredSession(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig())
	c := passwordLogin(t, a)
	a.now = func() time.Time { return time.Now().Add(DefaultSessionTTL + time.Minute) }
	if rec := do(a.Middleware()(protected(t)), "GET", "/api/x", "", withCookie(c)); rec.Code != http.StatusUnauthorized {
		t.Errorf("expired session: %d", rec.Code)
	}
	if rec := do(a.Handler(), "GET", "/auth/me", "", withCookie(c)); rec.Code != http.StatusUnauthorized {
		t.Errorf("me with expired session: %d", rec.Code)
	}
}

func TestMiddlewareFallback(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig())
	c := passwordLogin(t, a)
	called := 0
	fallback := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called++
			next.ServeHTTP(w, r.WithContext(middleware.WithUser(r.Context(), 1, middleware.UserInfo{Login: "ts"})))
		})
	}
	h := a.Middleware(WithFallback(fallback))(protected(t))
	if rec := do(h, "GET", "/api/x", ""); rec.Code != http.StatusOK || called != 1 || !strings.Contains(rec.Body.String(), `"uid":1`) {
		t.Errorf("fallback: %d called=%d %s", rec.Code, called, rec.Body)
	}
	if rec := do(h, "GET", "/api/x", "", withCookie(c)); !strings.Contains(rec.Body.String(), `"uid":7`) || called != 1 {
		t.Errorf("session must win over fallback: %s called=%d", rec.Body, called)
	}
}

func TestLogoutAndSessions(t *testing.T) {
	a, store, _ := newTestAuth(t, passwordConfig())
	c1 := passwordLogin(t, a)
	rec := do(a.Handler(), "POST", "/auth/login", loginBody("alice", goodPassword), withOrigin(testBase))
	c2 := cookie(rec, "__Host-session")
	ctx := context.Background()

	list, err := a.ListSessions(ctx, 7)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListSessions = %d, %v", len(list), err)
	}
	if err := a.RevokeSession(ctx, 8, list[0].ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoke other user's session: %v", err)
	}
	if rec := do(a.Handler(), "POST", "/auth/logout", "", withCookie(c1), withOrigin("https://evil.example")); rec.Code != http.StatusForbidden {
		t.Errorf("logout foreign origin: %d", rec.Code)
	}
	rec = do(a.Handler(), "POST", "/auth/logout", "", withCookie(c1), withOrigin(testBase))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("logout: %d", rec.Code)
	}
	if lc := cookie(rec, "__Host-session"); lc == nil || lc.MaxAge >= 0 {
		t.Errorf("logout cookie = %+v", lc)
	}
	if rec := do(a.Handler(), "GET", "/auth/me", "", withCookie(c1)); rec.Code != http.StatusUnauthorized {
		t.Errorf("me after logout: %d", rec.Code)
	}
	if err := a.RevokeUserSessions(ctx, 7); err != nil {
		t.Fatal(err)
	}
	if rec := do(a.Handler(), "GET", "/auth/me", "", withCookie(c2)); rec.Code != http.StatusUnauthorized {
		t.Errorf("me after revoke: %d", rec.Code)
	}
	if len(store.sessions) != 0 {
		t.Errorf("sessions left: %d", len(store.sessions))
	}
}

func TestLoginReplacesPreviousSession(t *testing.T) {
	a, store, _ := newTestAuth(t, passwordConfig())
	c := passwordLogin(t, a)
	rec := do(a.Handler(), "POST", "/auth/login", loginBody("alice", goodPassword), withOrigin(testBase), withCookie(c))
	if rec.Code != http.StatusOK {
		t.Fatal(rec.Code)
	}
	if len(store.sessions) != 1 {
		t.Errorf("sessions = %d, want 1", len(store.sessions))
	}
}

func TestPasswordManagement(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig())
	ctx := context.Background()
	if err := a.CreatePasswordUser(ctx, 7, "alice", "short"); !errors.Is(err, ErrWeakPassword) {
		t.Errorf("short password: %v", err)
	}
	if err := a.CreatePasswordUser(ctx, 7, "alice", goodPassword); err != nil {
		t.Fatal(err)
	}
	if err := a.CreatePasswordUser(ctx, 8, "ALICE", goodPassword); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate username: %v", err)
	}
	if err := a.ChangePassword(ctx, 7, "wrong password!", "another long password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("change with wrong current: %v", err)
	}
	if err := a.ChangePassword(ctx, 7, goodPassword, "another long password"); err != nil {
		t.Fatal(err)
	}
	if err := a.SetPassword(ctx, 7, "admin reset password"); err != nil {
		t.Fatal(err)
	}
	if err := a.SetPassword(ctx, 99, "admin reset password"); !errors.Is(err, ErrNotFound) {
		t.Errorf("set password of unknown user: %v", err)
	}
	if rec := do(a.Handler(), "POST", "/auth/login", loginBody("alice", "admin reset password"), withOrigin(testBase)); rec.Code != http.StatusOK {
		t.Errorf("login with reset password: %d", rec.Code)
	}
}

func TestDeleteUser(t *testing.T) {
	a, store, _ := newTestAuth(t, passwordConfig())
	c := passwordLogin(t, a)
	_ = store.CreateIdentity(context.Background(), IdentityLink{Issuer: "i", Subject: "s", UserID: 7})
	if err := a.DeleteUser(context.Background(), 7); err != nil {
		t.Fatal(err)
	}
	if len(store.sessions)+len(store.identities)+len(store.passwords) != 0 {
		t.Error("rows left after DeleteUser")
	}
	if rec := do(a.Handler(), "GET", "/auth/me", "", withCookie(c)); rec.Code != http.StatusUnauthorized {
		t.Errorf("me after delete: %d", rec.Code)
	}
}

func TestMethodsEndpoint(t *testing.T) {
	cfg := oidcConfig("https://idp.example.com")
	cfg.Methods = []string{MethodOIDC, MethodPassword}
	cfg.OIDC.DisplayName = "Tailscale"
	a, _, _ := newTestAuth(t, cfg)
	rec := do(a.Handler(), "GET", "/auth/methods", "")
	want := `{"methods":[{"type":"oidc","display_name":"Tailscale","start_url":"/auth/oidc/start"},{"type":"password"}]}`
	if strings.TrimSpace(rec.Body.String()) != want {
		t.Errorf("methods = %s", rec.Body)
	}

	p, _, _ := newTestAuth(t, passwordConfig())
	if rec := do(p.Handler(), "GET", "/auth/oidc/start", ""); rec.Code != http.StatusNotFound {
		t.Errorf("oidc start on password-only instance: %d", rec.Code)
	}
}

func TestIsInitialAdmin(t *testing.T) {
	cfg := oidcConfig("https://idp.example.com")
	cfg.Methods = []string{MethodOIDC, MethodPassword}
	cfg.InitialAdmin = "Alice@example.com"
	a, _, _ := newTestAuth(t, cfg)
	tests := []struct {
		id   Identity
		want bool
	}{
		{Identity{Method: MethodOIDC, Issuer: "https://idp.example.com", Email: "alice@example.com"}, true},
		{Identity{Method: MethodOIDC, Issuer: "https://other.example.com", Email: "alice@example.com"}, false},
		{Identity{Method: MethodOIDC, Issuer: "https://idp.example.com", Email: "bob@example.com"}, false},
		{Identity{Method: MethodPassword, Subject: "alice@example.com"}, true},
		{Identity{Method: MethodPassword, Subject: "alice"}, false},
	}
	for _, tt := range tests {
		if got := a.IsInitialAdmin(tt.id); got != tt.want {
			t.Errorf("IsInitialAdmin(%+v) = %v", tt.id, got)
		}
	}
}

func TestLoopbackHTTPCookie(t *testing.T) {
	cfg := passwordConfig()
	cfg.BaseURL = "http://localhost:8080"
	a, _, _ := newTestAuth(t, cfg)
	if err := a.CreatePasswordUser(context.Background(), 7, "alice", goodPassword); err != nil {
		t.Fatal(err)
	}
	rec := do(a.Handler(), "POST", "/auth/login", loginBody("alice", goodPassword), withOrigin("http://localhost:8080"))
	c := cookie(rec, "session")
	if rec.Code != http.StatusOK || c == nil || c.Secure {
		t.Fatalf("loopback login: %d cookie %+v", rec.Code, c)
	}
}
