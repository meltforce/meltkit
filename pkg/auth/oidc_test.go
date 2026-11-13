package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeIdP is an in-process OIDC provider: discovery, JWKS and a token
// endpoint that checks PKCE.
type fakeIdP struct {
	srv *httptest.Server
	key *rsa.PrivateKey

	mu              sync.Mutex
	codes           map[string]fakeGrant
	discoveryIssuer string // overrides the issuer in the discovery document
	tokenIssuer     string // overrides iss in ID tokens
	nonceOverride   string
	sub, email      string
	emailVerified   any
}

type fakeGrant struct {
	challenge, nonce, redirect string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &fakeIdP{key: key, codes: map[string]fakeGrant{}, sub: "tsuid-123", email: "alice@example.com"}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", p.discovery)
	mux.HandleFunc("GET /jwks", p.jwks)
	mux.HandleFunc("POST /token", p.token)
	p.srv = httptest.NewServer(mux)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeIdP) issuer() string { return p.srv.URL }

func (p *fakeIdP) discovery(w http.ResponseWriter, _ *http.Request) {
	iss := p.issuer()
	if p.discoveryIssuer != "" {
		iss = p.discoveryIssuer
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                p.issuer() + "/authorize",
		"token_endpoint":                        p.issuer() + "/token",
		"jwks_uri":                              p.issuer() + "/jwks",
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func (p *fakeIdP) jwks(w http.ResponseWriter, _ *http.Request) {
	pub := p.key.PublicKey
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256",
		"n": b64(pub.N.Bytes()), "e": b64(big.NewInt(int64(pub.E)).Bytes()),
	}}})
}

// authorize records what a browser redirect to the provider would carry and
// returns a code for it.
func (p *fakeIdP) authorize(t *testing.T, location string) (code, state string) {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil || !strings.HasPrefix(location, p.issuer()+"/authorize") {
		t.Fatalf("start redirect = %q", location)
	}
	q := u.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" || q.Get("nonce") == "" || q.Get("state") == "" {
		t.Fatalf("authorize query lacks PKCE, nonce or state: %s", u.RawQuery)
	}
	if q.Get("client_id") != "vimmary" || q.Get("redirect_uri") != testBase+"/auth/oidc/callback" {
		t.Fatalf("client_id/redirect_uri = %q %q", q.Get("client_id"), q.Get("redirect_uri"))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	code = "code-" + b64([]byte(q.Get("state")))[:8]
	p.codes[code] = fakeGrant{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), redirect: q.Get("redirect_uri")}
	return code, q.Get("state")
}

func (p *fakeIdP) token(w http.ResponseWriter, r *http.Request) {
	if id, secret, ok := r.BasicAuth(); !ok || id != "vimmary" || secret != "s3cret" {
		if r.PostFormValue("client_id") != "vimmary" || r.PostFormValue("client_secret") != "s3cret" {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
	}
	p.mu.Lock()
	g, ok := p.codes[r.PostFormValue("code")]
	delete(p.codes, r.PostFormValue("code"))
	p.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostFormValue("code_verifier")))
	if !ok || b64(sum[:]) != g.challenge || r.PostFormValue("redirect_uri") != g.redirect {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
		return
	}
	iss := p.issuer()
	if p.tokenIssuer != "" {
		iss = p.tokenIssuer
	}
	nonce := g.nonce
	if p.nonceOverride != "" {
		nonce = p.nonceOverride
	}
	claims := map[string]any{
		"iss": iss, "sub": p.sub, "aud": "vimmary", "nonce": nonce,
		"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(),
		"email": p.email, "name": "Alice",
	}
	if p.emailVerified != nil {
		claims["email_verified"] = p.emailVerified
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": p.sign(claims),
	})
}

func (p *fakeIdP) sign(claims map[string]any) string {
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	c, _ := json.Marshal(claims)
	input := b64(h) + "." + b64(c)
	sum := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, p.key, crypto.SHA256, sum[:])
	return input + "." + b64(sig)
}

func oidcConfig(issuer string) Config {
	return Config{
		BaseURL: testBase,
		Methods: []string{MethodOIDC},
		OIDC: OIDCConfig{
			Issuer:       issuer,
			ClientID:     "vimmary",
			ClientSecret: "s3cret",
		},
	}
}

func newOIDCAuth(t *testing.T, idp *fakeIdP, mod func(*Config)) (*Auth, *memStore, *fakeResolver) {
	cfg := oidcConfig(idp.issuer())
	if mod != nil {
		mod(&cfg)
	}
	return newTestAuth(t, cfg, WithHTTPClient(idp.srv.Client()))
}

// oidcLogin runs start, the provider round trip and the callback. tamper may
// change the callback query.
func oidcLogin(t *testing.T, a *Auth, idp *fakeIdP, next string, tamper func(url.Values)) *httptest.ResponseRecorder {
	t.Helper()
	h := a.Handler()
	start := do(h, "GET", "/auth/oidc/start?next="+url.QueryEscape(next), "")
	if start.Code != http.StatusFound {
		t.Fatalf("start: %d %s", start.Code, start.Body)
	}
	sc := cookie(start, "__Host-oidc_state")
	if sc == nil || !sc.HttpOnly || !sc.Secure {
		t.Fatalf("state cookie = %+v", sc)
	}
	code, state := idp.authorize(t, start.Header().Get("Location"))
	q := url.Values{"code": {code}, "state": {state}}
	if tamper != nil {
		tamper(q)
	}
	return do(h, "GET", "/auth/oidc/callback?"+q.Encode(), "", withCookie(sc))
}

func TestOIDCLogin(t *testing.T) {
	idp := newFakeIdP(t)
	a, store, res := newOIDCAuth(t, idp, nil)

	rec := oidcLogin(t, a, idp, "/videos?x=1", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/videos?x=1" {
		t.Fatalf("callback: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	c := cookie(rec, "__Host-session")
	if c == nil {
		t.Fatal("no session cookie")
	}
	id := res.last()
	if id.Method != MethodOIDC || id.Issuer != idp.issuer() || id.Subject != "tsuid-123" || id.Email != "alice@example.com" || id.UserID != 0 || id.EmailVerified {
		t.Errorf("identity = %+v", id)
	}
	link, err := store.GetIdentity(context.Background(), idp.issuer(), "tsuid-123")
	if err != nil || link.UserID != 101 {
		t.Fatalf("identity link = %+v, %v", link, err)
	}

	// Second login: known identity, resolver receives the linked user.
	rec = oidcLogin(t, a, idp, "", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("second login: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if id := res.last(); id.UserID != 101 {
		t.Errorf("second login UserID = %d", id.UserID)
	}

	me := do(a.Handler(), "GET", "/auth/me", "", withCookie(cookie(rec, "__Host-session")))
	if !strings.Contains(me.Body.String(), `"login":"alice@example.com"`) || !strings.Contains(me.Body.String(), `"method":"oidc"`) {
		t.Errorf("me = %s", me.Body)
	}
}

func TestOIDCEmailVerifiedClaim(t *testing.T) {
	idp := newFakeIdP(t)
	idp.emailVerified = true
	a, _, res := newOIDCAuth(t, idp, nil)
	oidcLogin(t, a, idp, "", nil)
	if !res.last().EmailVerified {
		t.Error("email_verified true not read")
	}
}

func expectLoginError(t *testing.T, rec *httptest.ResponseRecorder, code string) {
	t.Helper()
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/login?error="+code {
		t.Errorf("got %d %q, want redirect to /login?error=%s", rec.Code, rec.Header().Get("Location"), code)
	}
	if cookie(rec, "__Host-session") != nil {
		t.Error("session cookie set on failure")
	}
}

func TestOIDCWrongState(t *testing.T) {
	idp := newFakeIdP(t)
	a, _, res := newOIDCAuth(t, idp, nil)
	rec := oidcLogin(t, a, idp, "", func(q url.Values) { q.Set("state", "forged") })
	expectLoginError(t, rec, "invalid_state")

	// Callback without the state cookie.
	rec = do(a.Handler(), "GET", "/auth/oidc/callback?code=x&state=y", "")
	expectLoginError(t, rec, "invalid_state")
	if len(res.calls) != 0 {
		t.Error("resolver called")
	}
}

func TestOIDCWrongNonce(t *testing.T) {
	idp := newFakeIdP(t)
	idp.nonceOverride = "replayed-nonce"
	a, store, _ := newOIDCAuth(t, idp, nil)
	expectLoginError(t, oidcLogin(t, a, idp, "", nil), "oidc_failed")
	if len(store.identities) != 0 {
		t.Error("identity stored")
	}
}

func TestOIDCForeignIssuerInToken(t *testing.T) {
	idp := newFakeIdP(t)
	idp.tokenIssuer = "https://evil.example.com"
	a, _, _ := newOIDCAuth(t, idp, nil)
	expectLoginError(t, oidcLogin(t, a, idp, "", nil), "oidc_failed")
}

func TestOIDCForeignIssuerInDiscovery(t *testing.T) {
	idp := newFakeIdP(t)
	idp.discoveryIssuer = "https://evil.example.com"
	a, _, _ := newOIDCAuth(t, idp, nil)
	rec := do(a.Handler(), "GET", "/auth/oidc/start", "")
	expectLoginError(t, rec, "oidc_unavailable")
}

func TestOIDCPKCEVerifierMismatch(t *testing.T) {
	idp := newFakeIdP(t)
	a, _, _ := newOIDCAuth(t, idp, nil)
	h := a.Handler()
	start := do(h, "GET", "/auth/oidc/start", "")
	code, state := idp.authorize(t, start.Header().Get("Location"))
	// A state cookie from a second, unrelated start carries another verifier.
	other := do(h, "GET", "/auth/oidc/start", "")
	var st oidcState
	raw, _ := base64.RawURLEncoding.DecodeString(cookie(other, "__Host-oidc_state").Value)
	_ = json.Unmarshal(raw, &st)
	st.State = state
	b, _ := json.Marshal(st)
	sc := &http.Cookie{Name: "__Host-oidc_state", Value: base64.RawURLEncoding.EncodeToString(b)}
	rec := do(h, "GET", "/auth/oidc/callback?code="+code+"&state="+url.QueryEscape(state), "", withCookie(sc))
	expectLoginError(t, rec, "oidc_failed")
}

func TestOIDCProviderError(t *testing.T) {
	idp := newFakeIdP(t)
	a, _, _ := newOIDCAuth(t, idp, nil)
	rec := oidcLogin(t, a, idp, "", func(q url.Values) { q.Del("code"); q.Set("error", "access_denied") })
	expectLoginError(t, rec, "oidc_denied")
}

func TestOIDCNoAccount(t *testing.T) {
	idp := newFakeIdP(t)
	a, store, res := newOIDCAuth(t, idp, nil)
	res.refuse = true
	expectLoginError(t, oidcLogin(t, a, idp, "", nil), "no_account")
	if len(store.identities) != 0 {
		t.Error("identity stored for refused login")
	}
}

func TestOIDCOpenRedirect(t *testing.T) {
	for _, next := range []string{"https://evil.example", "//evil.example/x", "/\\evil.example", "javascript:alert(1)"} {
		if got := safeNext(next); got != "/" {
			t.Errorf("safeNext(%q) = %q", next, got)
		}
	}
	if got := safeNext("/a/b?c=d"); got != "/a/b?c=d" {
		t.Errorf("safeNext kept path wrongly: %q", got)
	}
}

func TestLinkByEmailOff(t *testing.T) {
	idp := newFakeIdP(t)
	a, store, res := newOIDCAuth(t, idp, nil)
	res.logins["alice@example.com"] = 5
	oidcLogin(t, a, idp, "", nil)
	if id := res.last(); id.UserID != 0 {
		t.Errorf("link_by_email off linked to %d", id.UserID)
	}
	if l, _ := store.GetIdentity(context.Background(), idp.issuer(), "tsuid-123"); l.UserID == 5 {
		t.Error("identity linked to existing user")
	}
}

func TestLinkByEmailOn(t *testing.T) {
	idp := newFakeIdP(t)
	a, store, res := newOIDCAuth(t, idp, func(c *Config) { c.OIDC.LinkByEmail = true })
	res.logins["alice@example.com"] = 5
	rec := oidcLogin(t, a, idp, "", nil)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if id := res.last(); id.UserID != 5 {
		t.Errorf("resolver UserID = %d, want 5", id.UserID)
	}
	if l, err := store.GetIdentity(context.Background(), idp.issuer(), "tsuid-123"); err != nil || l.UserID != 5 {
		t.Errorf("link = %+v, %v", l, err)
	}
}

func TestLinkByEmailSkipsUserWithIdentity(t *testing.T) {
	idp := newFakeIdP(t)
	a, store, res := newOIDCAuth(t, idp, func(c *Config) { c.OIDC.LinkByEmail = true })
	res.logins["alice@example.com"] = 5
	_ = store.CreateIdentity(context.Background(), IdentityLink{Issuer: idp.issuer(), Subject: "other-sub", UserID: 5})
	oidcLogin(t, a, idp, "", nil)
	if id := res.last(); id.UserID != 0 {
		t.Errorf("linked to user that already has an identity: %d", id.UserID)
	}
}

func TestLinkByEmailNoMatch(t *testing.T) {
	idp := newFakeIdP(t)
	a, _, res := newOIDCAuth(t, idp, func(c *Config) { c.OIDC.LinkByEmail = true })
	oidcLogin(t, a, idp, "", nil)
	if id := res.last(); id.UserID != 0 {
		t.Errorf("UserID = %d", id.UserID)
	}
}
