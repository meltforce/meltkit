package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// startLink calls StartOIDCLink for userID the way an app route does and
// returns the state cookie and the provider's code and state.
func startLink(t *testing.T, a *Auth, idp *fakeIdP, userID int64) (sc *http.Cookie, code, state string) {
	t.Helper()
	rec := httptest.NewRecorder()
	a.StartOIDCLink(rec, httptest.NewRequest("GET", "/api/settings/link", nil), userID, "/settings")
	if rec.Code != http.StatusFound {
		t.Fatalf("StartOIDCLink: %d %s", rec.Code, rec.Body)
	}
	sc = cookie(rec, "__Host-oidc_state")
	code, state = idp.authorize(t, rec.Header().Get("Location"))
	return sc, code, state
}

func callback(a *Auth, sc *http.Cookie, code, state string) *httptest.ResponseRecorder {
	q := url.Values{"code": {code}, "state": {state}}
	return do(a.Handler(), "GET", "/auth/oidc/callback?"+q.Encode(), "", withCookie(sc))
}

func editState(t *testing.T, c *http.Cookie, f func(*oidcState)) *http.Cookie {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		t.Fatal(err)
	}
	var st oidcState
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	f(&st)
	b, _ := json.Marshal(st)
	return &http.Cookie{Name: c.Name, Value: base64.RawURLEncoding.EncodeToString(b)}
}

func TestOIDCLinkFlow(t *testing.T) {
	idp := newFakeIdP(t)
	a, store, res := newOIDCAuth(t, idp, nil)
	sc, code, state := startLink(t, a, idp, 7)
	raw, _ := base64.RawURLEncoding.DecodeString(sc.Value)
	if containsUserID(raw) {
		t.Fatalf("state cookie carries the user ID: %s", raw)
	}

	rec := callback(a, sc, code, state)
	if rec.Code != http.StatusFound || rec.Header().Get("Location") != "/settings" {
		t.Fatalf("callback: %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if cookie(rec, "__Host-session") == nil {
		t.Error("no session after link")
	}
	if id := res.last(); id.UserID != 7 || id.Subject != "tsuid-123" {
		t.Errorf("resolver identity = %+v", id)
	}
	ids, err := a.ListIdentities(context.Background(), 7)
	if err != nil || len(ids) != 1 || ids[0].Subject != "tsuid-123" || ids[0].Issuer != idp.issuer() {
		t.Fatalf("ListIdentities = %+v, %v", ids, err)
	}
	if len(store.links) != 0 {
		t.Error("pending link not consumed")
	}

	// A later plain login with the same identity resolves to user 7.
	oidcLogin(t, a, idp, "", nil)
	if id := res.last(); id.UserID != 7 {
		t.Errorf("login after link: UserID = %d", id.UserID)
	}

	if err := a.UnlinkIdentity(context.Background(), 8, idp.issuer(), "tsuid-123"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unlink by other user: %v", err)
	}
	if err := a.UnlinkIdentity(context.Background(), 7, idp.issuer(), "tsuid-123"); err != nil {
		t.Fatal(err)
	}
	if ids, _ := a.ListIdentities(context.Background(), 7); len(ids) != 0 {
		t.Errorf("identities after unlink: %+v", ids)
	}
}

func containsUserID(raw []byte) bool {
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, v := range m {
		if f, ok := v.(float64); ok && f == 7 {
			return true
		}
	}
	return false
}

func TestOIDCLinkIdentityInUse(t *testing.T) {
	idp := newFakeIdP(t)
	a, store, res := newOIDCAuth(t, idp, nil)
	_ = store.CreateIdentity(context.Background(), IdentityLink{Issuer: idp.issuer(), Subject: "tsuid-123", UserID: 9})
	sc, code, state := startLink(t, a, idp, 7)
	expectLoginError(t, callback(a, sc, code, state), "identity_in_use")
	if l, _ := store.GetIdentity(context.Background(), idp.issuer(), "tsuid-123"); l.UserID != 9 {
		t.Errorf("identity moved to user %d", l.UserID)
	}
	if len(res.calls) != 0 {
		t.Error("resolver called")
	}
}

func TestOIDCLinkAlreadyOwn(t *testing.T) {
	idp := newFakeIdP(t)
	a, store, _ := newOIDCAuth(t, idp, nil)
	_ = store.CreateIdentity(context.Background(), IdentityLink{Issuer: idp.issuer(), Subject: "tsuid-123", UserID: 7})
	sc, code, state := startLink(t, a, idp, 7)
	if rec := callback(a, sc, code, state); rec.Header().Get("Location") != "/settings" {
		t.Errorf("relink own identity: %q", rec.Header().Get("Location"))
	}
}

func TestOIDCLinkExpired(t *testing.T) {
	idp := newFakeIdP(t)
	a, store, _ := newOIDCAuth(t, idp, nil)
	sc, code, state := startLink(t, a, idp, 7)
	a.now = func() time.Time { return time.Now().Add(oidcStateTTL + time.Minute) }
	expectLoginError(t, callback(a, sc, code, state), "invalid_state")
	if len(store.identities) != 0 {
		t.Error("identity linked after expiry")
	}
}

func TestOIDCLinkReused(t *testing.T) {
	idp := newFakeIdP(t)
	a, store, _ := newOIDCAuth(t, idp, nil)
	sc, code, state := startLink(t, a, idp, 7)
	if rec := callback(a, sc, code, state); rec.Header().Get("Location") != "/settings" {
		t.Fatalf("first callback: %q", rec.Header().Get("Location"))
	}
	_ = store.DeleteIdentity(context.Background(), 7, idp.issuer(), "tsuid-123")
	// Replay with the same cookie and state, and a fresh code for them.
	idp.mu.Lock()
	idp.codes["replay"] = fakeGrant{}
	idp.mu.Unlock()
	expectLoginError(t, callback(a, sc, "replay", state), "invalid_state")
	if len(store.identities) != 0 {
		t.Error("replayed link created an identity")
	}
}

func TestOIDCLinkForgedCookie(t *testing.T) {
	idp := newFakeIdP(t)
	a, store, res := newOIDCAuth(t, idp, nil)
	h := a.Handler()
	// A plain login flow whose cookie is edited to claim a link.
	start := do(h, "GET", "/auth/oidc/start", "")
	code, state := idp.authorize(t, start.Header().Get("Location"))
	forged := editState(t, cookie(start, "__Host-oidc_state"), func(s *oidcState) { s.Link = true })
	expectLoginError(t, callback(a, forged, code, state), "invalid_state")
	if len(store.identities) != 0 || len(res.calls) != 0 {
		t.Error("forged link cookie had an effect")
	}

	// A link flow whose cookie drops the flag is an ordinary login: it does
	// not link to user 7.
	sc, code, state := startLink(t, a, idp, 7)
	plain := editState(t, sc, func(s *oidcState) { s.Link = false })
	callback(a, plain, code, state)
	if id := res.last(); id.UserID != 0 {
		t.Errorf("unflagged link flow linked to %d", id.UserID)
	}
}

func TestStartOIDCLinkChecks(t *testing.T) {
	idp := newFakeIdP(t)
	a, _, _ := newOIDCAuth(t, idp, nil)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/settings/link", nil)
	r.Header.Set("Origin", "https://evil.example")
	a.StartOIDCLink(rec, r, 7, "/")
	if rec.Code != http.StatusForbidden {
		t.Errorf("foreign origin: %d", rec.Code)
	}

	p, _, _ := newTestAuth(t, passwordConfig())
	rec = httptest.NewRecorder()
	p.StartOIDCLink(rec, httptest.NewRequest("GET", "/", nil), 7, "/")
	if rec.Code != http.StatusNotFound {
		t.Errorf("password-only instance: %d", rec.Code)
	}
}

func TestChangePasswordRateLimit(t *testing.T) {
	a, _, _ := newTestAuth(t, passwordConfig()) // 3 failures per username
	ctx := context.Background()
	if err := a.CreatePasswordUser(ctx, 7, "alice", goodPassword); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := a.ChangePassword(ctx, 7, "wrong password!", "another long password"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", i, err)
		}
	}
	if err := a.ChangePassword(ctx, 7, goodPassword, "another long password"); !errors.Is(err, ErrRateLimited) {
		t.Fatalf("after limit: %v", err)
	}
	if rec := do(a.Handler(), "POST", "/auth/login", loginBody("alice", goodPassword), withOrigin(testBase)); rec.Code != http.StatusTooManyRequests {
		t.Errorf("login shares the username limit: %d", rec.Code)
	}
	a.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if err := a.ChangePassword(ctx, 7, goodPassword, "another long password"); err != nil {
		t.Fatalf("after window: %v", err)
	}
}
