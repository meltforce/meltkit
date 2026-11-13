package auth

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	callbackPath   = "/auth/oidc/callback"
	oidcStateTTL   = 10 * time.Minute
	oidcCookieBase = "oidc_state"
)

// oidcClient discovers the provider on first use and retries after a failure.
type oidcClient struct {
	cfg        Config
	redirect   string
	httpClient *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

func newOIDCClient(cfg Config, base baseURL, hc *http.Client) *oidcClient {
	return &oidcClient{cfg: cfg, redirect: base.origin + callbackPath, httpClient: hc}
}

func (c *oidcClient) clientContext(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, c.httpClient)
}

func (c *oidcClient) load(ctx context.Context) (*oauth2.Config, *oidc.IDTokenVerifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.provider != nil {
		return c.oauth, c.verifier, nil
	}
	// The provider keeps only the context's HTTP client for JWKS fetches,
	// not its deadline.
	dctx, cancel := context.WithTimeout(c.clientContext(ctx), 10*time.Second)
	defer cancel()
	p, err := oidc.NewProvider(dctx, c.cfg.OIDC.Issuer)
	if err != nil {
		return nil, nil, fmt.Errorf("oidc discovery: %w", err)
	}
	c.provider = p
	c.verifier = p.Verifier(&oidc.Config{ClientID: c.cfg.OIDC.ClientID})
	c.oauth = &oauth2.Config{
		ClientID:     c.cfg.OIDC.ClientID,
		ClientSecret: c.cfg.OIDC.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  c.redirect,
		Scopes:       c.cfg.oidcScopes(),
	}
	return c.oauth, c.verifier, nil
}

// oidcState travels in a short-lived HttpOnly cookie between start and
// callback.
type oidcState struct {
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Next     string `json:"r"`
}

// safeNext accepts only a local absolute path, so the callback cannot
// redirect off-site.
func safeNext(next string) string {
	if next == "" || !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.ContainsAny(next, "\\\r\n") {
		return "/"
	}
	u, err := url.Parse(next)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return next
}

func (a *Auth) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	oc, _, err := a.oidc.load(r.Context())
	if err != nil {
		a.log.Error("auth: oidc start failed", "error", err)
		a.loginRedirect(w, r, "oidc_unavailable")
		return
	}
	st := oidcState{
		State:    randomToken(),
		Nonce:    randomToken(),
		Verifier: oauth2.GenerateVerifier(),
		Next:     safeNext(r.URL.Query().Get("next")),
	}
	raw, _ := json.Marshal(st)
	a.setCookie(w, a.cookieName(oidcCookieBase), base64.RawURLEncoding.EncodeToString(raw), int(oidcStateTTL/time.Second))
	http.Redirect(w, r, oc.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)), http.StatusFound)
}

func (a *Auth) loginRedirect(w http.ResponseWriter, r *http.Request, code string) {
	http.Redirect(w, r, a.loginPath+"?error="+url.QueryEscape(code), http.StatusFound)
}

func (a *Auth) readOIDCState(r *http.Request) (oidcState, bool) {
	c, err := r.Cookie(a.cookieName(oidcCookieBase))
	if err != nil {
		return oidcState{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return oidcState{}, false
	}
	var st oidcState
	if json.Unmarshal(raw, &st) != nil || st.State == "" || st.Nonce == "" || st.Verifier == "" {
		return oidcState{}, false
	}
	return st, true
}

// oidcClaims are the ID token claims pkg/auth reads. email_verified is
// accepted as a boolean or the strings "true"/"false".
type oidcClaims struct {
	Email         string          `json:"email"`
	EmailVerified json.RawMessage `json:"email_verified"`
	Name          string          `json:"name"`
}

func (c oidcClaims) emailVerified() bool {
	s := strings.Trim(string(c.EmailVerified), `"`)
	return s == "true"
}

func (a *Auth) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	st, ok := a.readOIDCState(r)
	a.setCookie(w, a.cookieName(oidcCookieBase), "", -1)
	q := r.URL.Query()
	if !ok || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(st.State)) != 1 {
		a.log.Warn("auth: oidc callback with missing or wrong state")
		a.loginRedirect(w, r, "invalid_state")
		return
	}
	if e := q.Get("error"); e != "" {
		a.log.Info("auth: oidc provider returned an error", "error", e)
		a.loginRedirect(w, r, "oidc_denied")
		return
	}
	id, err := a.exchange(r.Context(), q.Get("code"), st)
	if err != nil {
		a.log.Warn("auth: oidc login failed", "error", err)
		a.loginRedirect(w, r, "oidc_failed")
		return
	}
	uid, err := a.resolveOIDC(r.Context(), id)
	if errors.Is(err, ErrNoAccount) {
		a.log.Info("auth: oidc login refused", "issuer", id.Issuer, "subject", id.Subject, "email", id.Email)
		a.loginRedirect(w, r, "no_account")
		return
	}
	if err != nil {
		a.log.Error("auth: oidc user resolution failed", "error", err)
		a.loginRedirect(w, r, "login_failed")
		return
	}
	if _, err := a.startSession(w, r, uid, id); err != nil {
		a.log.Error("auth: creating session failed", "error", err)
		a.loginRedirect(w, r, "login_failed")
		return
	}
	a.log.Info("auth: oidc login", "user_id", uid, "subject", id.Subject)
	http.Redirect(w, r, st.Next, http.StatusFound)
}

// exchange redeems the code and verifies the ID token and its nonce.
func (a *Auth) exchange(ctx context.Context, code string, st oidcState) (Identity, error) {
	if code == "" {
		return Identity{}, errors.New("missing code")
	}
	oc, verifier, err := a.oidc.load(ctx)
	if err != nil {
		return Identity{}, err
	}
	ctx, cancel := context.WithTimeout(a.oidc.clientContext(ctx), 15*time.Second)
	defer cancel()
	tok, err := oc.Exchange(ctx, code, oauth2.VerifierOption(st.Verifier))
	if err != nil {
		return Identity{}, fmt.Errorf("token exchange: %w", err)
	}
	rawID, ok := tok.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Identity{}, errors.New("token response has no id_token")
	}
	idt, err := verifier.Verify(ctx, rawID)
	if err != nil {
		return Identity{}, fmt.Errorf("id token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(st.Nonce)) != 1 {
		return Identity{}, errors.New("id token nonce mismatch")
	}
	var cl oidcClaims
	if err := idt.Claims(&cl); err != nil {
		return Identity{}, fmt.Errorf("id token claims: %w", err)
	}
	if idt.Subject == "" {
		return Identity{}, errors.New("id token has no sub")
	}
	return Identity{
		Method:        MethodOIDC,
		Issuer:        idt.Issuer,
		Subject:       idt.Subject,
		Email:         cl.Email,
		EmailVerified: cl.emailVerified(),
		Name:          cl.Name,
	}, nil
}

// resolveOIDC maps a verified OIDC identity to an app user and records the
// (issuer, subject) link on a first login.
func (a *Auth) resolveOIDC(ctx context.Context, id Identity) (int64, error) {
	link, err := a.store.GetIdentity(ctx, id.Issuer, id.Subject)
	switch {
	case err == nil:
		id.UserID = link.UserID
		return a.resolve(ctx, id)
	case !errors.Is(err, ErrNotFound):
		return 0, err
	}

	if a.cfg.OIDC.LinkByEmail && id.Issuer == a.cfg.OIDC.Issuer && id.Email != "" {
		uid, err := a.users.(LoginLookup).UserIDByLogin(ctx, id.Email)
		switch {
		case err == nil:
			has, err := a.store.UserHasIdentity(ctx, uid)
			if err != nil {
				return 0, err
			}
			if !has {
				id.UserID = uid
			}
		case !errors.Is(err, ErrNoAccount):
			return 0, err
		}
	}

	uid, err := a.resolve(ctx, id)
	if err != nil {
		return 0, err
	}
	err = a.store.CreateIdentity(ctx, IdentityLink{Issuer: id.Issuer, Subject: id.Subject, UserID: uid, Email: id.Email})
	if errors.Is(err, ErrExists) {
		// A concurrent first login of the same subject linked it first.
		link, err := a.store.GetIdentity(ctx, id.Issuer, id.Subject)
		if err != nil {
			return 0, err
		}
		return link.UserID, nil
	}
	if err != nil {
		return 0, err
	}
	return uid, nil
}
