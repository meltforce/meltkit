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
	// Link marks a flow started by StartOIDCLink. The user to link to is
	// held server-side under the state's hash, never in this cookie.
	Link bool `json:"l,omitempty"`
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
	a.beginOIDC(w, r, r.URL.Query().Get("next"), 0)
}

// StartOIDCLink starts the OIDC code flow to link the provider identity to
// userID, a user the app has already authenticated (session or fallback).
// The callback links (issuer, subject) if no other user holds it, then
// starts a session for userID and redirects to next. Failures redirect to
// the login page with error=identity_in_use, invalid_state and the login
// error codes.
//
// Call it from a top-level navigation (link or form POST), not from fetch.
// A state-changing request must carry an Origin equal to base_url.
func (a *Auth) StartOIDCLink(w http.ResponseWriter, r *http.Request, userID int64, next string) {
	if a.oidc == nil {
		writeError(w, http.StatusNotFound, "oidc not enabled")
		return
	}
	if !isSafeMethod(r.Method) && !a.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin mismatch")
		return
	}
	if userID <= 0 {
		writeError(w, http.StatusBadRequest, "invalid user")
		return
	}
	a.beginOIDC(w, r, next, userID)
}

// beginOIDC redirects to the provider. A non-zero linkUser records a pending
// link for the flow's state.
func (a *Auth) beginOIDC(w http.ResponseWriter, r *http.Request, next string, linkUser int64) {
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
		Next:     safeNext(next),
		Link:     linkUser != 0,
	}
	if st.Link {
		if err := a.store.CreateOIDCLink(r.Context(), hashToken(st.State), linkUser, a.now().Add(oidcStateTTL)); err != nil {
			a.log.Error("auth: recording oidc link failed", "error", err)
			writeError(w, http.StatusInternalServerError, "link failed")
			return
		}
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
	// Consume the pending link before anything else, so that every outcome
	// spends it.
	var linkUser int64
	if st.Link {
		uid, err := a.store.ConsumeOIDCLink(r.Context(), hashToken(st.State), a.now())
		if err != nil {
			if !errors.Is(err, ErrNotFound) {
				a.log.Error("auth: reading oidc link failed", "error", err)
			}
			a.log.Warn("auth: oidc link callback without a pending link")
			a.loginRedirect(w, r, "invalid_state")
			return
		}
		linkUser = uid
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
	var uid int64
	if linkUser != 0 {
		uid, err = a.linkOIDC(r.Context(), id, linkUser)
	} else {
		uid, err = a.resolveOIDC(r.Context(), id)
	}
	if errors.Is(err, errIdentityInUse) {
		a.log.Info("auth: oidc identity already linked to another user", "subject", id.Subject, "user_id", linkUser)
		a.loginRedirect(w, r, "identity_in_use")
		return
	}
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
		// A concurrent first login of the same subject linked it first. Its
		// user wins; a user the resolver created for this login stays in the
		// app without an identity.
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

// errIdentityInUse refuses a link to an identity another user holds.
var errIdentityInUse = errors.New("auth: identity linked to another user")

// linkOIDC links a verified identity to userID unless another user holds it,
// then asks the resolver with UserID set.
func (a *Auth) linkOIDC(ctx context.Context, id Identity, userID int64) (int64, error) {
	link, err := a.store.GetIdentity(ctx, id.Issuer, id.Subject)
	switch {
	case err == nil && link.UserID != userID:
		return 0, errIdentityInUse
	case err == nil:
		id.UserID = userID
		return a.resolve(ctx, id)
	case !errors.Is(err, ErrNotFound):
		return 0, err
	}
	id.UserID = userID
	uid, err := a.resolve(ctx, id)
	if err != nil {
		return 0, err
	}
	err = a.store.CreateIdentity(ctx, IdentityLink{Issuer: id.Issuer, Subject: id.Subject, UserID: uid, Email: id.Email})
	if errors.Is(err, ErrExists) {
		// Linked concurrently; accept it only if it went to the same user.
		link, err := a.store.GetIdentity(ctx, id.Issuer, id.Subject)
		if err != nil {
			return 0, err
		}
		if link.UserID != uid {
			return 0, errIdentityInUse
		}
		return uid, nil
	}
	if err != nil {
		return 0, err
	}
	return uid, nil
}

// ListIdentities returns the OIDC identities linked to userID.
func (a *Auth) ListIdentities(ctx context.Context, userID int64) ([]IdentityLink, error) {
	return a.store.ListIdentities(ctx, userID)
}

// UnlinkIdentity removes an OIDC identity of userID. It returns ErrNotFound
// when the identity does not exist or belongs to another user. Whether the
// user keeps a way to log in is the app's check.
func (a *Auth) UnlinkIdentity(ctx context.Context, userID int64, issuer, subject string) error {
	return a.store.DeleteIdentity(ctx, userID, issuer, subject)
}
