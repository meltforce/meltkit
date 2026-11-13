package auth

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Password length bounds, in characters and bytes.
const (
	MinPasswordLength = 12
	maxPasswordBytes  = 1024
	maxUsernameBytes  = 256
)

// argon2id parameters (OWASP minimum: 19 MiB, 2 iterations, 1 lane).
const (
	argonMemory  = 19 * 1024
	argonTime    = 2
	argonThreads = 1
	argonKeyLen  = 32
	argonSaltLen = 16

	hashConcurrency = 4
)

// ErrWeakPassword is returned when a password is shorter than
// MinPasswordLength characters or longer than 1024 bytes.
var ErrWeakPassword = fmt.Errorf("auth: password must have at least %d characters", MinPasswordLength)

// ErrInvalidCredentials is returned by ChangePassword for a wrong current
// password.
var ErrInvalidCredentials = errors.New("auth: invalid credentials")

// dummyHash is verified for unknown usernames so that their response time
// matches that of a known username.
var dummyHash = sync.OnceValue(func() string { return hashPasswordUnbounded("meltkit-dummy-password") })

func checkPassword(pw string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLength || len(pw) > maxPasswordBytes {
		return ErrWeakPassword
	}
	return nil
}

func normalizeUsername(u string) string { return strings.TrimSpace(u) }

func hashPasswordUnbounded(pw string) string {
	salt := make([]byte, argonSaltLen)
	_, _ = rand.Read(salt)
	key := argon2.IDKey([]byte(pw), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key))
}

// acquire bounds concurrent argon2 computations, which take 19 MiB each.
func (a *Auth) acquire(ctx context.Context) error {
	select {
	case a.hashSem <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (a *Auth) release() { <-a.hashSem }

func (a *Auth) hashPassword(ctx context.Context, pw string) (string, error) {
	if err := a.acquire(ctx); err != nil {
		return "", err
	}
	defer a.release()
	return hashPasswordUnbounded(pw), nil
}

func (a *Auth) verifyPassword(ctx context.Context, encoded, pw string) (bool, error) {
	if err := a.acquire(ctx); err != nil {
		return false, err
	}
	defer a.release()
	return verifyPHC(encoded, pw)
}

// verifyPHC checks pw against a $argon2id$v=19$m=..,t=..,p=..$salt$key string.
func verifyPHC(encoded, pw string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" || parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return false, fmt.Errorf("auth: unsupported password hash format")
	}
	var m, t uint32
	var p uint8
	for _, kv := range strings.Split(parts[3], ",") {
		k, v, _ := strings.Cut(kv, "=")
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return false, fmt.Errorf("auth: password hash parameter %q: %w", kv, err)
		}
		switch k {
		case "m":
			m = uint32(n)
		case "t":
			t = uint32(n)
		case "p":
			if n > math.MaxUint8 {
				return false, fmt.Errorf("auth: password hash parameter %q out of range", kv)
			}
			p = uint8(n)
		}
	}
	if m == 0 || t == 0 || p == 0 || m > 1<<22 || t > 64 {
		return false, fmt.Errorf("auth: password hash parameters out of range")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("auth: password hash salt: %w", err)
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) == 0 || len(want) > 128 {
		return false, fmt.Errorf("auth: password hash key malformed")
	}
	got := argon2.IDKey([]byte(pw), salt, t, m, p, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// CreatePasswordUser gives the existing app user userID a local login. The
// app creates the user row first. Usernames are unique, case-insensitively.
func (a *Auth) CreatePasswordUser(ctx context.Context, userID int64, username, password string) error {
	username = normalizeUsername(username)
	if username == "" || len(username) > maxUsernameBytes || !utf8.ValidString(username) {
		return fmt.Errorf("auth: invalid username")
	}
	if err := checkPassword(password); err != nil {
		return err
	}
	h, err := a.hashPassword(ctx, password)
	if err != nil {
		return err
	}
	return a.store.CreatePassword(ctx, PasswordRecord{UserID: userID, Username: username, Hash: h})
}

// SetPassword replaces the password of userID, as an admin reset does. It
// keeps existing sessions; RevokeUserSessions ends them.
func (a *Auth) SetPassword(ctx context.Context, userID int64, password string) error {
	if err := checkPassword(password); err != nil {
		return err
	}
	if _, err := a.store.GetPasswordByUserID(ctx, userID); err != nil {
		return err
	}
	h, err := a.hashPassword(ctx, password)
	if err != nil {
		return err
	}
	if err := a.store.UpdatePasswordHash(ctx, userID, h); err != nil {
		return err
	}
	return a.store.ResetLoginFailures(ctx, userID)
}

// ChangePassword replaces the password of userID after verifying the current
// one, as a user changing their own password does.
func (a *Auth) ChangePassword(ctx context.Context, userID int64, current, password string) error {
	rec, err := a.store.GetPasswordByUserID(ctx, userID)
	if err != nil {
		return err
	}
	ok, err := a.verifyPassword(ctx, rec.Hash, current)
	if err != nil {
		return err
	}
	if !ok {
		return ErrInvalidCredentials
	}
	return a.SetPassword(ctx, userID, password)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *Auth) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !a.sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin mismatch")
		return
	}
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	username := normalizeUsername(req.Username)
	if username == "" || req.Password == "" || len(username) > maxUsernameBytes || len(req.Password) > maxPasswordBytes {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	userKey := strings.ToLower(username)
	ip := a.clientIP(r).String()
	now := a.now()
	if blocked, until := a.limiter.blocked(userKey, ip, now); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(until.Sub(now).Seconds()))))
		writeError(w, http.StatusTooManyRequests, "too many failed logins")
		return
	}

	ctx := r.Context()
	rec, err := a.store.GetPasswordByUsername(ctx, username)
	known := err == nil
	if err != nil && !errors.Is(err, ErrNotFound) {
		a.log.Error("auth: password lookup failed", "error", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	hash := dummyHash()
	if known {
		hash = rec.Hash
	}
	ok, err := a.verifyPassword(ctx, hash, req.Password)
	if err != nil {
		a.log.Error("auth: password verification failed", "user_id", rec.UserID, "error", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	if !known || !ok {
		a.limiter.fail(userKey, ip, now)
		if known {
			if err := a.store.RecordLoginFailure(ctx, rec.UserID, now); err != nil {
				a.log.Warn("auth: recording login failure failed", "error", err)
			}
		}
		a.log.Info("auth: password login failed", "username", username, "client_ip", ip)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}

	id := Identity{Method: MethodPassword, Subject: rec.Username, UserID: rec.UserID}
	uid, err := a.resolve(ctx, id)
	if errors.Is(err, ErrNoAccount) {
		writeError(w, http.StatusForbidden, "no account")
		return
	}
	if err != nil {
		a.log.Error("auth: resolving user failed", "error", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	a.limiter.reset(userKey)
	if rec.FailedAttempts > 0 {
		if err := a.store.ResetLoginFailures(ctx, uid); err != nil {
			a.log.Warn("auth: resetting login failures failed", "error", err)
		}
	}
	s, err := a.startSession(w, r, uid, id)
	if err != nil {
		a.log.Error("auth: creating session failed", "error", err)
		writeError(w, http.StatusInternalServerError, "login failed")
		return
	}
	a.log.Info("auth: password login", "user_id", uid, "client_ip", ip)
	writeJSON(w, http.StatusOK, map[string]any{"user_id": uid, "expires_at": s.ExpiresAt.UTC().Format(time.RFC3339)})
}
