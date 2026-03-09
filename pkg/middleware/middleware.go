package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"tailscale.com/client/tailscale/apitype"
)

// WhoisClient looks up the identity of a Tailscale peer.
type WhoisClient interface {
	WhoIs(ctx context.Context, remoteAddr string) (*apitype.WhoIsResponse, error)
}

// UserStore resolves Tailscale identities to application user IDs.
type UserStore interface {
	GetOrCreateUser(ctx context.Context, login, displayName string) (int, error)
	GetPrimaryUser(ctx context.Context) (int, string, error)
}

type contextKey int

const (
	userIDKey   contextKey = iota
	userInfoKey
)

// UserInfo holds identity information for an authenticated user.
type UserInfo struct {
	Login       string `json:"login"`
	DisplayName string `json:"display_name"`
	TailscaleID string `json:"tailscale_id,omitempty"`
	Tailnet     string `json:"tailnet,omitempty"`
}

// UserIDFromContext returns the authenticated user ID from the request context.
func UserIDFromContext(r *http.Request) (int, bool) {
	id, ok := r.Context().Value(userIDKey).(int)
	return id, ok
}

// UserInfoFromContext returns the authenticated user info from the request context.
func UserInfoFromContext(r *http.Request) UserInfo {
	if info, ok := r.Context().Value(userInfoKey).(UserInfo); ok {
		return info
	}
	return UserInfo{Login: "local", DisplayName: "Local Dev User"}
}

// TailscaleIdentity returns middleware that authenticates requests via Tailscale WhoIs.
func TailscaleIdentity(lc WhoisClient, db UserStore, log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			whois, err := lc.WhoIs(r.Context(), r.RemoteAddr)
			if err != nil {
				log.Error("tailscale whois failed", "remote", r.RemoteAddr, "error", err)
				http.Error(w, `{"error":"identity lookup failed"}`, http.StatusInternalServerError)
				return
			}

			var login, displayName string

			if whois.Node != nil && whois.Node.IsTagged() {
				ownerID, ownerLogin, err := db.GetPrimaryUser(r.Context())
				if err != nil {
					log.Warn("tagged device access denied: no registered user yet",
						"node", whois.Node.ComputedName)
					http.Error(w, `{"error":"access denied: no registered user yet; log in from a personal device first"}`, http.StatusForbidden)
					return
				}
				login = ownerLogin
				displayName = ownerLogin

				log.Info("tagged device resolved to owner",
					"node", whois.Node.ComputedName,
					"owner_login", ownerLogin,
					"owner_id", ownerID,
				)
			} else {
				login = whois.UserProfile.LoginName
				if login == "" {
					http.Error(w, `{"error":"access denied: personal Tailscale login required"}`, http.StatusForbidden)
					return
				}
				displayName = whois.UserProfile.DisplayName
			}

			nodeName := ""
			if whois.Node != nil {
				nodeName = whois.Node.ComputedName
			}

			userID, err := db.GetOrCreateUser(r.Context(), login, displayName)
			if err != nil {
				log.Error("user resolution failed", "login", login, "error", err)
				http.Error(w, `{"error":"user resolution failed"}`, http.StatusInternalServerError)
				return
			}

			log.Info("request authenticated",
				"tailscale_user", login,
				"tailscale_node", nodeName,
				"user_id", userID,
			)

			var tsID, tailnet string
			if whois.Node != nil {
				parts := strings.Split(strings.TrimSuffix(whois.Node.Name, "."), ".")
				if len(parts) >= 3 {
					tsID = parts[0]
					tailnet = strings.Join(parts[1:], ".")
				} else {
					tsID = whois.Node.Name
				}
			}

			ctx := context.WithValue(r.Context(), userIDKey, userID)
			ctx = context.WithValue(ctx, userInfoKey, UserInfo{
				Login:       login,
				DisplayName: displayName,
				TailscaleID: tsID,
				Tailnet:     tailnet,
			})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// DevIdentity is middleware that sets a development user identity (user_id=1).
func DevIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), userIDKey, 1)
		ctx = context.WithValue(ctx, userInfoKey, UserInfo{Login: "local", DisplayName: "Local Dev User"})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestLogging returns middleware that logs HTTP requests.
func RequestLogging(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			log.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.status,
				"duration", time.Since(start).String(),
			)
		})
	}
}

// CORS is middleware that sets permissive CORS headers.
func CORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
