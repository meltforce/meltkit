package middleware

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

type mockWhoisClient struct {
	resp *apitype.WhoIsResponse
	err  error
}

func (m *mockWhoisClient) WhoIs(_ context.Context, _ string) (*apitype.WhoIsResponse, error) {
	return m.resp, m.err
}

type mockUserStore struct {
	userID       int
	err          error
	primaryID    int
	primaryLogin string
	primaryErr   error
}

func (m *mockUserStore) GetOrCreateUser(_ context.Context, _, _ string) (int, error) {
	return m.userID, m.err
}

func (m *mockUserStore) GetPrimaryUser(_ context.Context) (int, string, error) {
	return m.primaryID, m.primaryLogin, m.primaryErr
}

func TestDevIdentity(t *testing.T) {
	handler := DevIdentity(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := UserIDFromContext(r)
		if !ok {
			t.Error("expected user ID in context")
		}
		if uid != 1 {
			t.Errorf("UserID = %d, want 1", uid)
		}

		info := UserInfoFromContext(r)
		if info.Login != "local" {
			t.Errorf("Login = %q, want %q", info.Login, "local")
		}
		if info.DisplayName != "Local Dev User" {
			t.Errorf("DisplayName = %q, want %q", info.DisplayName, "Local Dev User")
		}
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestTailscaleIdentity(t *testing.T) {
	log := slog.Default()

	t.Run("success", func(t *testing.T) {
		lc := &mockWhoisClient{resp: &apitype.WhoIsResponse{
			UserProfile: &tailcfg.UserProfile{
				LoginName:   "user@example.com",
				DisplayName: "Test User",
			},
			Node: &tailcfg.Node{
				ComputedName: "mynode",
				Name:         "mynode.tail.ts.net.",
			},
		}}
		us := &mockUserStore{userID: 42}

		handler := TailscaleIdentity(lc, us, log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			uid, ok := UserIDFromContext(r)
			if !ok || uid != 42 {
				t.Errorf("UserID = %d, ok=%v", uid, ok)
			}
			w.WriteHeader(http.StatusOK)
		}))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("tagged device", func(t *testing.T) {
		lc := &mockWhoisClient{resp: &apitype.WhoIsResponse{
			UserProfile: &tailcfg.UserProfile{},
			Node: &tailcfg.Node{
				ComputedName: "server",
				Name:         "server.tail.ts.net.",
				Tags:         []string{"tag:server"},
			},
		}}
		us := &mockUserStore{userID: 1, primaryID: 1, primaryLogin: "owner@example.com"}

		handler := TailscaleIdentity(lc, us, log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("missing login", func(t *testing.T) {
		lc := &mockWhoisClient{resp: &apitype.WhoIsResponse{
			UserProfile: &tailcfg.UserProfile{LoginName: ""},
			Node:        &tailcfg.Node{ComputedName: "node"},
		}}
		us := &mockUserStore{}

		handler := TailscaleIdentity(lc, us, log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		}))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
	})

	t.Run("whois error", func(t *testing.T) {
		lc := &mockWhoisClient{err: fmt.Errorf("connection failed")}
		us := &mockUserStore{}

		handler := TailscaleIdentity(lc, us, log)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		}))

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Code != http.StatusInternalServerError {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusInternalServerError)
		}
	})
}

func TestRequestLogging(t *testing.T) {
	handler := RequestLogging(slog.Default())(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/test", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "hello" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "hello")
	}
}

func TestCORS(t *testing.T) {
	handler := CORS(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("normal request", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
		if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Error("missing CORS origin header")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("preflight", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("OPTIONS", "/", nil))
		if rec.Code != http.StatusNoContent {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
		}
	})
}

func TestUserInfoFromContextDefault(t *testing.T) {
	r := httptest.NewRequest("GET", "/", nil)
	info := UserInfoFromContext(r)
	if info.Login != "local" {
		t.Errorf("Login = %q, want %q", info.Login, "local")
	}
	if info.DisplayName != "Local Dev User" {
		t.Errorf("DisplayName = %q, want %q", info.DisplayName, "Local Dev User")
	}
}
