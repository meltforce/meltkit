package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/meltforce/meltkit/pkg/middleware"
)

func TestHealthz(t *testing.T) {
	sha := "0123456789abcdef0123456789abcdef01234567"
	for _, tc := range []struct {
		name string
		opts []Option
		want string
	}{
		{"unset reports dev", nil, `{"status":"ok","sha":"dev"}`},
		{"empty reports dev", []Option{WithBuildSHA("")}, `{"status":"ok","sha":"dev"}`},
		{"build SHA", []Option{WithBuildSHA(sha)}, `{"status":"ok","sha":"` + sha + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(tc.opts...)
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", ct)
			}
			if rec.Body.String() != tc.want {
				t.Errorf("body = %q, want %q", rec.Body.String(), tc.want)
			}
		})
	}
}

func TestRouterAccess(t *testing.T) {
	s := New()
	s.Router().Get("/custom", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("custom"))
	})

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/custom", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "custom" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "custom")
	}
}

func TestIdentityMiddlewareDevMode(t *testing.T) {
	s := New()
	handler := s.IdentityMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		uid, ok := middleware.UserIDFromContext(r)
		if !ok || uid != 1 {
			t.Errorf("UserID = %d, ok=%v, want 1/true", uid, ok)
		}
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

func TestSetFrontend(t *testing.T) {
	webFS := fstest.MapFS{
		"index.html":       {Data: []byte("<html>app</html>")},
		"assets/main.js":   {Data: []byte("console.log('hi')")},
		"favicon.ico":      {Data: []byte("icon")},
	}

	s := New()
	s.SetFrontend(webFS)

	t.Run("asset with cache", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest("GET", "/assets/main.js", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		cc := rec.Header().Get("Cache-Control")
		if cc != "public, max-age=31536000, immutable" {
			t.Errorf("Cache-Control = %q, want immutable", cc)
		}
	})

	t.Run("non-asset no cache", func(t *testing.T) {
		rec := httptest.NewRecorder()
		s.ServeHTTP(rec, httptest.NewRequest("GET", "/favicon.ico", nil))
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
		cc := rec.Header().Get("Cache-Control")
		if cc != "no-cache, no-store, must-revalidate" {
			t.Errorf("Cache-Control = %q, want no-cache", cc)
		}
	})
}

func TestSetFrontendSPAFallback(t *testing.T) {
	webFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>app</html>")},
	}

	s := New()
	s.SetFrontend(webFS)

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/some/unknown/path", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "<html>app</html>" {
		t.Errorf("body = %q, want index.html content", rec.Body.String())
	}
}

func TestSetFrontendAPINotFound(t *testing.T) {
	webFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>app</html>")},
	}

	s := New()
	s.SetFrontend(webFS)

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/api/missing", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestSetMCPWithAuth(t *testing.T) {
	s := New()
	called := 0
	deny := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called++
			w.Header().Set("WWW-Authenticate", "Bearer")
			w.WriteHeader(http.StatusUnauthorized)
		})
	}
	s.SetMCPWithAuth(mcpserver.NewMCPServer("test", "0"), func(ctx context.Context, _ *http.Request) context.Context { return ctx }, deny)

	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("POST", "/mcp", strings.NewReader(`{}`)))
	if rec.Code != http.StatusUnauthorized || called != 1 {
		t.Errorf("status = %d, middleware calls = %d; want 401, 1", rec.Code, called)
	}
}

func TestSetMCPUsesIdentityMiddleware(t *testing.T) {
	s := New()
	var uid int
	s.SetMCP(mcpserver.NewMCPServer("test", "0"), func(ctx context.Context, r *http.Request) context.Context {
		uid, _ = middleware.UserIDFromContext(r)
		return ctx
	})
	req := httptest.NewRequest("POST", "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || uid != 1 {
		t.Errorf("status = %d, uid = %d; want 200, 1 (DevIdentity)", rec.Code, uid)
	}
}
