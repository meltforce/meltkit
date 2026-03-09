package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/meltforce/meltkit/pkg/middleware"
)

func TestHealthz(t *testing.T) {
	s := New()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if rec.Body.String() != "ok" {
		t.Errorf("body = %q, want %q", rec.Body.String(), "ok")
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
