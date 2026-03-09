package server

import (
	"context"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/meltforce/meltkit/pkg/middleware"
	mcpserver "github.com/mark3labs/mcp-go/server"
)

// Server is a shared HTTP server with routing, identity, and optional frontend serving.
type Server struct {
	log    *slog.Logger
	router chi.Router
	whois  middleware.WhoisClient
	users  middleware.UserStore
}

// Option configures server creation.
type Option func(*Server)

// WithLogger sets the server logger.
func WithLogger(log *slog.Logger) Option {
	return func(s *Server) {
		s.log = log
	}
}

// New creates a new Server with RequestLogging, CORS, and /healthz.
func New(opts ...Option) *Server {
	s := &Server{
		log:    slog.Default(),
		router: chi.NewRouter(),
	}
	for _, opt := range opts {
		opt(s)
	}

	s.router.Use(middleware.RequestLogging(s.log))
	s.router.Use(middleware.CORS)

	s.router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	return s
}

// SetTailscale configures Tailscale identity resolution.
func (s *Server) SetTailscale(lc middleware.WhoisClient, us middleware.UserStore) {
	s.whois = lc
	s.users = us
}

// SetMCP mounts an MCP server at /mcp with identity middleware.
// userIDInjector is called to inject the user ID into the MCP context.
func (s *Server) SetMCP(mcpSrv *mcpserver.MCPServer, userIDInjector func(ctx context.Context, r *http.Request) context.Context) {
	httpServer := mcpserver.NewStreamableHTTPServer(mcpSrv,
		mcpserver.WithHTTPContextFunc(userIDInjector),
	)
	identity := s.IdentityMiddleware()
	s.router.Handle("/mcp", identity(httpServer))
}

// SetFrontend mounts the embedded SPA filesystem.
// Unmatched routes serve index.html for client-side routing.
// Hashed assets get long cache; index.html is never cached.
func (s *Server) SetFrontend(webFS fs.FS) {
	fileServer := http.FileServerFS(webFS)

	s.router.NotFound(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path[1:] // strip leading /

		// API and well-known paths must not fall through to the SPA.
		if strings.HasPrefix(path, "api/") || strings.HasPrefix(path, ".well-known/") || strings.HasPrefix(path, "mcp") {
			http.NotFound(w, r)
			return
		}

		// Try to serve the exact file first
		f, err := webFS.Open(path)
		if err == nil {
			_ = f.Close()
			if len(path) > 7 && path[:7] == "assets/" {
				w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
			} else {
				w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			}
			fileServer.ServeHTTP(w, r)
			return
		}
		// Fallback to index.html for SPA routing
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		r.URL.Path = "/"
		fileServer.ServeHTTP(w, r)
	})
}

// Router returns the chi.Router for adding application routes.
func (s *Server) Router() chi.Router {
	return s.router
}

// IdentityMiddleware returns middleware that uses Tailscale identity if configured,
// otherwise falls back to DevIdentity.
func (s *Server) IdentityMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if s.whois != nil {
				middleware.TailscaleIdentity(s.whois, s.users, s.log)(next).ServeHTTP(w, r)
			} else {
				middleware.DevIdentity(next).ServeHTTP(w, r)
			}
		})
	}
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.router.ServeHTTP(w, r)
}
