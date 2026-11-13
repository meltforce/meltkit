package server

import (
	"context"
	"encoding/json"
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
	sha    string
}

// Option configures server creation.
type Option func(*Server)

// WithLogger sets the server logger.
func WithLogger(log *slog.Logger) Option {
	return func(s *Server) {
		s.log = log
	}
}

// WithBuildSHA sets the commit SHA that /healthz reports. Pass the value of
// the BUILD_SHA build argument; an empty value reports "dev".
func WithBuildSHA(sha string) Option {
	return func(s *Server) {
		s.sha = sha
	}
}

// New creates a new Server with RequestLogging, CORS, and /healthz.
// /healthz answers 200 with {"status":"ok","sha":"<build SHA>"}.
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

	if s.sha == "" {
		s.sha = "dev"
	}
	health, _ := json.Marshal(struct {
		Status string `json:"status"`
		SHA    string `json:"sha"`
	}{"ok", s.sha})
	s.router.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(health)
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
	s.SetMCPWithAuth(mcpSrv, userIDInjector, s.IdentityMiddleware())
}

// SetMCPWithAuth mounts an MCP server at /mcp behind authMiddleware instead of
// IdentityMiddleware, for example auth.Middleware(auth.WithScope(auth.ScopeMCP)).
// userIDInjector is called to inject the user ID into the MCP context.
func (s *Server) SetMCPWithAuth(mcpSrv *mcpserver.MCPServer, userIDInjector func(ctx context.Context, r *http.Request) context.Context, authMiddleware func(http.Handler) http.Handler) {
	httpServer := mcpserver.NewStreamableHTTPServer(mcpSrv,
		mcpserver.WithHTTPContextFunc(userIDInjector),
	)
	s.router.Handle("/mcp", authMiddleware(httpServer))
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
