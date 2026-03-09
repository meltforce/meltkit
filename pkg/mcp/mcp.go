package mcp

import (
	"context"

	"github.com/mark3labs/mcp-go/server"
)

type contextKey int

const userIDKey contextKey = iota

// UserIDFromContext returns the user ID from the context, defaulting to 1.
func UserIDFromContext(ctx context.Context) int {
	if id, ok := ctx.Value(userIDKey).(int); ok {
		return id
	}
	return 1
}

// WithUserID stores the user ID in the context.
func WithUserID(ctx context.Context, userID int) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// NewServer creates a new MCP server with standard capabilities.
func NewServer(name, version, instructions string) *server.MCPServer {
	return server.NewMCPServer(name, version,
		server.WithToolCapabilities(false),
		server.WithInstructions(instructions),
	)
}
