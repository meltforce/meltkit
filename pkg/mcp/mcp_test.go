package mcp

import (
	"context"
	"testing"
)

func TestWithUserID(t *testing.T) {
	ctx := WithUserID(context.Background(), 42)
	got := UserIDFromContext(ctx)
	if got != 42 {
		t.Errorf("UserIDFromContext() = %d, want 42", got)
	}
}

func TestUserIDFromContextDefault(t *testing.T) {
	got := UserIDFromContext(context.Background())
	if got != 1 {
		t.Errorf("UserIDFromContext() = %d, want 1", got)
	}
}

func TestNewServer(t *testing.T) {
	s := NewServer("test", "1.0.0", "test instructions")
	if s == nil {
		t.Error("NewServer() returned nil")
	}
}
