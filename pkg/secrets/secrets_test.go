package secrets

import (
	"testing"
)

func TestResolveSecretFromEnv(t *testing.T) {
	t.Setenv("TEST_DB_PASSWORD", "env-password")

	r := NewResolver(map[string]string{"db-password": "literal-value"}, "TEST")
	got, err := r.ResolveSecret("db-password")
	if err != nil {
		t.Fatalf("ResolveSecret() error: %v", err)
	}
	if got != "env-password" {
		t.Errorf("ResolveSecret() = %q, want %q", got, "env-password")
	}
}

func TestResolveSecretLiteral(t *testing.T) {
	r := NewResolver(map[string]string{"api-key": "my-literal-key"}, "NOEXIST")
	got, err := r.ResolveSecret("api-key")
	if err != nil {
		t.Fatalf("ResolveSecret() error: %v", err)
	}
	if got != "my-literal-key" {
		t.Errorf("ResolveSecret() = %q, want %q", got, "my-literal-key")
	}
}

func TestResolveSecretCaching(t *testing.T) {
	r := NewResolver(map[string]string{"key": "value"}, "NOEXIST")
	v1, err := r.ResolveSecret("key")
	if err != nil {
		t.Fatal(err)
	}
	v2, err := r.ResolveSecret("key")
	if err != nil {
		t.Fatal(err)
	}
	if v1 != v2 {
		t.Errorf("cached value mismatch: %q != %q", v1, v2)
	}
	if _, ok := r.resolvedSecrets["key"]; !ok {
		t.Error("expected key to be in resolved cache")
	}
}

func TestResolveSecretNotConfigured(t *testing.T) {
	r := NewResolver(map[string]string{}, "NOEXIST")
	_, err := r.ResolveSecret("unknown")
	if err == nil {
		t.Error("expected error for unknown key")
	}
}

func TestResolveSecretEnvPrefix(t *testing.T) {
	// Dashes in key name become underscores, uppercased
	t.Setenv("MYAPP_MY_SECRET_KEY", "from-env")

	r := NewResolver(map[string]string{"my-secret-key": "literal"}, "MYAPP")
	got, err := r.ResolveSecret("my-secret-key")
	if err != nil {
		t.Fatalf("ResolveSecret() error: %v", err)
	}
	if got != "from-env" {
		t.Errorf("ResolveSecret() = %q, want %q", got, "from-env")
	}
}
