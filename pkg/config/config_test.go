package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	yaml := `
server:
  host: "0.0.0.0"
  port: 8080
database:
  host: "localhost"
  port: 5432
  name: "testdb"
  user: "testuser"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	type cfg struct {
		Server   ServerConfig   `yaml:"server"`
		Database DatabaseConfig `yaml:"database"`
	}

	var c cfg
	if err := Load(path, &c); err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if c.Server.Host != "0.0.0.0" {
		t.Errorf("Server.Host = %q, want %q", c.Server.Host, "0.0.0.0")
	}
	if c.Server.Port != 8080 {
		t.Errorf("Server.Port = %d, want %d", c.Server.Port, 8080)
	}
	if c.Database.Host != "localhost" {
		t.Errorf("Database.Host = %q, want %q", c.Database.Host, "localhost")
	}
	if c.Database.Name != "testdb" {
		t.Errorf("Database.Name = %q, want %q", c.Database.Name, "testdb")
	}
}

func TestDatabaseConfigDSN(t *testing.T) {
	d := DatabaseConfig{Host: "localhost", Port: 5432, Name: "mydb", User: "me"}

	got := d.DSN("secret")
	want := "postgres://me:secret@localhost:5432/mydb?sslmode=disable"
	if got != want {
		t.Errorf("DSN() = %q, want %q", got, want)
	}

	d.SSLMode = "require"
	got = d.DSN("secret")
	want = "postgres://me:secret@localhost:5432/mydb?sslmode=require"
	if got != want {
		t.Errorf("DSN() with SSLMode = %q, want %q", got, want)
	}
}

func TestDatabaseConfigValidate(t *testing.T) {
	tests := []struct {
		name string
		cfg  DatabaseConfig
		err  bool
	}{
		{"valid", DatabaseConfig{Host: "h", Port: 1, Name: "n", User: "u"}, false},
		{"no host", DatabaseConfig{Port: 1, Name: "n", User: "u"}, true},
		{"no port", DatabaseConfig{Host: "h", Name: "n", User: "u"}, true},
		{"no name", DatabaseConfig{Host: "h", Port: 1, User: "u"}, true},
		{"no user", DatabaseConfig{Host: "h", Port: 1, Name: "n"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.err {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.err)
			}
		})
	}
}

func TestApplyEnvOverrides(t *testing.T) {
	t.Setenv("TEST_SERVER_HOST", "envhost")
	t.Setenv("TEST_SERVER_PORT", "9090")
	t.Setenv("TEST_DB_HOST", "dbhost")
	t.Setenv("TEST_DB_PORT", "5433")
	t.Setenv("TEST_DB_NAME", "envdb")
	t.Setenv("TEST_DB_USER", "envuser")
	t.Setenv("TEST_DB_SSLMODE", "require")
	t.Setenv("TEST_TS_HOSTNAME", "myhost")
	t.Setenv("TEST_TS_STATE_DIR", "/tmp/ts")

	s := &ServerConfig{}
	d := &DatabaseConfig{}
	ts := &TailscaleConfig{}
	ApplyEnvOverrides(s, d, ts, "TEST")

	if s.Host != "envhost" {
		t.Errorf("Server.Host = %q, want %q", s.Host, "envhost")
	}
	if s.Port != 9090 {
		t.Errorf("Server.Port = %d, want %d", s.Port, 9090)
	}
	if d.Host != "dbhost" {
		t.Errorf("Database.Host = %q, want %q", d.Host, "dbhost")
	}
	if d.Port != 5433 {
		t.Errorf("Database.Port = %d, want %d", d.Port, 5433)
	}
	if d.Name != "envdb" {
		t.Errorf("Database.Name = %q, want %q", d.Name, "envdb")
	}
	if d.User != "envuser" {
		t.Errorf("Database.User = %q, want %q", d.User, "envuser")
	}
	if d.SSLMode != "require" {
		t.Errorf("Database.SSLMode = %q, want %q", d.SSLMode, "require")
	}
	if ts.Hostname != "myhost" {
		t.Errorf("Tailscale.Hostname = %q, want %q", ts.Hostname, "myhost")
	}
	if ts.StateDir != "/tmp/ts" {
		t.Errorf("Tailscale.StateDir = %q, want %q", ts.StateDir, "/tmp/ts")
	}
}

func TestApplyEnvOverridesBoolParsing(t *testing.T) {
	tests := []struct {
		val  string
		want bool
	}{
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"1", true},
		{"false", false},
		{"0", false},
		{"anything", false},
	}
	for _, tt := range tests {
		t.Run(tt.val, func(t *testing.T) {
			t.Setenv("BP_TS_ENABLED", tt.val)
			ts := &TailscaleConfig{}
			ApplyEnvOverrides(&ServerConfig{}, &DatabaseConfig{}, ts, "BP")
			if ts.Enabled != tt.want {
				t.Errorf("TS_ENABLED=%q → Enabled=%v, want %v", tt.val, ts.Enabled, tt.want)
			}
		})
	}
}
