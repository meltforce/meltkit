package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

type DatabaseConfig struct {
	Host    string `yaml:"host"`
	Port    int    `yaml:"port"`
	Name    string `yaml:"name"`
	User    string `yaml:"user"`
	SSLMode string `yaml:"sslmode"`
}

type TailscaleConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Hostname string `yaml:"hostname"`
	StateDir string `yaml:"state_dir"`
}

type SecretBackendConfig struct {
	Type     string `yaml:"type"`      // "setec" or ""
	SetecURL string `yaml:"setec_url"` // e.g. "https://setec.tail-scale.ts.net"
}

func (d DatabaseConfig) DSN(password string) string {
	sslmode := d.SSLMode
	if sslmode == "" {
		sslmode = "disable"
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, password, d.Host, d.Port, d.Name, sslmode)
}

func (d DatabaseConfig) Validate() error {
	if d.Host == "" {
		return fmt.Errorf("database.host is required")
	}
	if d.Port == 0 {
		return fmt.Errorf("database.port is required")
	}
	if d.Name == "" {
		return fmt.Errorf("database.name is required")
	}
	if d.User == "" {
		return fmt.Errorf("database.user is required")
	}
	return nil
}

// Load reads a YAML file and unmarshals it into the target struct.
func Load[T any](path string, target *T) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading config file: %w", err)
	}
	if err := yaml.Unmarshal(data, target); err != nil {
		return fmt.Errorf("parsing config file: %w", err)
	}
	return nil
}

// ApplyEnvOverrides applies environment variable overrides using the given prefix.
// For example, with prefix "MYAPP", it checks MYAPP_SERVER_HOST, MYAPP_DB_HOST, etc.
func ApplyEnvOverrides(server *ServerConfig, database *DatabaseConfig, tailscale *TailscaleConfig, prefix string) {
	if v := os.Getenv(prefix + "_SERVER_HOST"); v != "" {
		server.Host = v
	}
	if v := os.Getenv(prefix + "_SERVER_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			server.Port = port
		}
	}
	if v := os.Getenv(prefix + "_DB_HOST"); v != "" {
		database.Host = v
	}
	if v := os.Getenv(prefix + "_DB_PORT"); v != "" {
		if port, err := strconv.Atoi(v); err == nil {
			database.Port = port
		}
	}
	if v := os.Getenv(prefix + "_DB_NAME"); v != "" {
		database.Name = v
	}
	if v := os.Getenv(prefix + "_DB_USER"); v != "" {
		database.User = v
	}
	if v := os.Getenv(prefix + "_DB_SSLMODE"); v != "" {
		database.SSLMode = v
	}
	if v := os.Getenv(prefix + "_TS_ENABLED"); v != "" {
		tailscale.Enabled = strings.EqualFold(v, "true") || v == "1"
	}
	if v := os.Getenv(prefix + "_TS_HOSTNAME"); v != "" {
		tailscale.Hostname = v
	}
	if v := os.Getenv(prefix + "_TS_STATE_DIR"); v != "" {
		tailscale.StateDir = v
	}
}
