package auth

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"
)

// Login methods accepted in Config.Methods.
const (
	MethodOIDC     = "oidc"
	MethodPassword = "password"
)

// DefaultSessionTTL applies when Config.SessionTTL is zero.
const DefaultSessionTTL = 720 * time.Hour

// Config is the `auth:` block of an app's configuration file.
type Config struct {
	// BaseURL is the public origin of the app. Redirect URIs and the Origin
	// check derive from it, never from the Host header. https is required,
	// except for http on a loopback host.
	BaseURL        string        `yaml:"base_url"`
	Methods        []string      `yaml:"methods"`
	SessionTTL     time.Duration `yaml:"session_ttl"`
	TrustedProxies []string      `yaml:"trusted_proxies"`
	// InitialAdmin names the first admin: an OIDC email or a local username.
	// The app reads it through Auth.IsInitialAdmin.
	InitialAdmin string     `yaml:"initial_admin"`
	OIDC         OIDCConfig `yaml:"oidc"`
}

// OIDCConfig configures the single OIDC provider.
type OIDCConfig struct {
	Issuer   string `yaml:"issuer"`
	ClientID string `yaml:"client_id"`
	// ClientSecret holds the resolved secret; the app resolves it through
	// pkg/secrets before calling New.
	ClientSecret string   `yaml:"client_secret"`
	DisplayName  string   `yaml:"display_name"`
	Scopes       []string `yaml:"scopes"`
	// LinkByEmail links a first login to an existing app user whose login
	// equals the email claim and who has no OIDC identity yet. It requires a
	// UserResolver that implements LoginLookup.
	LinkByEmail bool `yaml:"link_by_email"`
}

// HasMethod reports whether m is enabled.
func (c Config) HasMethod(m string) bool {
	return slices.Contains(c.Methods, m)
}

// Validate checks the configuration. New calls it.
func (c Config) Validate() error {
	if _, err := parseBaseURL(c.BaseURL); err != nil {
		return err
	}
	if len(c.Methods) == 0 {
		return fmt.Errorf("auth.methods: at least one of %q, %q is required", MethodOIDC, MethodPassword)
	}
	for _, m := range c.Methods {
		if m != MethodOIDC && m != MethodPassword {
			return fmt.Errorf("auth.methods: unknown method %q", m)
		}
	}
	if c.SessionTTL < 0 {
		return fmt.Errorf("auth.session_ttl must not be negative")
	}
	if _, err := parsePrefixes(c.TrustedProxies); err != nil {
		return err
	}
	if c.HasMethod(MethodOIDC) {
		if c.OIDC.Issuer == "" {
			return fmt.Errorf("auth.oidc.issuer is required for method %q", MethodOIDC)
		}
		if c.OIDC.ClientID == "" {
			return fmt.Errorf("auth.oidc.client_id is required for method %q", MethodOIDC)
		}
	}
	return nil
}

func (c Config) sessionTTL() time.Duration {
	if c.SessionTTL == 0 {
		return DefaultSessionTTL
	}
	return c.SessionTTL
}

func (c Config) oidcScopes() []string {
	scopes := c.OIDC.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "email", "profile"}
	}
	if !slices.Contains(scopes, "openid") {
		scopes = append([]string{"openid"}, scopes...)
	}
	return scopes
}

// baseURL is the parsed form of Config.BaseURL.
type baseURL struct {
	origin string // scheme://host[:port], lower case, no default port
	secure bool   // https
}

func parseBaseURL(raw string) (baseURL, error) {
	if raw == "" {
		return baseURL{}, fmt.Errorf("auth.base_url is required")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return baseURL{}, fmt.Errorf("auth.base_url: %w", err)
	}
	if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return baseURL{}, fmt.Errorf("auth.base_url must be an origin without path, query or user info")
	}
	origin, ok := normalizeOrigin(u)
	if !ok {
		return baseURL{}, fmt.Errorf("auth.base_url: scheme must be https or http")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return baseURL{}, fmt.Errorf("auth.base_url: http is allowed only for a loopback host")
	}
	return baseURL{origin: origin, secure: u.Scheme == "https"}, nil
}

// normalizeOrigin returns scheme://host[:port] with the default port removed.
func normalizeOrigin(u *url.URL) (string, bool) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" || u.Host == "" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if scheme == "https" && port == "443" || scheme == "http" && port == "80" {
		port = ""
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, true
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func parsePrefixes(list []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("auth.trusted_proxies: %q is neither a CIDR nor an address", s)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}
