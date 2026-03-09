package secrets

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/tailscale/setec/client/setec"
)

// Resolver resolves secrets using a priority chain: env var → setec → literal value.
type Resolver struct {
	secrets         map[string]string
	resolvedSecrets map[string]string
	setecStore      *setec.Store
	envPrefix       string
}

// NewResolver creates a new secret resolver.
// secrets maps logical key names to either setec secret names or literal values.
// envPrefix is used for environment variable lookups (e.g. "MYAPP" checks MYAPP_<KEY>).
func NewResolver(secrets map[string]string, envPrefix string) *Resolver {
	return &Resolver{
		secrets:         secrets,
		resolvedSecrets: make(map[string]string),
		envPrefix:       envPrefix,
	}
}

// InitSetecStore initializes the setec secret store.
// Must be called after tsnet is running (setec authenticates via Tailscale identity).
func (r *Resolver) InitSetecStore(ctx context.Context, httpClient *http.Client, serverURL string) error {
	var names []string
	for _, v := range r.secrets {
		if v != "" {
			names = append(names, v)
		}
	}
	store, err := setec.NewStore(ctx, setec.StoreConfig{
		Client: setec.Client{
			Server: serverURL,
			DoHTTP: httpClient.Do,
		},
		Secrets: names,
	})
	if err != nil {
		return fmt.Errorf("init setec store: %w", err)
	}
	r.setecStore = store
	return nil
}

// ResolveSecret resolves a secret by key using the priority chain:
// 1. Environment variable <PREFIX>_<UPPER_KEY> (dashes replaced with underscores)
// 2. setec store (if configured)
// 3. Literal value from config
func (r *Resolver) ResolveSecret(key string) (string, error) {
	if v, ok := r.resolvedSecrets[key]; ok {
		return v, nil
	}

	// 1. Environment variable
	envKey := r.envPrefix + "_" + strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
	if v := os.Getenv(envKey); v != "" {
		r.resolvedSecrets[key] = v
		return v, nil
	}

	raw, ok := r.secrets[key]
	if !ok {
		return "", fmt.Errorf("secret %q not configured", key)
	}

	// 2. setec store lookup
	if r.setecStore != nil && raw != "" {
		if v := r.setecStore.Secret(raw).GetString(); v != "" {
			r.resolvedSecrets[key] = v
			return v, nil
		}
	}

	// 3. Literal value
	r.resolvedSecrets[key] = raw
	return raw, nil
}
