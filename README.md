# meltkit

Shared Go infrastructure library for [meltforce](https://github.com/meltforce) services. Each service focuses on business logic — meltkit handles the boilerplate.

## Packages

| Package | Description |
|---|---|
| `pkg/config` | YAML config loading, reusable config structs, env var overrides |
| `pkg/secrets` | Secret resolution chain: env var → setec → literal value |
| `pkg/db` | pgxpool connection pool, migrations via embedded FS, optional pgvector |
| `pkg/middleware` | Tailscale identity, dev identity, request logging, CORS |
| `pkg/server` | chi router, SPA frontend serving, MCP mounting, health check |
| `pkg/mcp` | MCP server factory with user ID context injection |

## Usage

```go
import (
    "github.com/meltforce/meltkit/pkg/config"
    "github.com/meltforce/meltkit/pkg/db"
    "github.com/meltforce/meltkit/pkg/server"
)

// Define your app config by embedding meltkit structs
type AppConfig struct {
    Server   config.ServerConfig   `yaml:"server"`
    Database config.DatabaseConfig `yaml:"database"`
    // app-specific fields...
}

// Load config
var cfg AppConfig
config.Load("config.yaml", &cfg)
config.ApplyEnvOverrides(&cfg.Server, &cfg.Database, nil, "MYAPP")

// Connect to database
database, _ := db.New(ctx, cfg.Database.DSN(password), db.WithPgvector())
defer database.Close()

// Create server
srv := server.New(server.WithLogger(log))
srv.Router().Get("/api/v1/things", handleThings)
```

## Design Principles

- **No app-specific logic** — infrastructure only, business logic stays in each service
- **Opt-in features** — pgvector, setec secrets, frontend serving are all optional
- **Interface-based** — middleware uses interfaces for testability
- **Embed and extend** — apps embed meltkit config structs, adding their own fields

## Development

```bash
go test ./...           # run tests
go test -race ./...     # run tests with race detector
go vet ./...            # static analysis
```

## Dependencies

- [go-chi/chi](https://github.com/go-chi/chi) — HTTP router
- [jackc/pgx](https://github.com/jackc/pgx) — PostgreSQL driver
- [pgvector/pgvector-go](https://github.com/pgvector/pgvector-go) — pgvector types
- [mark3labs/mcp-go](https://github.com/mark3labs/mcp-go) — MCP server
- [golang-migrate/migrate](https://github.com/golang-migrate/migrate) — database migrations
- [tailscale.com](https://github.com/tailscale/tailscale) — Tailscale identity
- [tailscale/setec](https://github.com/tailscale/setec) — secret management
