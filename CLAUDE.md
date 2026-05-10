# meltkit

Shared Go library for meltforce services. Provides reusable infrastructure packages so each service focuses on business logic, not boilerplate.

Currently used by: **totalrecall** (personal knowledge system), **vimmary** (YouTube video summaries).

## Packages

```
pkg/config/       # YAML + env var config loading, struct validation
pkg/db/           # pgxpool connection, migrations, optional pgvector registration
pkg/server/       # chi router, SPA frontend serving, HTTP lifecycle
pkg/middleware/    # Tailscale identity, dev identity, request logging, CORS
pkg/mcp/          # MCP server factory, user ID context injection
pkg/secrets/      # setec integration (optional), secret resolution chain
```

## Package Details

### pkg/config
- Generic YAML config loading with env var overrides
- Reusable structs: `DatabaseConfig` (with `DSN()` method), `ServerConfig`, `TailscaleConfig`
- Apps embed these structs and add app-specific fields
- Env var prefix is app-defined (e.g. `TOTALRECALL_*`, `VIMMARY_*`)

### pkg/db
- `DB` struct wrapping `pgxpool.Pool`
- `New(ctx, dsn, ...Option)` — connection pool factory
- `WithPgvector()` option — registers pgvector types via `AfterConnect` hook
- `RunMigrations(dsn, migrationsFS)` — golang-migrate with embedded SQL
- `Close()` for graceful shutdown

### pkg/server
- `Server` struct with `chi.Router`
- `New(...Option)` factory
- `SetTailscale(lc)` — configure Tailscale local client for auth
- `SetMCP(mcpSrv)` — mount MCP at `/mcp` with user ID context injection
- `SetFrontend(fs.FS)` — serve embedded SPA with cache control
- `ServeHTTP(w, r)` — implements `http.Handler`

### pkg/middleware
- `UserInfo` struct, `UserIDFromContext(r)`, `UserInfoFromContext(r)` helpers
- `TailscaleIdentity(whoisClient, userStore)` — production auth
- `DevIdentity()` — dev mode, falls back to user_id=1
- `RequestLogging()` — structured HTTP request logs
- `CORS()` — permissive CORS for dev

### pkg/mcp
- `UserIDFromContext(ctx)`, `WithUserID(ctx, id)` — context helpers
- `NewServer(name, version, instructions)` — MCP server factory with standard capabilities
- Apps register their own tools via `mcp.AddTools()`

### pkg/secrets
- `InitSetecStore(ctx, httpClient, serverURL)` — connect to setec over Tailscale
- `ResolveSecret(key)` — priority chain: env var → setec → literal config value
- Optional — apps without secrets skip this package entirely

## Patterns

- **No app-specific logic**: meltkit provides infrastructure only. Business logic, storage queries, MCP tool handlers, and service layers stay in each app.
- **Opt-in features**: pgvector registration, setec secrets, frontend serving are all optional. Services use only what they need.
- **Interface-based**: Middleware uses interfaces (`whoisClient`, `userStore`) for testability.
- **Embed and extend**: Apps embed meltkit config structs into their own config, adding app-specific fields.

## Git Push

Source of truth is the in-house Forgejo (`git.coydog-fence.ts.net/meltforce.net/meltkit`, tailnet-only). Codeberg (`codeberg.org/meltforce/meltkit`) is a public push-mirror.

```bash
# Forgejo push uses the credential helper (setec-backed)
git remote set-url origin https://git.coydog-fence.ts.net/meltforce.net/meltkit.git
git push
```

## Key Commands

```bash
# Run tests
go test ./...

# Run tests with race detector
go test -race ./...
```

## Dependencies

- `go-chi/chi/v5` — HTTP router
- `jackc/pgx/v5` — PostgreSQL driver
- `pgvector/pgvector-go` — pgvector type support
- `mark3labs/mcp-go` — MCP server
- `golang-migrate/migrate/v4` — database migrations
- `tailscale.com` — tsnet, local client
- `tailscale/setec` — secret management
- `yaml.v3` — config parsing

## CI

Forgejo Actions runs on push to `main` and on PRs (`.forgejo/workflows/ci.yml`): build, vet, test (`-race`), golangci-lint, govulncheck. Runs on the `bob-01` runner using the `docker` label.

govulncheck is `continue-on-error` due to a Go 1.25 / x/tools compatibility panic. Remove the flag once upstream fixes it.

## Related Projects

- **totalrecall** (`../totalrecall/`) — Original extraction source. To be refactored to import meltkit.
- **vimmary** (`../vimmary/`) — First new consumer. See `../vimmary/CONCEPT.md`.
