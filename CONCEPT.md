# meltkit — Implementierungsauftrag

## Ziel

Gemeinsame Go-Infrastruktur aus totalrecall extrahieren und als eigenständiges, versioniertes Go-Modul bereitstellen. Danach totalrecall auf meltkit umstellen, dann vimmary damit bauen.

## Vorgehen

### Phase 1: Modul aufsetzen

1. Go-Modul initialisieren: `github.com/meltforce/meltkit`
2. Package-Struktur anlegen (siehe CLAUDE.md)
3. Go dependencies einrichten

### Phase 2: Code extrahieren

Reihenfolge nach Abhängigkeiten (unabhängige Packages zuerst):

**Schritt 1 — pkg/config**
- `DatabaseConfig`, `ServerConfig`, `TailscaleConfig` aus `/Users/linus/projects/totalrecall/internal/config/config.go`
- YAML-Loading und env var override Pattern generalisieren
- Env-Var-Prefix als Parameter, nicht hardcoded
- Validierung als Interface oder Methode

**Schritt 2 — pkg/secrets**
- setec-Integration aus `/Users/linus/projects/totalrecall/internal/config/config.go` herauslösen
- `InitSetecStore(ctx, httpClient, serverURL)`
- `ResolveSecret(key)` mit Priority Chain
- Als eigenständiges Package, nicht in config eingebettet

**Schritt 3 — pkg/db**
- `DB` struct, `New()`, `Close()` aus `/Users/linus/projects/totalrecall/internal/storage/db.go`
- `RunMigrations()` generalisieren (migrationsFS als Parameter)
- pgvector-Registration als `WithPgvector()` Option
- AfterConnect-Hook Pattern beibehalten

**Schritt 4 — pkg/middleware**
- `UserInfo`, Context-Helpers aus `/Users/linus/projects/totalrecall/internal/server/middleware.go`
- `TailscaleIdentity()`, `DevIdentity()`, `RequestLogging()`, `CORS()`
- Interfaces für whoisClient und userStore beibehalten

**Schritt 5 — pkg/server**
- `Server` struct aus `/Users/linus/projects/totalrecall/internal/server/server.go`
- `SetTailscale()`, `SetMCP()`, `SetFrontend()`
- Middleware-Integration aus pkg/middleware

**Schritt 6 — pkg/mcp**
- Context-Helpers (`WithUserID`, `UserIDFromContext`) aus `/Users/linus/projects/totalrecall/internal/mcp/server.go`
- `NewServer()` Factory
- Tool-Handler bleiben in den Apps

### Phase 3: Tests

- Unit-Tests für jedes Package
- Besonders: Config-Loading mit env vars, DB-Connection mit pgvector, Middleware-Chain
- Keine Integration-Tests gegen echte Datenbank in meltkit (das machen die Apps)

### Phase 4: totalrecall umstellen

1. `go get github.com/meltforce/meltkit`
2. Interne Packages durch meltkit-Imports ersetzen
3. App-spezifischen Code in totalrecall belassen
4. Tests laufen lassen, deployen, verifizieren

### Phase 5: vimmary bauen

- vimmary importiert meltkit von Anfang an
- Siehe `../vimmary/CONCEPT.md` für Details

## Wichtige Regeln

- **Keine Business-Logik** in meltkit — nur Infrastruktur
- **Keine Breaking Changes** ohne Semver-Bump
- **Opt-in Features** — kein Package darf Abhängigkeiten erzwingen, die nicht jeder Consumer braucht
- **Interfaces statt konkrete Typen** wo sinnvoll (Testbarkeit)
- **Bestehende Patterns beibehalten** — nicht "verbessern" beim Extrahieren, sondern 1:1 übernehmen und erst in einem zweiten Schritt refactorn
