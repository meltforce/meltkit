# Plan: application-level authentication (`pkg/auth`)

## Goal

meltkit apps (vimmary, labtrak, nutrak) authenticate users themselves instead
of through tsnet `WhoIs`:

- browser login through OIDC, local username and password, or both, chosen per
  instance;
- MCP clients through OAuth, with the app as authorization server;
- TLS terminated by a reverse proxy in front of the app.

tsidp is one OIDC provider among others and needs no code of its own.

## Decisions

- **Inbound tsnet and `WhoIs` identity are removed; there is no permanent
  Tailscale mode.** A tsidp login gives tailnet users the same password-free
  sign-in, because tsidp resolves them by `WhoIs` itself. A second identity path
  doubles the test surface, and a wrong mode selection opens access. One
  transitional app release accepts both.
- **Outbound tailnet access is a deployment concern.** cast2md, Aperture and the
  tsidp token endpoint are reached through `tailscaled` on the host or a
  sidecar, not through an in-process tsnet node.
- **`pkg/auth` authenticates; the app authorizes.** `pkg/auth` returns a
  verified identity. User rows, admin role, act-as and account policy stay in
  the app, because labtrak and nutrak already diverge there
  (`internal/identity`).
- **The app is its own OAuth authorization server for MCP in every
  configuration.** A password-only instance has no external authorization
  server to delegate to. tsidp also implements the MCP authorization endpoints
  and DCR (behind the `allow_dcr` capability), but it would cover only instances
  that log in through tsidp.
- **MCP client registration uses Client ID Metadata Documents (CIMD).** MCP
  revision 2026-07-28 marks DCR deprecated and recommends CIMD; claude.ai
  registers through CIMD (tsmcp relies on it). DCR is not implemented.
- **Login, consent and account pages are rendered by each app's frontend.**
  `pkg/auth` serves JSON endpoints and redirects; each app keeps its own design
  system.
- **Machine clients use personal access tokens.** tsmcp, juno and scripts send
  a bearer token bound to a user. tsmcp already sets a per-endpoint upstream
  bearer (`upstream_token_env`), and juno's `mcp-wiring` role supports
  `auth: bearer` from setec, so neither needs a change of its own.
- **No tailnet switch.** An inbound tailnet connection can be told apart from
  others (see *Tailnet switch, considered*), but every caller that relies on
  `WhoIs` today is a machine client covered by a token, and tailnet users get a
  password-free login through tsidp.
- **vimmary is reached at `vimmary.meltrocker.net` through the ingress on
  smokey; outbound requests carry smokey's tailnet identity** (operator
  decision 2026-11-13; the Aperture grant is extended to smokey).

## `pkg/auth`

### Configuration

```yaml
auth:
  base_url: https://vimmary.example.com   # issuer, redirect URIs and the MCP resource derive from it, never the Host header
  methods: [oidc, password]               # one or both
  session_ttl: 720h
  trusted_proxies: [172.16.0.0/12]        # X-Forwarded-For is read only from these
  initial_admin: alice@example.com        # first admin: OIDC email or local username
  oidc:
    issuer: https://idp.coydog-fence.ts.net
    client_id: vimmary
    client_secret: ""                     # resolved through pkg/secrets
    display_name: Tailscale               # button label
    scopes: [openid, email, profile]
    link_by_email: false                  # migration aid, see below
```

Account policy (who may get an account) is a runtime setting the admin changes
in the app, so it is not part of this file; the app answers it through
`UserResolver`.

### Interface to the app

```go
type Identity struct {
    Method   string // "oidc" | "password"
    Issuer   string // OIDC issuer, empty for password
    Subject  string // OIDC sub or local username
    Email    string
    EmailVerified bool
    Name     string
}

type UserResolver interface {
    // Resolve maps an identity to an app user, creating one if the app's
    // account policy allows it. ErrNoAccount refuses the login.
    Resolve(ctx context.Context, id Identity) (userID int64, err error)
}
```

`auth.Middleware` reads the session cookie or a bearer token and puts the user
ID into the request context; `pkg/mcp` and the app's handlers read it from
there as today. The app calls `auth.DeleteUser(ctx, id)` when it deletes a
user, because `pkg/auth` tables carry no foreign key into app tables (vimmary's
is `users`, labtrak's `app_user`).

### Storage

`pkg/auth` ships its SQL migrations as an `fs.FS`. The app runs them with
`db.RunMigrations` into a separate migrations table (`auth_schema_migrations`),
so they do not interleave with the app's numbering.

| Table | Content |
|---|---|
| `auth_sessions` | SHA-256 of the cookie token, user ID, expiry, last use, client IP, user agent |
| `auth_identities` | `(issuer, subject)` → user ID |
| `auth_passwords` | username, argon2id hash, user ID, failed-attempt counter |
| `auth_oidc_links` | SHA-256 of the link flow's `state`, user ID, expiry (10 min, single use) |
| `auth_tokens` | SHA-256 of the personal access token, user ID, name, scopes, expiry, last use |
| `oauth_clients` | CIMD URL, fetched metadata, cache expiry |
| `oauth_codes` | authorization code hash, client, redirect URI, PKCE challenge, resource, user, expiry |
| `oauth_tokens` | access and refresh token hashes, client, user, resource, scope, expiry, revocation |

### Sessions and CSRF

- Opaque 32-byte random token in a `__Host-` cookie: `Secure`, `HttpOnly`,
  `SameSite=Lax`. Only its hash is stored.
- State-changing requests with a session cookie must carry an `Origin` equal to
  `base_url`; anything else answers 403.
- `POST /auth/logout` deletes the session row. The app lists a user's sessions
  and revokes them through `pkg/auth` functions.

### Local passwords

- argon2id; minimum length 12; no composition rules.
- Rate limit per username and per client IP; the IP comes from
  `X-Forwarded-For` only when the peer is in `trusted_proxies`.
- No e-mail flow. An admin sets a new password; a user changes their own.
- The first admin is created by the CLI subcommand the app wires
  (`vimmary auth create-user --admin <name>`), or, for OIDC, by the first login
  whose email matches `initial_admin`. The first visitor never becomes admin.

### OIDC client

- `coreos/go-oidc` and `golang.org/x/oauth2`; authorization code flow with PKCE
  (S256), `state` and `nonce`.
- The account key is `(issuer, sub)`. Email is used only for display and for
  `link_by_email`.
- `link_by_email: true` links a first OIDC login to an existing app user whose
  login equals the `email` claim and who has no identity yet. It exists to
  carry over the users created by `WhoIs`; it is switched off after migration.
  It applies only to the configured issuer and does not require
  `email_verified`, because tsidp does not send that claim.
- tsidp claims: `sub` is the Tailscale user ID; `email` is the Tailscale login
  name, except that logins ending in `@github` or `@passkey` get the tsidp
  hostname appended (`alice@github.idp`). Such a user does not match its
  `WhoIs` login and is linked by hand.

Endpoints: `GET /auth/methods`, `POST /auth/login`, `GET /auth/oidc/start`,
`GET /auth/oidc/callback`, `POST /auth/logout`, `GET /auth/me`.

### OAuth authorization server and resource server for MCP

Spec: MCP authorization, revision 2026-07-28.

- `GET /.well-known/oauth-protected-resource` and
  `/.well-known/oauth-protected-resource/mcp` (RFC 9728): `resource` is
  `base_url`, `authorization_servers` is `[base_url]`.
- `GET /.well-known/oauth-authorization-server` (RFC 8414): `issuer` identical
  to `base_url`; `code_challenge_methods_supported: ["S256"]`;
  `client_id_metadata_document_supported: true`;
  `authorization_response_iss_parameter_supported: true`;
  `scopes_supported: ["mcp"]`.
- `GET /oauth/authorize`: without a session, redirect to the app's login page;
  with one, redirect to the app's consent page, which shows the client name and
  the redirect host and posts the decision back. The response carries `iss`
  (RFC 9207).
- `POST /oauth/token`: `authorization_code` (PKCE S256 required, `resource`
  must equal `base_url`) and `refresh_token` (rotated on every use).
- CIMD fetch: `https` only, no private or loopback address after DNS
  resolution, 5 s timeout, 64 KiB limit, cached by HTTP cache headers;
  `client_id` in the document must equal the URL; redirect URIs must be listed
  in the document.
- Tokens are opaque and stored hashed. Access token 1 h (spec: SHOULD be
  short-lived), refresh token 30 days and rotated on every use (spec: MUST for
  public clients).
- Redirect URIs match exactly against the metadata document and are `https` or
  `localhost` (spec: MUST). For a client whose redirect URIs are all
  `localhost`, the consent page shows a warning and the hostname (spec: MUST
  display the hostname).
- `/mcp` without a valid token answers 401 with
  `WWW-Authenticate: Bearer resource_metadata="<base_url>/.well-known/oauth-protected-resource"`.
  A token whose resource is not `base_url` is rejected (spec: MUST).
- The app shows connected clients per user and revokes them through `pkg/auth`.

### Personal access tokens

- Created by a user in the app (`CreateToken`), shown once, stored as SHA-256 of
  32 random bytes, with a name, an optional expiry and scopes `mcp`, `api`;
  listed and revoked through `ListTokens`, `RevokeToken`; deleted by
  `DeleteUser`.
- Accepted as `Authorization: Bearer` on `/mcp` and the REST API, mapped to the
  user who created it. Issued by the app for the app, so the spec's audience
  rule holds.
- Format `<prefix>_pat_<random>`, prefix from `auth.token_prefix` or
  `WithTokenPrefix`, so a leaked token is recognisable in logs and secret
  scanners.
- A bearer request needs no `Origin`, because a browser does not attach the
  header on its own. An invalid, expired or revoked token answers 401 with
  `WWW-Authenticate: Bearer error="invalid_token"` and does not reach the
  fallback; a token without the scope that `WithScope` requires answers 403.
- A session satisfies `api` and not `mcp`. `/mcp` therefore accepts only
  tokens: the browser UI does not call it, and an MCP grant stays an explicit
  act of the user (a token now, OAuth consent from v0.5.0).

### Tailnet switch, considered

Three mechanisms tell an inbound tailnet connection apart:

| Mechanism | Identity | Condition |
|---|---|---|
| Separate tsnet listener | `WhoIs`, users and tagged nodes | tsnet stays in the process, with its startup order |
| `tailscale serve` (host or sidecar) on a dedicated backend port | `Tailscale-User-Login` for users; `Tailscale-App-Capabilities` with `--accept-app-caps` (≥ 1.92) for users and tagged nodes | the port is reachable only from Serve; Serve strips client-supplied copies of these headers |
| Peer address in `100.64.0.0/10` plus `WhoIs` over the host's `tailscaled` socket | users and tagged nodes | the app sees the real peer address or a trusted `X-Forwarded-For` |

The Serve variant needs no tsnet in the process and is the one to build if a
switch is wanted later: a second listener whose middleware reads only the
Serve headers, while the public listener ignores them. Identity headers are not
set for tagged nodes, so a tagged caller needs an app-capability grant; a grant
with a tag as `src` is not shown in Tailscale's examples and has to be tested.

### Changes elsewhere in meltkit

- `pkg/server.SetMCPWithAuth` mounts `/mcp` behind a given middleware;
  `SetMCP` keeps `IdentityMiddleware`. From v0.5.0 the well-known paths are
  mounted beside `/mcp`.
- Removed after every consumer has migrated: `middleware.TailscaleIdentity`,
  `middleware.DevIdentity`, `server.SetTailscale`,
  `server.IdentityMiddleware`, `config.TailscaleConfig`. Local development uses
  a password account.

### Releases

| Version | Content | Breaking |
|---|---|---|
| v0.3.0 | sessions, passwords, OIDC client, middleware, migrations | no |
| v0.4.0 | personal access tokens; bearer and scopes in `Middleware`; `SetMCPWithAuth` | no |
| v0.5.0 | OAuth authorization and resource server for MCP | no |
| v0.6.0 | Tailscale identity, `SetTailscale`, `TailscaleConfig` removed | yes |

Tests: `httptest` against an in-process OIDC provider and full OAuth flows
(PKCE mismatch, wrong resource, replayed code, rotated refresh token, CIMD
redirect mismatch, SSRF targets). A security review runs before v0.5.0.

## vimmary

### R1 — login (meltkit v0.3.0), `WhoIs` still accepted

1. Migration: `users.is_admin`, set for the row `GetPrimaryUser` returns today.
   Admin checks read `is_admin`; `GetPrimaryUser` stays only where a background
   job needs a single owner. A password username without `@` would otherwise
   never be admin, because the current rule is `login LIKE '%@%'`.
2. `UserResolver`: account policy as an admin setting in `app_settings` —
   `closed` (admin creates accounts), `oidc_auto` (first OIDC login creates the
   account), optional email-domain allowlist for `oidc_auto`.
3. Admin user management in Settings: list, create password user, reset
   password, disable, delete.
4. Frontend: `/login` (buttons per enabled method), 401 in `web/src/api.ts`
   redirects to `/login?next=…`, logout, own sessions in Settings,
   `IdentitySection` shows the login method.
5. Middleware order: session first, `WhoIs` as fallback. `link_by_email` on for
   tsidp.

### R2 — tokens (meltkit v0.4.0), MCP OAuth (meltkit v0.5.0)

1. `/mcp` requires a bearer token (personal access token, OAuth from v0.5.0);
   stdio mode keeps user 1.
2. Personal access tokens in Settings; consent page and connected clients with
   v0.5.0.
3. Before `WhoIs` stops being accepted for `/mcp`, every machine client carries
   a token (see *Homelab*).

### R3 — tsnet removed (meltkit v0.6.0)

1. `startTailscale`, the tsnet branch of `openListener`, `tsnetHTTPClient` and
   the loopback health listener are removed; `/healthz` is served on the main
   port and the `Dockerfile` `HEALTHCHECK` targets it.
2. Outbound clients for cast2md, Aperture and the embedder use the default
   transport.
3. `compose.example.yml` gains Caddy with automatic TLS; vimmary listens only on
   the compose network.
4. `CLAUDE.md` gotchas on tsnet, the health listener and "admin is the primary
   user" are rewritten.

### Homelab (operator decisions, made in `meltforce.net/homelab`)

Machine clients that reach vimmary through `WhoIs` today, found in
`homelab`, `juno` and `tsmcp` (the request logs on smokey were not checked):

| Client | Today | After R2 |
|---|---|---|
| tsmcp `/mcp/vimmary` (claude.ai connector) | tagged node → primary user | personal access token of the primary user through `upstream_token_env`, setec `public-cloud/tsmcp-vimmary-token` (`docs/tsmcp.md` step 3) |
| juno master session (`mcp-wiring`, `mcp_catalog.vimmary`) | tagged node → primary user | `auth: bearer`, token in setec |
| juno media specialist (`juno/specialists/media/.mcp.json`) | tagged node → primary user | `headers.Authorization` from the same secret |
| Uptime Kuma and CI deploy gate (`/version`) | unauthenticated | unchanged |

tsmcp keeps its Keycloak login for claude.ai; vimmary sees only the token, so
every member of group `mcp` still reads the primary user's data, as today.

- **Reachability of the instance**: decided, see *Decisions*.
- **tsidp client**: created with the `tsidp-client` skill; the secret goes to
  setec.
- tsidp is tailnet-only: the browser that logs in and the vimmary host both need
  tailnet access, also for a public instance.

## labtrak and nutrak

They adopt v0.6.0 after vimmary R3, each with its own plan for mapping
`Identity` onto its `Principal`.

## Open questions

- vimmary's request logs on smokey for REST calls from non-browser clients:
  the repositories show none, the logs were not read.
