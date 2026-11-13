# How-to: move an app from tsnet identity to `pkg/auth`

For an app that today is its own tsnet node and identifies callers by
`WhoIs` (vimmary, labtrak, nutrak). The result: the app logs users in itself
(`pkg/auth`), machine clients send personal access tokens, and the app is
reached as `<app>.meltrocker.net` through the ingress on its host. vimmary
is the reference implementation: `f8dcfea` login, `154839d` tokens,
`166f144` login redirect.

Design and reasons: `auth-plan.md`. Deployment: homelab
`docs/tsnet-app-to-ingress.md`.

## 0. Decide per app

| Question | vimmary's answer |
|---|---|
| Login methods | `oidc` (tsidp) only |
| Account policy for unknown OIDC logins | `closed` (admin creates) or `oidc_auto` with a domain allowlist; admin setting at runtime |
| Who calls the app without a browser | tsmcp, juno and juno's media specialist (MCP); Karakeep (webhook); FreshRSS (feeds); CI deploy gate; Uptime Kuma |
| Egress identity for tailnet services | the host's (smokey); grants that named the app's own tag move to the host |
| Data keyed by tailnet facts | none; nutrak keys households by tailnet (see § 6) |

## 1. Code, inert by default

Every push to `main` deploys, so each step below changes nothing until the
config carries an `auth:` block.

1. `go get github.com/meltforce/meltkit@<version>` (v0.3.0 login, v0.4.0
   tokens).
2. Config: embed `*auth.Config` as `auth:`; nil means off. Resolve
   `oidc_client_secret` through the existing secrets resolver
   (`<APP>_OIDC_CLIENT_SECRET`).
3. Migrations: `auth.RunMigrations(dsn)` right after the app's own; it keeps
   its own version table. Run it with or without `auth:`.
4. Build `auth.New(...)` after the service and before the router. No network
   request at startup: OIDC discovery is lazy.

## 2. Users

1. Migration: `is_admin`, `disabled_at` on the user table; set `is_admin` for
   whoever the app treats as owner today. labtrak already has `is_admin`.
2. Implement `auth.UserResolver` and `auth.LoginLookup` in the service layer:
   - a linked identity (`id.UserID != 0`): refuse disabled users with
     `auth.ErrNoAccount`, else return the ID;
   - a first OIDC login: apply the account policy, create the user with
     `login` = email, make it admin through `IsInitialAdmin` only while no
     admin exists;
   - `UserIDByLogin` matches the column that holds the `WhoIs` login today;
     with `link_by_email: true` this carries existing users over, because
     tsidp's `email` is the Tailscale login name.
3. Admin checks read `is_admin`. Without `auth:`, keep the old rule.
   Disabling a user revokes their sessions and tokens: the bearer path does
   not ask the resolver.
4. Logins on `@github`/`@passkey` do not match (tsidp appends its hostname);
   such a user links through `StartOIDCLink` from an authenticated route.
5. CLI subcommands: `<app> auth create-user [--admin] <name>` (password from
   stdin) for instances without OIDC, and `<app> auth create-token --user
   <login> --name <name> --scope mcp [--scope api] [--expires 90d]`, which
   prints only the token on stdout. Machine-client tokens belong to the admin
   user, which is whom tagged nodes resolved to over `WhoIs`.

## 3. Request authentication

1. The protected group uses
   `a.Middleware(auth.WithFallback(<WhoIs middleware>))` while tsnet still
   serves. Install the fallback only when tsnet runs: off the tailnet,
   meltkit's identity middleware is `DevIdentity` (user 1) and would bypass
   login. labtrak and nutrak: build their `Principal` from the user ID the
   middleware sets; act-as stays as it is.
2. Mount `/auth/*` outside the protected group.
3. Browser routes that answer a redirect (share-sheet targets) send an
   unauthenticated request to `/login?next=…`; JSON routes answer 401.
4. `/mcp`: `SetMCPWithAuth(mcpSrv, injector, a.Middleware(auth.WithScope(auth.ScopeMCP), auth.WithFallback(<WhoIs>)))`,
   the fallback again only while tsnet runs. A session does not satisfy
   `mcp`. A request with a bearer header never reaches the `WhoIs` fallback,
   so a machine client gets its token only when the app accepts it.
5. The protected REST group requires `auth.ScopeAPI`; a session satisfies
   it, an `mcp`-only token gets 403.
6. Refuse every bearer request of a disabled user, on `/mcp` and REST, even
   though disabling revokes the tokens: the revocation can fail.
7. A token-authenticated request cannot create a token (403): an `api` token
   could otherwise mint an `mcp` token or outlive its own revocation. Listing
   and revoking stay allowed.
8. Token requests carry an empty `UserInfo`; read login and display name from
   the user table.

## 4. Frontend

- `/login`: one button per method from `GET /auth/methods`, password form,
  `?error=` codes as text.
- With OIDC as the only method, `/login` redirects to its `start_url` with
  `next` at once. It stays on the page when `?error=` is set (a refusal would
  loop) and on `?signed_out=1`, where sign-out lands: tsidp signs a known
  browser back in without asking, so sign-out would otherwise undo itself.
- API client: 401 → `/login?next=<current path>`.
- Settings, own account: sessions (revoke), linked identities (link, unlink
  while another login remains), password, tokens (name, scopes, expiry;
  plaintext shown once with a copy button; revoke; list with last use).
- Settings, admin: users (create, reset password, disable, admin flag),
  account policy.

## 5. Tests

- Resolver: linked, disabled, unknown with each policy, admin bootstrap,
  `link_by_email` hit and miss.
- Middleware matrix: with/without `auth:` × tsnet on/off; disabled user over
  `WhoIs` → 403; `auth:` without tsnet → 401.
- Tokens: `mcp` token on `/mcp` 200 and on REST 403; `api` token the
  reverse; session cookie on `/mcp` 401; unknown token 401 even with tsnet
  running; disabled user's token 403.
- End to end against a throwaway Postgres: password login, 401 redirect,
  logout, admin pages, a CLI token on `/mcp` (`initialize`, one tool call),
  a token created and revoked in the UI; and one run without `auth:` against
  the same database.
- Migration against a copy of the production schema.

## 6. App-specific points

- **nutrak** keys households by tailnet (`extractTailnet`). `auth.Identity`
  carries no tailnet. tsidp emits a `tailnet` claim; decide before migrating
  whether `pkg/auth` passes extra claims through or households get assigned
  another way.
- **labtrak** seeds the admin by a hardcoded login (migration `000004`);
  `link_by_email` keeps it.
- Both resolve tagged nodes to the primary user over `WhoIs`; after the move
  those callers need tokens.

## 7. Deployment (homelab)

Order, traps and checks for the switch are in homelab
`docs/tsnet-app-to-ingress.md`. The app-side prerequisite is § 1–4 released
and running on tsnet, so that `/mcp`, webhooks and feeds work with login
configured and tsnet off.
