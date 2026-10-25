# @~lyre/auth

Shared **Axis Accounts** auth SDK. A small, framework-agnostic core for session
and identity handling (HMAC-signed cookies, the accounts login → callback →
logout exchange, tenant resolution), plus an optional turnkey **SvelteKit**
adapter that wires it all up in a few lines.

Ships built ESM output from `dist/`, with type declarations.

## Install

```bash
pnpm add @~lyre/auth        # or: npm i / yarn add
```

## Sign in with Nipate Accounts

Since 0.12.0 sign-in follows the Accounts OpenID Connect contract
(`nipate/platform/docs/12-accounts-oidc.md`): authorization code + PKCE S256
for every app, `state` + `nonce`, form-encoded token requests with client
authentication, an RS256 `id_token` verified against the JWKS, and rotating
refresh tokens. No new dependencies: JWT checks use `node:crypto`.

Register the app in Accounts first (client id = app id; exact redirect URIs).
Confidential apps (anything with a server) get a client secret; public apps
(browser-only, CLI) have none and authenticate with `client_id` only.

### SvelteKit

```ts
// src/hooks.server.ts
import { createAccountsClientConfig } from '@~lyre/auth';
import { createAuthHandle } from '@~lyre/auth/sveltekit';

export const handle = createAuthHandle({
  config: createAccountsClientConfig({
    baseUrl: 'https://accounts.nipate.africa',       // ACCOUNTS_BASE_URL (issuer: ACCOUNTS_ISSUER)
    clientId: 'shop',                                 // ACCOUNTS_CLIENT_ID
    clientSecret: process.env.ACCOUNTS_CLIENT_SECRET, // confidential apps only
    redirectUri: 'https://shop.example/auth/callback',
    logoutRedirectUri: 'https://shop.example/'
    // scopes default to: openid profile email offline_access
  }),
  sessionSecret: process.env.SESSION_SECRET,          // signs the session AND the login-state cookie
  endAccountsSession: false,                          // true: logout also ends the Accounts session
  protect: (event) => event.url.pathname.startsWith('/account')
});
```

`/auth/login` stores `state`, `nonce` and the PKCE verifier in a 10-minute
signed httpOnly cookie and redirects to `/auth/authorize`; `/auth/callback`
checks state, exchanges the code, verifies the id_token and writes the app's
own session; requests refresh the access token shortly before it expires
(storing the rotated refresh token; a refused refresh signs the user out);
`/auth/logout` revokes the refresh token. Failures become a 400 naming the
`OidcError` code, or whatever `onAuthError` returns. Mock mode
(`useMock`) keeps the old demo flow for local work without Accounts.

### Plain Node

```ts
import { createOidcClient, isOidcError } from '@~lyre/auth';

const accounts = createOidcClient({
  issuer: 'https://accounts.nipate.africa',
  clientId: 'premail',
  clientSecret: process.env.ACCOUNTS_CLIENT_SECRET, // omit for a public client
  redirectUri: 'https://premail.example/auth/callback',
  postLogoutRedirectUri: 'https://premail.example/',
  discovery: true // optional: read endpoints from /.well-known/openid-configuration (cached)
});

// 1. Start: keep state, nonce and codeVerifier (server-side or in a signed httpOnly cookie).
const login = await accounts.beginLogin();
//    createLoginStateCookie(login, { nextPath, secret }) / readLoginStateCookie(header, { secret })
res.redirect(login.url);

// 2. Callback: throws OidcError with a code (state_mismatch, nonce_mismatch, audience_mismatch,
//    token_expired, token_request_failed + oauthError, …).
const { claims, tokens } = await accounts.handleCallback({ url: req.url, expected: login });
// claims.sub is the user id. Create your own session; store tokens.refreshToken.

// 3. Later
const fresh = await accounts.refresh(tokens.refreshToken!); // ALWAYS store fresh.refreshToken
const { claims: at } = await accounts.verifyAccessToken(fresh.accessToken); // local JWKS check
await accounts.revoke(fresh.refreshToken!);
res.redirect(await accounts.logoutUrl()); // optional: end the Accounts session
```

Services that only receive bearer tokens use `createAccessTokenVerifier({ issuer, audience })`,
or `createUserSessionResolver({ config: { baseUrl }, audience })` from `@~lyre/auth/nest`.
Keys are cached and refetched when a token names an unknown `kid`; if the JWKS
is unreachable, userinfo vouches for the token instead (`remoteFallback`).

**Deprecated in 0.12.0** (still exported; removed in a later major):
`beginAccountsLoginRedirect`, `handleAccountsCallback`, `exchangeAuthorizationCode`,
`logoutFromAccounts`, and the `AuthorizationState` / `AccountsTokenResponse` types.

## App switcher (`<nipate-apps>`), 0.13.0

Every app shows the same apps menu. Accounts serves the web component at
`https://accounts.nipate.africa/embed/apps.js`; the SDK fetches the list server-side with the
user's access token (no CORS, the token never reaches the page):

```ts
// src/routes/+layout.server.ts
import { loadLauncherApps } from '@~lyre/auth/sveltekit';
export const load = async (event) => ({
  launcher: await loadLauncherApps(event, { baseUrl: 'https://accounts.nipate.africa' })
});
```

```svelte
<!-- header -->
<svelte:head><script type="module" src={data.launcher.scriptUrl}></script></svelte:head>
{#if data.launcher.apps.length}<nipate-apps data={data.launcher} label="Nipate apps"></nipate-apps>{/if}
```

Each entry (`LauncherApp`) has `id, slug, name, description, iconUrl, color, launchUrl,
displayOrder, current`; `launchUrl` is the app's `initiate_login_uri`, so opening an app signs the
person in silently through Accounts. Signed out or Accounts unreachable: an empty list, never an
error. Browser-only apps can use `fetchLauncherApps({ baseUrl, accessToken })` from
`@~lyre/auth/launcher` (no Node imports), or give the element `accounts="https://accounts…"` and a
`token` property. Theme with `--nipate-apps-bg`, `-fg`, `-muted`, `-border`, `-accent`, `-hover`,
`-radius`, `-shadow`, `-width`, `-font`, or `::part(button|panel|item|icon|name|description)`.

## Entry points

### `@~lyre/auth` — framework-agnostic core

Session, identity and accounts primitives — usable from any Node runtime:

```ts
import {
  createPlatformAuth,
  beginAccountsLoginRedirect,
  handleAccountsCallback,
  readPlatformSessionCookie,
  clearPlatformSessionCookie,
  resolveActiveTenant,
  syncAccountsUser,
  type PlatformSession,
  type AccountsIdentity,
} from '@~lyre/auth';
```

The core depends only on `node:crypto` and `fetch` — no framework required.

### `@~lyre/auth/sveltekit` — turnkey SvelteKit adapter

A single `handle` that reads the session into `event.locals`, serves
`/auth/login`, `/auth/callback` and `/auth/logout` inline (no route files), and
optionally gates protected paths:

```ts
// src/hooks.server.ts
import { createAuthHandle } from '@~lyre/auth/sveltekit';

export const handle = createAuthHandle({
  // ...SvelteKitAuthOptions
});
```

`@sveltejs/kit` is an **optional peer dependency** — only required if you import
the `/sveltekit` entry.

### `@~lyre/auth/nest` — Nest / Fastify adapter

For services on Nest + Fastify. Adds **no dependencies** — nothing here imports
`@nestjs/*` or `fastify`; you supply the guard class and DI wiring, the SDK
supplies the Accounts logic. Works from a plain Fastify app too: any request
whose `headers` is a plain object satisfies the input type.

```ts
import { createServiceKeyResolver, createUserSessionResolver, hasScopes }
  from '@~lyre/auth/nest';

const keys = createServiceKeyResolver({ config: { baseUrl: ACCOUNTS_BASE_URL } });
const sessions = createUserSessionResolver({
  config: { baseUrl: ACCOUNTS_BASE_URL },
  audience: 'my-app' // accept only tokens issued to these client ids
});

// In a Nest guard (req is the Fastify request):
const key = await keys.resolve(req);
if (key.status === 'invalid') throw new UnauthorizedException();  // present but bad
if (key.status === 'ok') {
  if (!hasScopes(key.context, ['my-app:things:read'])) throw new ForbiddenException();
  // key.context.accessibleApps tells you which apps this key may act on
}

// An access-token bearer resolves to who + which app, verified locally against the JWKS:
const user = await sessions.resolve(req);
// → { userId, sessionId, appId, tenantId, scopes, verifiedBy } | null
```

Semantics match `createServiceKeyHandle`: **absent key → `absent`** (fall through to
other auth), **present-but-invalid → `invalid`** (reject rather than silently
continue). Introspection is cached by `sha256` of the credential — negative
results too, so a bad key can't hammer Accounts. Neither resolver throws: a
transport failure reads as "not authenticated", so a flaky Accounts cannot 500
the consuming service.

JWT bearers are verified locally (`aud` → `appId`, `tid` → `tenantId`, `sid` →
`sessionId`). Opaque pre-JWT session ids still go to the legacy
`GET /api/auth/me` until you pass `legacySessionTokens: false`.

## Publishing

See [PUBLISHING.md](PUBLISHING.md). Published to npm via GitHub Actions Trusted
Publishing on version bump.
