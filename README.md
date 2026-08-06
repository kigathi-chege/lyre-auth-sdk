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

The core depends only on `node:crypto` — no framework required.

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
const sessions = createUserSessionResolver({ config: { baseUrl: ACCOUNTS_BASE_URL } });

// In a Nest guard (req is the Fastify request):
const key = await keys.resolve(req);
if (key.status === 'invalid') throw new UnauthorizedException();  // present but bad
if (key.status === 'ok') {
  if (!hasScopes(key.context, ['my-app:things:read'])) throw new ForbiddenException();
  // key.context.accessibleApps tells you which apps this key may act on
}

// A user session bearer resolves to who + which app, from the token alone:
const user = await sessions.resolve(req);
// → { userId, sessionId, appId, tenantId, email, name } | null
```

Semantics match `createServiceKeyHandle`: **absent key → `absent`** (fall through to
other auth), **present-but-invalid → `invalid`** (reject rather than silently
continue). Introspection is cached by `sha256` of the credential — negative
results too, so a bad key can't hammer Accounts. Neither resolver throws: a
transport failure reads as "not authenticated", so a flaky Accounts cannot 500
the consuming service.

`resolve()` needs `GET /api/auth/me` to return `session.appId` (Accounts ≥ the
release that added it); older deployments yield `appId: null`.

## Publishing

See [PUBLISHING.md](PUBLISHING.md). Published to npm via GitHub Actions Trusted
Publishing on version bump.
