# @~lyre/auth

Shared **Axis Accounts** auth SDK. A small, framework-agnostic core for session
and identity handling (HMAC-signed cookies, the accounts login → callback →
logout exchange, tenant resolution), plus an optional turnkey **SvelteKit**
adapter that wires it all up in a few lines.

Ships as raw TypeScript source.

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

## Publishing

See [PUBLISHING.md](PUBLISHING.md). Published to npm via GitHub Actions Trusted
Publishing on version bump.
