// Turnkey SvelteKit adapter for @~lyre/auth. Lets a SvelteKit app wire Axis Accounts
// auth in ~3 lines with no route files: a single `handle` reads the session into
// `event.locals`, serves /auth/login · /auth/callback · /auth/logout inline, and (optionally)
// gates protected paths. Importing this submodule pulls in `@sveltejs/kit`; the core
// entry (`@~lyre/auth`) stays framework-agnostic. Added 0.0.2; non-breaking.
import { createHash } from 'node:crypto';
import { type Handle, type RequestEvent } from '@sveltejs/kit';
import {
	beginAccountsLoginRedirect,
	clearPlatformSessionCookie,
	handleAccountsCallback,
	identityPassthroughSync,
	introspectServiceKey,
	readPlatformSessionCookie,
	serviceKeyFromRequest,
	type AccountsClientConfig,
	type CookieOptions,
	type PlatformSession,
	type ServiceKeyContext,
	type SyncAccountsUser
} from './index';

const STATE_COOKIE = 'accounts_auth_state';

// Build a 302 redirect Response that also sets cookies (the core functions return
// ready-made Set-Cookie strings). Multiple cookies via repeated `set-cookie` headers.
function redirectWithCookies(location: string, cookies: string[]): Response {
	const headers = new Headers({ location });
	for (const c of cookies) if (c) headers.append('set-cookie', c);
	return new Response(null, { status: 302, headers });
}

export type SvelteKitAuthOptions = {
	/** Accounts client config (use createAccountsClientConfig()). */
	config: AccountsClientConfig;
	/** Map an Accounts identity to a local user. Defaults to identity passthrough (no DB). */
	syncAccountsUser?: SyncAccountsUser;
	loginPath?: string;
	callbackPath?: string;
	logoutPath?: string;
	/** Where to send the user after logout. Default '/'. */
	postLogoutPath?: string;
	/**
	 * Return true if THIS request must be authenticated. Unauthenticated page requests are
	 * redirected to the login flow; unauthenticated /api requests get a 401 JSON response.
	 * Omit to leave everything public (session is still read into locals).
	 */
	protect?: (event: RequestEvent) => boolean;
	/**
	 * Cookie attributes for the session + state cookies. Set `{ sameSite: 'none' }` to make
	 * the session usable cross-site (an SDK on another origin calling a protected API).
	 */
	cookieOptions?: CookieOptions;
	/**
	 * HMAC secret. When set, the session cookie is signed on write and verified on read —
	 * unsigned/forged/tampered cookies are rejected (treated as logged out). Strongly
	 * recommended in production, since the session payload includes tenant memberships.
	 */
	sessionSecret?: string;
};

// Apps should augment App.Locals with these. We set them on every request.
export type PlatformLocals = {
	session: PlatformSession;
	principal: PlatformSession['principal'];
};

export function createAuthHandle(opts: SvelteKitAuthOptions): Handle {
	const sync = opts.syncAccountsUser ?? identityPassthroughSync;
	const loginPath = opts.loginPath ?? '/auth/login';
	const callbackPath = opts.callbackPath ?? '/auth/callback';
	const logoutPath = opts.logoutPath ?? '/auth/logout';
	const postLogoutPath = opts.postLogoutPath ?? '/';
	const cookieOptions = opts.cookieOptions;
	const sessionSecret = opts.sessionSecret;

	return async ({ event, resolve }) => {
		const session = readPlatformSessionCookie(event.request.headers.get('cookie'), {
			secret: sessionSecret
		});
		(event.locals as PlatformLocals).session = session;
		(event.locals as PlatformLocals).principal = session.principal;

		const path = event.url.pathname;

		// ── inline auth routes ──
		// We build redirect Responses MANUALLY with Set-Cookie headers (using the cookie
		// strings the core functions return). Setting event.cookies + throwing a redirect
		// from inside `handle` does not reliably flush cookies, so we don't rely on that.
		if (path === loginPath) {
			const next = event.url.searchParams.get('next') ?? '/';
			const flow = beginAccountsLoginRedirect(opts.config, { nextPath: next, cookieOptions });
			return redirectWithCookies(flow.redirectUrl, [flow.stateCookie]);
		}

		if (path === callbackPath) {
			const code = event.url.searchParams.get('code') ?? '';
			const state = event.url.searchParams.get('state') ?? '';
			const storedState = event.cookies.get(STATE_COOKIE);
			const result = await handleAccountsCallback({
				config: opts.config,
				code,
				state,
				storedState,
				syncAccountsUser: sync,
				cookieOptions,
				secret: sessionSecret
			});
			return redirectWithCookies(result.nextPath || '/', [
				result.sessionCookie,
				result.clearStateCookie
			]);
		}

		if (path === logoutPath) {
			return redirectWithCookies(postLogoutPath, [
				clearPlatformSessionCookie(cookieOptions),
				`${STATE_COOKIE}=; ${cookieOptions?.sameSite === 'none' ? 'Path=/; HttpOnly; SameSite=None; Secure' : 'Path=/; HttpOnly; SameSite=Lax'}; Max-Age=0`
			]);
		}

		// ── gate protected paths ──
		if (opts.protect && opts.protect(event) && !session.principal) {
			if (path.startsWith('/api')) {
				return new Response(JSON.stringify({ message: 'Authentication required.' }), {
					status: 401,
					headers: { 'content-type': 'application/json' }
				});
			}
			// RETURN a real 302 Response (not `throw redirect(...)`). When this package is consumed as an
			// externalized dependency, a thrown `redirect()` is a `Redirect` from node_modules' copy of
			// @sveltejs/kit, while the host's bundled kit does the `instanceof Redirect` check against its
			// OWN copy — so the check fails and the redirect is coalesced into a fatal 500. Returning a
			// Response (as the login/callback/logout branches already do) is handled verbatim by the host,
			// so a 302 stays a 302 regardless of bundling.
			return redirectWithCookies(`${loginPath}?next=${encodeURIComponent(path + event.url.search)}`, []);
		}

		return resolve(event);
	};
}

// ── App-scoped API key handle ────────────────────────────────────────────────────
// Turnkey adapter mirroring createAuthHandle, for the machine/SDK auth path. On a matched request
// carrying a service key (`X-API-KEY` or `Authorization: Bearer sk_…`), it introspects the key
// against Axis Accounts and, on success, sets `event.locals.serviceKey` and calls `onResolved` so
// the app can map the grant onto its own locals. A key that is PRESENT but invalid/revoked/expired
// gets a 401 JSON response (a request with no key passes through untouched, so cookie/bearer auth
// still applies). Introspection is cached per key-hash (default 60s). Added 0.0.8; non-breaking.
export type ServiceKeyHandleOptions = {
	config: AccountsClientConfig;
	fetchImpl?: typeof fetch;
	/** Which requests to attempt key auth on. Default: paths starting with `/api`. */
	match?: (event: RequestEvent) => boolean;
	/** Introspection cache TTL in ms. Default 60_000; set 0 to disable caching. */
	cacheTtlMs?: number;
	/** Map the resolved key grant onto app locals. Called only for a valid key. */
	onResolved?: (event: RequestEvent, ctx: ServiceKeyContext) => void;
	/** Observe a present-but-invalid key (e.g. logging) before the 401 is returned. */
	onInvalid?: (event: RequestEvent) => void;
};

// Apps consuming service keys should augment App.Locals with this.
export type ServiceKeyLocals = { serviceKey?: ServiceKeyContext | null };

export function createServiceKeyHandle(opts: ServiceKeyHandleOptions): Handle {
	const match = opts.match ?? ((event: RequestEvent) => event.url.pathname.startsWith('/api'));
	const ttl = opts.cacheTtlMs ?? 60_000;
	const cache = new Map<string, { value: ServiceKeyContext | null; expires: number }>();

	return async ({ event, resolve }) => {
		if (!match(event)) return resolve(event);
		const key = serviceKeyFromRequest(event.request);
		if (!key) return resolve(event);

		const hash = createHash('sha256').update(key).digest('hex');
		const now = Date.now();
		let ctx: ServiceKeyContext | null;
		const cached = ttl > 0 ? cache.get(hash) : undefined;
		if (cached && cached.expires > now) {
			ctx = cached.value;
		} else {
			ctx = await introspectServiceKey({ config: opts.config, key, fetchImpl: opts.fetchImpl });
			if (ttl > 0) cache.set(hash, { value: ctx, expires: now + ttl });
		}

		if (ctx) {
			(event.locals as ServiceKeyLocals).serviceKey = ctx;
			opts.onResolved?.(event, ctx);
			return resolve(event);
		}

		// A key was presented but did not resolve — reject rather than silently fall through.
		opts.onInvalid?.(event);
		return new Response(JSON.stringify({ message: 'Invalid or expired API key.' }), {
			status: 401,
			headers: { 'content-type': 'application/json' }
		});
	};
}

export { clearPlatformSessionCookie };
