// Nest/Fastify adapter. Mirrors the SvelteKit adapter's semantics (see sveltekit.ts) for services
// that run on Nest + Fastify rather than SvelteKit.
//
// Deliberately framework-light: nothing here imports @nestjs/* or fastify, so the package gains no
// dependencies and stays usable from a plain Fastify app or any handler that can produce the small
// `HeaderCarrier` shape below. The consuming service supplies the Nest plumbing (guard class,
// DI token, exception type) — this module supplies the Accounts logic.
//
// Added 0.1.0; non-breaking (new entry point, existing exports untouched).

import { createHash } from 'node:crypto';
import {
	createAccessTokenVerifier,
	looksLikeJwt,
	type AccessTokenVerifier,
	type AccessTokenVerifierOptions,
	introspectServiceKey,
	normalizeAccountsWebhook,
	scopeSatisfied,
	serviceKeyFromRequest,
	verifyWebhookSignature,
	type AccountsClientConfig,
	type AccountsWebhookEvent,
	type ServiceKeyContext
} from './index.js';

/**
 * The minimum a request must expose. Fastify's `request` satisfies this as-is
 * (`headers` is a plain object), as does Node's IncomingMessage.
 */
export type HeaderCarrier = {
	headers: Record<string, string | string[] | undefined>;
};

/** Read a possibly-repeated header as a single value. */
function headerValue(carrier: HeaderCarrier, name: string): string | undefined {
	const v = carrier.headers[name] ?? carrier.headers[name.toLowerCase()];
	return Array.isArray(v) ? v[0] : v;
}

/**
 * Adapt a header-bearing request to the web `Request` that the core helpers expect.
 * Only headers are needed — `serviceKeyFromRequest` reads `x-api-key` / `authorization`.
 */
export function toWebRequest(carrier: HeaderCarrier): Request {
	const headers = new Headers();
	for (const [k, v] of Object.entries(carrier.headers)) {
		if (v === undefined) continue;
		if (Array.isArray(v)) {
			for (const item of v) headers.append(k, item);
		} else {
			headers.set(k, v);
		}
	}
	// URL is irrelevant to the helpers but `Request` requires one.
	return new Request('http://localhost/', { headers });
}

/** Extract an `sk_` service key from a Fastify/Node request, or null when absent. */
export function serviceKeyFromHeaders(carrier: HeaderCarrier): string | null {
	return serviceKeyFromRequest(toWebRequest(carrier));
}

// ── Service-key resolver ─────────────────────────────────────────────────────────
// Same contract as createServiceKeyHandle: absent key → null (let other auth apply);
// present-but-invalid → the caller decides (typically 401). Introspection is cached by
// sha256 of the key so a hot path doesn't hit Accounts on every request.

export type ServiceKeyResolverOptions = {
	config: Pick<AccountsClientConfig, 'baseUrl'>;
	fetchImpl?: typeof fetch;
	/** Introspection cache TTL in ms. Default 60_000; 0 disables caching. */
	cacheTtlMs?: number;
};

export type ServiceKeyResolution =
	| { status: 'absent' }
	| { status: 'invalid' }
	| { status: 'ok'; context: ServiceKeyContext };

export function createServiceKeyResolver(opts: ServiceKeyResolverOptions) {
	const ttl = opts.cacheTtlMs ?? 60_000;
	const cache = new Map<string, { value: ServiceKeyContext | null; expires: number }>();

	async function resolve(carrier: HeaderCarrier): Promise<ServiceKeyResolution> {
		const key = serviceKeyFromHeaders(carrier);
		if (!key) return { status: 'absent' };

		const hash = createHash('sha256').update(key).digest('hex');
		const now = Date.now();

		let ctx: ServiceKeyContext | null;
		const cached = ttl > 0 ? cache.get(hash) : undefined;
		if (cached && cached.expires > now) {
			ctx = cached.value;
		} else {
			ctx = await introspectServiceKey({ config: opts.config, key, fetchImpl: opts.fetchImpl });
			// Negative results are cached too, so a bad key can't hammer Accounts.
			if (ttl > 0) cache.set(hash, { value: ctx, expires: now + ttl });
		}

		return ctx ? { status: 'ok', context: ctx } : { status: 'invalid' };
	}

	/** Drop a cached introspection (e.g. after a key is revoked upstream). */
	function invalidate(key: string): void {
		cache.delete(createHash('sha256').update(key).digest('hex'));
	}

	return { resolve, invalidate };
}

// ── User-session resolver ────────────────────────────────────────────────────────
// A service that receives an Accounts access token (rather than holding its own signed cookie, as
// the SvelteKit adapter does) verifies it. Since 0.12.0 access tokens are RS256 JWTs, verified
// locally against the Accounts JWKS: no round trip. `aud` names the app the token was issued for,
// `tid` the tenant, `sid` the Accounts session. If the JWKS cannot be reached, Accounts' userinfo
// endpoint vouches for the token instead. An opaque (non-JWT) bearer is a pre-0.12 session id and
// is checked with the legacy `GET /api/auth/me` while `legacySessionTokens` is on.

export type UserSessionContext = {
	userId: string;
	email?: string;
	name?: string;
	/** Accounts session id (`sid`). Empty when the token carries none. */
	sessionId: string;
	/** The app (client id) the token was issued for: the JWT `aud`. */
	appId: string | null;
	tenantId: string | null;
	expiresAt?: string;
	/** Scopes granted to the token (JWT `scope`). Added 0.12.0. */
	scopes?: string[];
	/** How the token was checked. Added 0.12.0. */
	verifiedBy?: 'jwks' | 'userinfo' | 'legacy-me';
};

export type UserSessionResolverOptions = {
	/** `baseUrl` is the Accounts origin; `issuer` defaults to it. */
	config: Pick<AccountsClientConfig, 'baseUrl'> & Partial<Pick<AccountsClientConfig, 'issuer' | 'discovery'>>;
	fetchImpl?: typeof fetch;
	/** Cache TTL in ms. Default 60_000; 0 disables caching. Never outlives the token's exp. */
	cacheTtlMs?: number;
	/**
	 * Accept only tokens issued to these client ids (`aud`). Strongly recommended: without it a
	 * token issued to ANY Nipate app is accepted and the caller must check `appId` itself.
	 */
	audience?: string | readonly string[];
	/** Ask userinfo when the JWKS is unreachable. Default true. */
	remoteFallback?: boolean;
	/** Check opaque (pre-JWT) bearers via GET /api/auth/me. Default true; turn off once Accounts issues JWTs. */
	legacySessionTokens?: boolean;
	/** Extra verifier options (endpoints, clock tolerance, JWKS cache TTL/cooldown, clock). */
	verifier?: Partial<Omit<AccessTokenVerifierOptions, 'issuer' | 'audience' | 'fetchImpl'>>;
};

type MeResponse = {
	user?: { id?: string; emailAddress?: string; email?: string; name?: string };
	session?: { id?: string; appId?: string | null; tenantId?: string | null; expiresAt?: string };
};

/** A session bearer is any Authorization: Bearer token that is NOT an `sk_` service key. */
export function sessionTokenFromHeaders(carrier: HeaderCarrier): string | null {
	const auth = headerValue(carrier, 'authorization');
	if (!auth || !auth.startsWith('Bearer ')) return null;
	const token = auth.slice(7).trim();
	if (!token || token.startsWith('sk_')) return null;
	return token;
}

export function createUserSessionResolver(opts: UserSessionResolverOptions) {
	const ttl = opts.cacheTtlMs ?? 60_000;
	const cache = new Map<string, { value: UserSessionContext | null; expires: number }>();
	const fetchImpl = opts.fetchImpl ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
	const base = opts.config.baseUrl?.trim().replace(/\/$/, '');
	const issuer = (opts.config.issuer ?? base)?.trim();
	const legacy = opts.legacySessionTokens ?? true;
	let verifier: AccessTokenVerifier | null = null;
	if (issuer) {
		verifier = createAccessTokenVerifier({
			discovery: opts.config.discovery,
			...opts.verifier,
			issuer,
			audience: opts.audience,
			remoteFallback: opts.remoteFallback ?? true,
			fetchImpl
		});
	}

	async function viaJwt(token: string): Promise<UserSessionContext | null> {
		if (!verifier) return null;
		try {
			const { claims, verifiedBy } = await verifier.verify(token);
			const aud = Array.isArray(claims.aud) ? claims.aud[0] : claims.aud;
			return {
				userId: claims.sub,
				email: typeof claims.email === 'string' ? claims.email : undefined,
				name: typeof claims.name === 'string' ? claims.name : undefined,
				sessionId: claims.sid ?? '',
				appId: aud ?? null,
				tenantId: claims.tid ?? null,
				expiresAt: new Date(claims.exp * 1000).toISOString(),
				scopes: claims.scope ? claims.scope.split(' ').filter(Boolean) : [],
				verifiedBy
			};
		} catch {
			// Invalid, expired, wrong audience, or Accounts unreachable: "not authenticated".
			return null;
		}
	}

	async function viaLegacyMe(token: string): Promise<UserSessionContext | null> {
		if (!base || !token) return null;
		try {
			const res = await fetchImpl(new URL('/api/auth/me', base), {
				headers: { authorization: `Bearer ${token}`, accept: 'application/json' }
			});
			if (!res.ok) return null;
			const data = (await res.json()) as MeResponse;
			const userId = data.user?.id;
			const sessionId = data.session?.id;
			if (!userId || !sessionId) return null;
			const appId = data.session?.appId ?? null;
			const allowed = opts.audience === undefined ? null : typeof opts.audience === 'string' ? [opts.audience] : opts.audience;
			if (allowed && (!appId || !allowed.includes(appId))) return null;
			return {
				userId,
				email: data.user?.emailAddress ?? data.user?.email,
				name: data.user?.name,
				sessionId,
				appId,
				tenantId: data.session?.tenantId ?? null,
				expiresAt: data.session?.expiresAt,
				verifiedBy: 'legacy-me'
			};
		} catch {
			// Transport failure is indistinguishable from an invalid token to the caller: both are
			// "not authenticated". Never throw — a flaky Accounts must not 500 the consuming service.
			return null;
		}
	}

	async function introspect(token: string): Promise<UserSessionContext | null> {
		if (looksLikeJwt(token)) return viaJwt(token);
		return legacy ? viaLegacyMe(token) : null;
	}

	async function resolve(carrier: HeaderCarrier): Promise<UserSessionContext | null> {
		const token = sessionTokenFromHeaders(carrier);
		if (!token) return null;

		const hash = createHash('sha256').update(token).digest('hex');
		const now = Date.now();
		const cached = ttl > 0 ? cache.get(hash) : undefined;
		if (cached && cached.expires > now) return cached.value;

		const ctx = await introspect(token);
		if (ttl > 0) {
			const exp = ctx?.expiresAt ? Date.parse(ctx.expiresAt) : Infinity;
			cache.set(hash, { value: ctx, expires: Math.min(now + ttl, exp) });
		}
		return ctx;
	}

	function invalidate(token: string): void {
		cache.delete(createHash('sha256').update(token).digest('hex'));
	}

	return { resolve, invalidate };
}

// ── Authorization helper ─────────────────────────────────────────────────────────

/**
 * Whether a resolved key grants every required scope. Uses the core's `scopeSatisfied`
 * (flat exact match, no wildcards) so behaviour matches Accounts' own enforcement.
 */
export function hasScopes(ctx: ServiceKeyContext, required: readonly string[]): boolean {
	return required.every((scope) => scopeSatisfied(ctx.scopes, scope));
}

/** Whether a resolved key may act on an app, matched by Accounts app id OR slug. */
export function canAccessApp(ctx: ServiceKeyContext, appIdOrSlug: string): boolean {
	return ctx.accessibleApps.some((a) => a.id === appIdOrSlug || a.slug === appIdOrSlug);
}

// ── Accounts webhook receipt (Nest/Fastify) ───────────────────────────────────────
// The SDK owns the security-sensitive parts (signature verification + parsing); the consuming
// service supplies the controller and decides what each event MEANS. Mirrors the SvelteKit
// `createAccountsWebhookHandle` but framework-light: pass the raw body + the signature header value.

export type AccountsWebhookResult =
	| { ok: true; event: AccountsWebhookEvent }
	| { ok: false; reason: 'bad_signature' | 'bad_json' };

/** Header the Accounts webhook worker sends (HMAC-SHA256 hex of the raw body). */
export const ACCOUNTS_WEBHOOK_SIGNATURE_HEADER = 'x-webhook-signature';

/**
 * Verify an Accounts webhook and parse it into a normalized `{ type, data, ... }` event.
 *
 * Pass the RAW request body (a Nest/Fastify controller must read the raw body, not a re-serialized
 * object — the signature is over the exact bytes), the signature header value
 * (`request.headers['x-webhook-signature']`), and the shared secret. Returns `{ok:false}` on a bad
 * signature or unparseable JSON so the controller can 401/400; `{ok:true, event}` otherwise. The
 * controller then reacts to `event.type` / `event.data` and returns 200 (so Accounts doesn't retry).
 */
export function verifyAndParseAccountsWebhook(
	rawBody: string,
	signatureHeaderValue: string | string[] | undefined,
	secret: string
): AccountsWebhookResult {
	const signature = Array.isArray(signatureHeaderValue) ? signatureHeaderValue[0] : signatureHeaderValue;
	if (!verifyWebhookSignature(rawBody, signature ?? null, secret)) {
		return { ok: false, reason: 'bad_signature' };
	}
	try {
		return { ok: true, event: normalizeAccountsWebhook(JSON.parse(rawBody)) };
	} catch {
		return { ok: false, reason: 'bad_json' };
	}
}

// Re-export the shared normalizer so a Nest consumer that parses a dev/unsigned body itself can reuse it.
export { normalizeAccountsWebhook };

export type { ServiceKeyContext, AccountsClientConfig, AccountsWebhookEvent };
