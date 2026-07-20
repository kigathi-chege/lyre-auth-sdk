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
	introspectServiceKey,
	scopeSatisfied,
	serviceKeyFromRequest,
	type AccountsClientConfig,
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
// A service that receives a raw Accounts session bearer (rather than holding its own signed
// cookie, as the SvelteKit adapter does) verifies it by asking Accounts. `GET /api/auth/me`
// returns the user plus `session.appId` / `session.tenantId`, which is what lets a service scope
// a request to (user, app) from the token alone.

export type UserSessionContext = {
	userId: string;
	email?: string;
	name?: string;
	sessionId: string;
	/** The app the session was issued for. Null for sessions created outside an app context. */
	appId: string | null;
	tenantId: string | null;
	expiresAt?: string;
};

export type UserSessionResolverOptions = {
	config: Pick<AccountsClientConfig, 'baseUrl'>;
	fetchImpl?: typeof fetch;
	/** Cache TTL in ms. Default 60_000; 0 disables caching. */
	cacheTtlMs?: number;
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
	const fetchImpl = opts.fetchImpl ?? fetch;

	async function introspect(token: string): Promise<UserSessionContext | null> {
		const base = opts.config.baseUrl?.replace(/\/$/, '');
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
			return {
				userId,
				email: data.user?.emailAddress ?? data.user?.email,
				name: data.user?.name,
				sessionId,
				appId: data.session?.appId ?? null,
				tenantId: data.session?.tenantId ?? null,
				expiresAt: data.session?.expiresAt
			};
		} catch {
			// Transport failure is indistinguishable from an invalid token to the caller: both are
			// "not authenticated". Never throw — a flaky Accounts must not 500 the consuming service.
			return null;
		}
	}

	async function resolve(carrier: HeaderCarrier): Promise<UserSessionContext | null> {
		const token = sessionTokenFromHeaders(carrier);
		if (!token) return null;

		const hash = createHash('sha256').update(token).digest('hex');
		const now = Date.now();
		const cached = ttl > 0 ? cache.get(hash) : undefined;
		if (cached && cached.expires > now) return cached.value;

		const ctx = await introspect(token);
		if (ttl > 0) cache.set(hash, { value: ctx, expires: now + ttl });
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

export type { ServiceKeyContext, AccountsClientConfig };
