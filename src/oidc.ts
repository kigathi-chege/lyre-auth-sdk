// OpenID Connect client for Nipate Accounts (contract: nipate/platform docs/12-accounts-oidc.md).
//
// Authorization code + PKCE (S256, always), nonce + state, form-encoded token requests with
// client_secret_basic / client_secret_post / none, RS256 id_token and access-token verification
// against the JWKS (keys cached, refetched on an unknown kid), refresh-token rotation, revocation
// and the sign-out URL. Depends only on `node:crypto` and the global `fetch`. Added 0.12.0.

import {
	createHash,
	createPublicKey,
	randomBytes,
	timingSafeEqual,
	verify as cryptoVerify,
	type JsonWebKey as NodeJsonWebKey,
	type KeyObject
} from 'node:crypto';

// ── Errors ───────────────────────────────────────────────────────────────────────

export type OidcErrorCode =
	/** Client misconfiguration (e.g. client_secret_basic without a secret). */
	| 'invalid_config'
	/** Callback `state` missing or not the one this app sent (possible CSRF). */
	| 'state_mismatch'
	/** Accounts redirected back with `?error=…` (e.g. access_denied). */
	| 'authorization_error'
	/** Callback carried no `code`. */
	| 'missing_code'
	/** Callback `iss` parameter (RFC 9207) is not our issuer. */
	| 'issuer_mismatch'
	/** Discovery document unreachable or invalid. */
	| 'discovery_failed'
	/** JWKS unreachable or invalid. */
	| 'jwks_fetch_failed'
	/** fetch() itself failed (DNS, connection refused, …). */
	| 'network_error'
	/** Token endpoint answered non-2xx (see `oauthError`, e.g. invalid_grant, invalid_client). */
	| 'token_request_failed'
	/** Token endpoint answered 2xx with an unusable body. */
	| 'invalid_token_response'
	/** `openid` was requested but no id_token came back. */
	| 'missing_id_token'
	/** Not a well-formed compact JWS. */
	| 'invalid_jwt'
	/** Header alg is not RS256 (blocks `none`, HS256 key confusion, …). */
	| 'unsupported_alg'
	/** No JWKS key matches the token's `kid`, even after a refetch. */
	| 'unknown_kid'
	| 'invalid_signature'
	| 'audience_mismatch'
	| 'token_expired'
	| 'token_not_yet_valid'
	| 'nonce_mismatch'
	/** A token that is not an access token (e.g. an id_token) was presented as one. */
	| 'wrong_token_type'
	/** userinfo answered non-2xx, or its `sub` disagrees with the token. */
	| 'userinfo_failed'
	| 'revocation_failed';

export class OidcError extends Error {
	readonly code: OidcErrorCode;
	/** HTTP status from Accounts, when the failure was an HTTP response. */
	readonly status?: number;
	/** OAuth `error` field (`invalid_grant`, `invalid_client`, `access_denied`, …). */
	readonly oauthError?: string;
	readonly oauthErrorDescription?: string;

	constructor(
		code: OidcErrorCode,
		message: string,
		details: { status?: number; oauthError?: string; oauthErrorDescription?: string; cause?: unknown } = {}
	) {
		super(message, details.cause === undefined ? undefined : { cause: details.cause });
		this.name = 'OidcError';
		this.code = code;
		this.status = details.status;
		this.oauthError = details.oauthError;
		this.oauthErrorDescription = details.oauthErrorDescription;
	}
}

export function isOidcError(error: unknown, code?: OidcErrorCode): error is OidcError {
	return error instanceof OidcError && (code === undefined || error.code === code);
}

// ── Types ────────────────────────────────────────────────────────────────────────

export type OidcEndpoints = {
	authorization: string;
	token: string;
	userinfo: string;
	jwks: string;
	revocation: string;
	endSession: string;
};

/** Paths fixed by the contract, resolved against the issuer when discovery is off. */
export const ACCOUNTS_ENDPOINT_PATHS: Readonly<OidcEndpoints> = Object.freeze({
	authorization: '/auth/authorize',
	token: '/api/auth/token',
	userinfo: '/api/auth/userinfo',
	jwks: '/api/.well-known/jwks.json',
	revocation: '/api/auth/revoke',
	endSession: '/auth/logout'
});

export const DEFAULT_OIDC_SCOPES = ['openid', 'profile', 'email', 'offline_access'] as const;

export type TokenEndpointAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'none';

type CommonVerifierOptions = {
	/** Issuer, e.g. `https://accounts.nipate.africa`. Tokens must carry exactly this `iss`. */
	issuer: string;
	/** Load endpoints from `/.well-known/openid-configuration` (cached). Default false: contract paths. */
	discovery?: boolean;
	/** Override individual endpoints (absolute URLs or paths relative to the issuer). */
	endpoints?: Partial<OidcEndpoints>;
	fetchImpl?: typeof fetch;
	/** Allowed clock skew for exp/nbf, seconds. Default 30. */
	clockToleranceSec?: number;
	/** Discovery cache TTL. Default 1h. */
	metadataCacheTtlMs?: number;
	/** JWKS cache TTL. Default 1h. */
	jwksCacheTtlMs?: number;
	/** Minimum gap between JWKS refetches triggered by an unknown kid. Default 5s. */
	jwksRefetchCooldownMs?: number;
	/** Clock, epoch ms. For tests. */
	now?: () => number;
};

export type OidcClientOptions = CommonVerifierOptions & {
	/** The app's client id (its app id in Accounts). Tokens must carry it as `aud`. */
	clientId: string;
	/** Confidential apps only. Public apps (browser-only, CLI) have none. */
	clientSecret?: string;
	/** Must match a registered redirect URI character for character. */
	redirectUri: string;
	/** Where Accounts sends the browser after `/auth/logout`. */
	postLogoutRedirectUri?: string;
	/** Default `openid profile email offline_access`. */
	scopes?: readonly string[] | string;
	/** Default `client_secret_basic` when a secret is set, otherwise `none`. */
	tokenEndpointAuthMethod?: TokenEndpointAuthMethod;
};

export type OidcLoginRequest = {
	/** Send the browser here. */
	url: string;
	/** Keep these three server-side (or in a signed httpOnly cookie) until the callback. */
	state: string;
	nonce: string;
	codeVerifier: string;
};

export type OidcLoginExpectation = Pick<OidcLoginRequest, 'state' | 'nonce' | 'codeVerifier'>;

export type TokenSet = {
	accessToken: string;
	tokenType: 'Bearer';
	expiresIn: number;
	/** Epoch ms at which the access token expires (local clock). */
	expiresAt: number;
	/** Rotates on every refresh: always store the new one; the old one stops working. */
	refreshToken?: string;
	idToken?: string;
	scope?: string;
	raw: Record<string, unknown>;
};

export type IdTokenClaims = {
	iss: string;
	sub: string;
	aud: string | string[];
	exp: number;
	iat: number;
	auth_time?: number;
	nonce?: string;
	email?: string;
	email_verified?: boolean;
	name?: string;
	given_name?: string;
	family_name?: string;
	picture?: string;
	[claim: string]: unknown;
};

export type AccessTokenClaims = {
	iss: string;
	sub: string;
	aud: string | string[];
	exp: number;
	iat: number;
	/** Tenant id. */
	tid?: string | null;
	/** Accounts session id. */
	sid?: string;
	/** Space-separated scopes. */
	scope?: string;
	jti?: string;
	[claim: string]: unknown;
};

export type UserInfo = {
	sub: string;
	email?: string;
	email_verified?: boolean;
	name?: string;
	given_name?: string;
	family_name?: string;
	picture?: string;
	[claim: string]: unknown;
};

export type VerifiedAccessToken = {
	claims: AccessTokenClaims;
	/** `jwks`: verified locally. `userinfo`: JWKS unreachable, Accounts vouched for it remotely. */
	verifiedBy: 'jwks' | 'userinfo';
};

// ── Small helpers ────────────────────────────────────────────────────────────────

function b64url(buf: Buffer): string {
	return buf.toString('base64url');
}

export function randomToken(bytes = 32): string {
	return b64url(randomBytes(bytes));
}

/** RFC 7636 S256: BASE64URL(SHA256(ascii(verifier))). */
export function pkceChallenge(verifier: string): string {
	return b64url(createHash('sha256').update(verifier, 'ascii').digest());
}

export function createPkcePair(): { codeVerifier: string; codeChallenge: string } {
	const codeVerifier = randomToken(32); // 43 chars, within RFC 7636's 43..128
	return { codeVerifier, codeChallenge: pkceChallenge(codeVerifier) };
}

function safeEqual(a: string, b: string): boolean {
	const ab = Buffer.from(a);
	const bb = Buffer.from(b);
	return ab.length === bb.length && timingSafeEqual(ab, bb);
}

function stripSlash(value: string): string {
	return value.replace(/\/+$/, '');
}

function resolveUrl(value: string, issuer: string): string {
	return new URL(value, issuer + '/').toString();
}

function normalizeScopes(scopes: readonly string[] | string | undefined): string {
	if (scopes === undefined) return DEFAULT_OIDC_SCOPES.join(' ');
	const list = typeof scopes === 'string' ? scopes.split(/[\s,]+/) : [...scopes];
	return list.map((s) => s.trim()).filter(Boolean).join(' ');
}

function formEncode(value: string): string {
	return encodeURIComponent(value).replace(/%20/g, '+');
}

async function safeFetch(fetchImpl: typeof fetch, url: string, init: RequestInit, code: OidcErrorCode) {
	try {
		return await fetchImpl(url, init);
	} catch (cause) {
		throw new OidcError(code === 'token_request_failed' ? 'network_error' : code, `Request to ${url} failed.`, {
			cause
		});
	}
}

async function readJson(res: Response): Promise<Record<string, unknown> | null> {
	try {
		const data = (await res.json()) as unknown;
		return data && typeof data === 'object' && !Array.isArray(data) ? (data as Record<string, unknown>) : null;
	} catch {
		return null;
	}
}

// ── Issuer metadata (discovery) ──────────────────────────────────────────────────

type MetadataSource = { get(): Promise<OidcEndpoints> };

function createMetadataSource(opts: CommonVerifierOptions): MetadataSource {
	const issuer = stripSlash(opts.issuer);
	const fetchImpl = opts.fetchImpl ?? fetch;
	const now = opts.now ?? Date.now;
	const ttl = opts.metadataCacheTtlMs ?? 60 * 60 * 1000;
	const override = (key: keyof OidcEndpoints) => opts.endpoints?.[key];
	const fromPaths = (): OidcEndpoints => {
		const out = {} as OidcEndpoints;
		for (const key of Object.keys(ACCOUNTS_ENDPOINT_PATHS) as (keyof OidcEndpoints)[]) {
			out[key] = resolveUrl(override(key) ?? ACCOUNTS_ENDPOINT_PATHS[key], issuer);
		}
		return out;
	};

	if (!opts.discovery) {
		const fixed = fromPaths();
		return { get: async () => fixed };
	}

	let cached: { value: OidcEndpoints; expires: number } | null = null;
	let inflight: Promise<OidcEndpoints> | null = null;

	async function load(): Promise<OidcEndpoints> {
		const url = `${issuer}/.well-known/openid-configuration`;
		const res = await safeFetch(fetchImpl, url, { headers: { accept: 'application/json' } }, 'discovery_failed');
		if (!res.ok) throw new OidcError('discovery_failed', `Discovery returned ${res.status}.`, { status: res.status });
		const doc = await readJson(res);
		if (!doc) throw new OidcError('discovery_failed', 'Discovery document is not JSON.');
		if (typeof doc.issuer !== 'string' || stripSlash(doc.issuer) !== issuer) {
			throw new OidcError('issuer_mismatch', `Discovery issuer ${String(doc.issuer)} is not ${issuer}.`);
		}
		const pick = (key: keyof OidcEndpoints, field: string) => {
			const explicit = override(key);
			if (explicit) return resolveUrl(explicit, issuer);
			const advertised = doc[field];
			return typeof advertised === 'string' && advertised
				? advertised
				: resolveUrl(ACCOUNTS_ENDPOINT_PATHS[key], issuer);
		};
		return {
			authorization: pick('authorization', 'authorization_endpoint'),
			token: pick('token', 'token_endpoint'),
			userinfo: pick('userinfo', 'userinfo_endpoint'),
			jwks: pick('jwks', 'jwks_uri'),
			revocation: pick('revocation', 'revocation_endpoint'),
			endSession: pick('endSession', 'end_session_endpoint')
		};
	}

	return {
		async get() {
			if (cached && cached.expires > now()) return cached.value;
			inflight ??= load()
				.then((value) => {
					cached = { value, expires: now() + ttl };
					return value;
				})
				.finally(() => {
					inflight = null;
				});
			return inflight;
		}
	};
}

// ── JWKS ─────────────────────────────────────────────────────────────────────────

type Jwk = NodeJsonWebKey & { kid?: string; kty?: string; use?: string; alg?: string };

class JwksStore {
	private keys = new Map<string, KeyObject>();
	private anonymous: KeyObject[] = [];
	private fetchedAt = -Infinity;
	private inflight: Promise<void> | null = null;
	/** Number of JWKS fetches performed (observability / tests). */
	fetchCount = 0;

	constructor(
		private readonly metadata: MetadataSource,
		private readonly fetchImpl: typeof fetch,
		private readonly ttlMs: number,
		private readonly cooldownMs: number,
		private readonly now: () => number
	) {}

	private async refresh(): Promise<void> {
		this.inflight ??= (async () => {
			const { jwks } = await this.metadata.get();
			const res = await safeFetch(this.fetchImpl, jwks, { headers: { accept: 'application/json' } }, 'jwks_fetch_failed');
			if (!res.ok) throw new OidcError('jwks_fetch_failed', `JWKS returned ${res.status}.`, { status: res.status });
			const body = await readJson(res);
			if (!body || !Array.isArray(body.keys)) throw new OidcError('jwks_fetch_failed', 'JWKS is not a key set.');
			const keys = new Map<string, KeyObject>();
			const anonymous: KeyObject[] = [];
			for (const jwk of body.keys as Jwk[]) {
				if (!jwk || jwk.kty !== 'RSA') continue;
				if (jwk.use && jwk.use !== 'sig') continue;
				if (jwk.alg && jwk.alg !== 'RS256') continue;
				let key: KeyObject;
				try {
					key = createPublicKey({ key: jwk, format: 'jwk' });
				} catch {
					continue;
				}
				if (jwk.kid) keys.set(jwk.kid, key);
				else anonymous.push(key);
			}
			this.fetchCount++;
			this.keys = keys;
			this.anonymous = anonymous;
			this.fetchedAt = this.now();
		})().finally(() => {
			this.inflight = null;
		});
		return this.inflight;
	}

	private lookup(kid: string | undefined): KeyObject | undefined {
		if (kid) return this.keys.get(kid);
		// No kid: acceptable only when the set is unambiguous.
		const all = [...this.keys.values(), ...this.anonymous];
		return all.length === 1 ? all[0] : undefined;
	}

	async getKey(kid: string | undefined): Promise<KeyObject> {
		const age = this.now() - this.fetchedAt;
		if (age >= this.ttlMs) await this.refresh();
		let key = this.lookup(kid);
		if (!key && this.now() - this.fetchedAt >= this.cooldownMs) {
			// Unknown kid: Accounts may have rotated keys. Refetch once (rate-limited).
			await this.refresh();
			key = this.lookup(kid);
		}
		if (!key) throw new OidcError('unknown_kid', `No signing key for kid ${kid ?? '(none)'}.`);
		return key;
	}
}

// ── JWT verification ─────────────────────────────────────────────────────────────

type JwtParts = { header: Record<string, unknown>; payload: Record<string, unknown>; signingInput: string; signature: Buffer };

function decodeJwt(token: string): JwtParts {
	const parts = typeof token === 'string' ? token.split('.') : [];
	if (parts.length !== 3 || parts.some((p) => !/^[A-Za-z0-9_-]*$/.test(p)) || !parts[0] || !parts[1]) {
		throw new OidcError('invalid_jwt', 'Token is not a compact JWS.');
	}
	const parse = (segment: string) => {
		try {
			const value = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as unknown;
			if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('not an object');
			return value as Record<string, unknown>;
		} catch {
			throw new OidcError('invalid_jwt', 'Token segment is not base64url JSON.');
		}
	};
	return {
		header: parse(parts[0]),
		payload: parse(parts[1]),
		signingInput: `${parts[0]}.${parts[1]}`,
		signature: Buffer.from(parts[2], 'base64url')
	};
}

/** True when the string has the shape of a compact JWS (three base64url segments). */
export function looksLikeJwt(token: string): boolean {
	return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.test(token);
}

type ClaimChecks = {
	issuer: string;
	/** Accepted audiences; null accepts any (the caller reads `aud` itself). */
	audience: string[] | null;
	nonce?: string;
	clockToleranceSec: number;
	nowMs: number;
};

function checkClaims(payload: Record<string, unknown>, checks: ClaimChecks): void {
	if (typeof payload.iss !== 'string' || stripSlash(payload.iss) !== checks.issuer) {
		throw new OidcError('issuer_mismatch', `Token issuer ${String(payload.iss)} is not ${checks.issuer}.`);
	}
	if (typeof payload.sub !== 'string' || !payload.sub) {
		throw new OidcError('invalid_jwt', 'Token has no subject.');
	}
	const aud = payload.aud;
	const auds = typeof aud === 'string' ? [aud] : Array.isArray(aud) ? aud.filter((a) => typeof a === 'string') : [];
	if (auds.length === 0) throw new OidcError('audience_mismatch', 'Token has no audience.');
	if (checks.audience) {
		if (!auds.some((a) => checks.audience!.includes(a))) {
			throw new OidcError('audience_mismatch', `Token audience ${auds.join(',')} is not accepted.`);
		}
		if (auds.length > 1 && typeof payload.azp === 'string' && !checks.audience.includes(payload.azp)) {
			throw new OidcError('audience_mismatch', `Token azp ${payload.azp} is not accepted.`);
		}
	}
	const nowSec = checks.nowMs / 1000;
	if (typeof payload.exp !== 'number') throw new OidcError('invalid_jwt', 'Token has no exp.');
	if (nowSec > payload.exp + checks.clockToleranceSec) throw new OidcError('token_expired', 'Token has expired.');
	if (typeof payload.nbf === 'number' && nowSec + checks.clockToleranceSec < payload.nbf) {
		throw new OidcError('token_not_yet_valid', 'Token is not valid yet.');
	}
	if (checks.nonce !== undefined) {
		if (typeof payload.nonce !== 'string' || !safeEqual(payload.nonce, checks.nonce)) {
			throw new OidcError('nonce_mismatch', 'id_token nonce is not the one this app sent.');
		}
	}
}

async function verifyJwt(token: string, store: JwksStore, checks: ClaimChecks): Promise<Record<string, unknown>> {
	const { header, payload, signingInput, signature } = decodeJwt(token);
	if (header.alg !== 'RS256') throw new OidcError('unsupported_alg', `Unsupported alg ${String(header.alg)}.`);
	const key = await store.getKey(typeof header.kid === 'string' ? header.kid : undefined);
	const valid = cryptoVerify('RSA-SHA256', Buffer.from(signingInput), key, signature);
	if (!valid) throw new OidcError('invalid_signature', 'Token signature is invalid.');
	checkClaims(payload, checks);
	return payload;
}

// ── Access-token verifier (resource servers) ─────────────────────────────────────

export type AccessTokenVerifierOptions = CommonVerifierOptions & {
	/**
	 * Accepted `aud` values (client ids). Omit to accept a token issued to any app; the caller
	 * then reads `claims.aud` to see which app it was issued for.
	 */
	audience?: string | readonly string[];
	/**
	 * When the JWKS (or discovery) cannot be reached, ask Accounts' userinfo endpoint instead.
	 * Default true. Never used for a token that fails verification against a reachable JWKS.
	 */
	remoteFallback?: boolean;
};

export type AccessTokenVerifier = {
	verify(token: string, options?: { audience?: string | readonly string[] }): Promise<VerifiedAccessToken>;
	fetchUserInfo(accessToken: string): Promise<UserInfo>;
	metadata(): Promise<OidcEndpoints>;
	/** @internal */
	readonly _jwks: JwksStore;
};

function toList(value: string | readonly string[] | undefined): string[] | null {
	if (value === undefined) return null;
	return typeof value === 'string' ? [value] : [...value];
}

type Internals = {
	issuer: string;
	metadata: MetadataSource;
	jwks: JwksStore;
	fetchImpl: typeof fetch;
	now: () => number;
	tolerance: number;
};

function createInternals(opts: CommonVerifierOptions): Internals {
	if (!opts.issuer) throw new OidcError('invalid_config', 'issuer is required.');
	const fetchImpl = opts.fetchImpl ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
	const now = opts.now ?? Date.now;
	const metadata = createMetadataSource({ ...opts, fetchImpl, now });
	return {
		issuer: stripSlash(opts.issuer),
		metadata,
		jwks: new JwksStore(metadata, fetchImpl, opts.jwksCacheTtlMs ?? 60 * 60 * 1000, opts.jwksRefetchCooldownMs ?? 5000, now),
		fetchImpl,
		now,
		tolerance: opts.clockToleranceSec ?? 30
	};
}

async function userInfoRequest(internals: Internals, accessToken: string): Promise<UserInfo> {
	const { userinfo } = await internals.metadata.get();
	const res = await safeFetch(
		internals.fetchImpl,
		userinfo,
		{ headers: { authorization: `Bearer ${accessToken}`, accept: 'application/json' } },
		'userinfo_failed'
	);
	const body = await readJson(res);
	if (!res.ok || !body || typeof body.sub !== 'string') {
		throw new OidcError('userinfo_failed', `userinfo returned ${res.status}.`, {
			status: res.status,
			oauthError: typeof body?.error === 'string' ? body.error : undefined
		});
	}
	return body as UserInfo;
}

async function verifyAccess(
	internals: Internals,
	token: string,
	audience: string[] | null,
	remoteFallback: boolean
): Promise<VerifiedAccessToken> {
	const checks: ClaimChecks = {
		issuer: internals.issuer,
		audience,
		clockToleranceSec: internals.tolerance,
		nowMs: internals.now()
	};
	const guardType = (payload: Record<string, unknown>) => {
		// An id_token carries a nonce and no scope; it must not be accepted as a bearer credential.
		if ('nonce' in payload) throw new OidcError('wrong_token_type', 'An id_token is not an access token.');
	};
	try {
		const payload = await verifyJwt(token, internals.jwks, checks);
		guardType(payload);
		return { claims: payload as AccessTokenClaims, verifiedBy: 'jwks' };
	} catch (error) {
		const unreachable = isOidcError(error, 'jwks_fetch_failed') || isOidcError(error, 'discovery_failed');
		if (!remoteFallback || !unreachable) throw error;
		// JWKS unreachable: Accounts validates the signature for us; we still check the claims.
		const { payload } = decodeJwt(token);
		checkClaims(payload, checks);
		guardType(payload);
		const info = await userInfoRequest(internals, token);
		if (info.sub !== payload.sub) throw new OidcError('userinfo_failed', 'userinfo subject does not match the token.');
		return { claims: payload as AccessTokenClaims, verifiedBy: 'userinfo' };
	}
}

export function createAccessTokenVerifier(opts: AccessTokenVerifierOptions): AccessTokenVerifier {
	const internals = createInternals(opts);
	const defaultAudience = toList(opts.audience);
	const remoteFallback = opts.remoteFallback ?? true;
	return {
		verify(token, options) {
			const audience = options?.audience !== undefined ? toList(options.audience) : defaultAudience;
			return verifyAccess(internals, token, audience, remoteFallback);
		},
		fetchUserInfo: (accessToken) => userInfoRequest(internals, accessToken),
		metadata: () => internals.metadata.get(),
		_jwks: internals.jwks
	};
}

// ── OIDC client (apps that sign people in) ───────────────────────────────────────

export type OidcClient = {
	readonly clientId: string;
	readonly issuer: string;
	readonly scope: string;
	readonly authMethod: TokenEndpointAuthMethod;
	metadata(): Promise<OidcEndpoints>;
	/** Step 1: build the /auth/authorize URL. Keep `state`, `nonce`, `codeVerifier` until the callback. */
	beginLogin(options?: {
		scopes?: readonly string[] | string;
		prompt?: string;
		loginHint?: string;
		extraParams?: Record<string, string>;
	}): Promise<OidcLoginRequest>;
	/** Steps 3–5: check state, exchange the code (with PKCE verifier), verify the id_token. */
	handleCallback(input: {
		/** The full callback URL, or just its query parameters. */
		url?: string | URL;
		params?: URLSearchParams | Record<string, string | undefined>;
		expected: Partial<OidcLoginExpectation> | null | undefined;
	}): Promise<{ claims: IdTokenClaims; tokens: TokenSet }>;
	/** Low-level code exchange. Does NOT verify the id_token: call `verifyIdToken(t, { nonce })` yourself. */
	exchangeCode(input: { code: string; codeVerifier: string }): Promise<TokenSet>;
	/** grant_type=refresh_token. The returned `refreshToken` replaces the old one, which is now dead. */
	refresh(refreshToken: string, options?: { scopes?: readonly string[] | string }): Promise<TokenSet>;
	/** POST /api/auth/revoke. Throws OidcError('revocation_failed') on a non-2xx answer. */
	revoke(token: string, tokenTypeHint?: 'refresh_token' | 'access_token'): Promise<void>;
	verifyIdToken(idToken: string, options?: { nonce?: string }): Promise<IdTokenClaims>;
	/** Verify locally against the JWKS (aud defaults to this client id); userinfo fallback if the JWKS is down. */
	verifyAccessToken(
		token: string,
		options?: { audience?: string | readonly string[]; remoteFallback?: boolean }
	): Promise<VerifiedAccessToken>;
	fetchUserInfo(accessToken: string): Promise<UserInfo>;
	/** /auth/logout?client_id=…&post_logout_redirect_uri=… */
	logoutUrl(options?: { postLogoutRedirectUri?: string; state?: string; idTokenHint?: string }): Promise<string>;
	/** @internal */
	readonly _jwks: JwksStore;
};

export function createOidcClient(opts: OidcClientOptions): OidcClient {
	if (!opts.clientId) throw new OidcError('invalid_config', 'clientId is required.');
	if (!opts.redirectUri) throw new OidcError('invalid_config', 'redirectUri is required.');
	const internals = createInternals(opts);
	const secret = opts.clientSecret?.trim() || undefined;
	const authMethod: TokenEndpointAuthMethod = opts.tokenEndpointAuthMethod ?? (secret ? 'client_secret_basic' : 'none');
	if (authMethod !== 'none' && !secret) {
		throw new OidcError('invalid_config', `${authMethod} needs a clientSecret.`);
	}
	const scope = normalizeScopes(opts.scopes);
	const clientId = opts.clientId;

	function applyClientAuth(body: URLSearchParams, headers: Record<string, string>) {
		if (authMethod === 'client_secret_basic') {
			// RFC 6749 §2.3.1: form-urlencode id and secret before base64.
			const raw = `${formEncode(clientId)}:${formEncode(secret!)}`;
			headers.authorization = `Basic ${Buffer.from(raw).toString('base64')}`;
		} else if (authMethod === 'client_secret_post') {
			body.set('client_id', clientId);
			body.set('client_secret', secret!);
		} else {
			body.set('client_id', clientId);
		}
	}

	async function tokenRequest(params: Record<string, string>, requireIdToken: boolean): Promise<TokenSet> {
		const { token: endpoint } = await internals.metadata.get();
		const body = new URLSearchParams(params);
		const headers: Record<string, string> = {
			'content-type': 'application/x-www-form-urlencoded',
			accept: 'application/json'
		};
		applyClientAuth(body, headers);
		const res = await safeFetch(
			internals.fetchImpl,
			endpoint,
			{ method: 'POST', headers, body: body.toString() },
			'token_request_failed'
		);
		const json = await readJson(res);
		if (!res.ok) {
			const oauthError = typeof json?.error === 'string' ? json.error : undefined;
			throw new OidcError(
				'token_request_failed',
				`Token endpoint returned ${res.status}${oauthError ? ` (${oauthError})` : ''}.`,
				{
					status: res.status,
					oauthError,
					oauthErrorDescription: typeof json?.error_description === 'string' ? json.error_description : undefined
				}
			);
		}
		if (!json || typeof json.access_token !== 'string' || !json.access_token) {
			throw new OidcError('invalid_token_response', 'Token response has no access_token.');
		}
		if (typeof json.token_type !== 'string' || json.token_type.toLowerCase() !== 'bearer') {
			throw new OidcError('invalid_token_response', `Unexpected token_type ${String(json.token_type)}.`);
		}
		const expiresIn = typeof json.expires_in === 'number' ? json.expires_in : Number(json.expires_in ?? 0) || 0;
		const tokens: TokenSet = {
			accessToken: json.access_token,
			tokenType: 'Bearer',
			expiresIn,
			expiresAt: internals.now() + expiresIn * 1000,
			refreshToken: typeof json.refresh_token === 'string' && json.refresh_token ? json.refresh_token : undefined,
			idToken: typeof json.id_token === 'string' && json.id_token ? json.id_token : undefined,
			scope: typeof json.scope === 'string' ? json.scope : undefined,
			raw: json
		};
		if (requireIdToken && !tokens.idToken) {
			throw new OidcError('missing_id_token', 'openid was requested but no id_token was returned.');
		}
		return tokens;
	}

	async function verifyIdToken(idToken: string, options?: { nonce?: string }): Promise<IdTokenClaims> {
		const payload = await verifyJwt(idToken, internals.jwks, {
			issuer: internals.issuer,
			audience: [clientId],
			nonce: options?.nonce,
			clockToleranceSec: internals.tolerance,
			nowMs: internals.now()
		});
		return payload as IdTokenClaims;
	}

	const scopeHasOpenId = (value: string) => value.split(' ').includes('openid');

	return {
		clientId,
		issuer: internals.issuer,
		scope,
		authMethod,
		metadata: () => internals.metadata.get(),
		_jwks: internals.jwks,

		async beginLogin(options = {}) {
			const { authorization } = await internals.metadata.get();
			const state = randomToken(32);
			const nonce = randomToken(32);
			const { codeVerifier, codeChallenge } = createPkcePair();
			const url = new URL(authorization);
			for (const [k, v] of Object.entries(options.extraParams ?? {})) url.searchParams.set(k, v);
			url.searchParams.set('client_id', clientId);
			url.searchParams.set('redirect_uri', opts.redirectUri);
			url.searchParams.set('response_type', 'code');
			url.searchParams.set('scope', options.scopes !== undefined ? normalizeScopes(options.scopes) : scope);
			url.searchParams.set('state', state);
			url.searchParams.set('nonce', nonce);
			url.searchParams.set('code_challenge', codeChallenge);
			url.searchParams.set('code_challenge_method', 'S256');
			if (options.prompt) url.searchParams.set('prompt', options.prompt);
			if (options.loginHint) url.searchParams.set('login_hint', options.loginHint);
			return { url: url.toString(), state, nonce, codeVerifier };
		},

		async handleCallback(input) {
			let params: URLSearchParams;
			if (input.url !== undefined) params = new URL(input.url.toString()).searchParams;
			else if (input.params instanceof URLSearchParams) params = input.params;
			else {
				params = new URLSearchParams();
				for (const [k, v] of Object.entries(input.params ?? {})) if (v !== undefined) params.set(k, v);
			}
			const expected = input.expected;
			const state = params.get('state');
			if (!expected?.state || !state || !safeEqual(state, expected.state)) {
				throw new OidcError('state_mismatch', 'Callback state does not match the login this browser started.');
			}
			const error = params.get('error');
			if (error) {
				throw new OidcError('authorization_error', `Accounts refused the sign-in: ${error}.`, {
					oauthError: error,
					oauthErrorDescription: params.get('error_description') ?? undefined
				});
			}
			const iss = params.get('iss');
			if (iss && stripSlash(iss) !== internals.issuer) {
				throw new OidcError('issuer_mismatch', `Callback iss ${iss} is not ${internals.issuer}.`);
			}
			const code = params.get('code');
			if (!code) throw new OidcError('missing_code', 'Callback has no authorization code.');
			if (!expected.nonce || !expected.codeVerifier) {
				throw new OidcError('state_mismatch', 'Stored login is missing its nonce or PKCE verifier.');
			}
			const tokens = await tokenRequest(
				{
					grant_type: 'authorization_code',
					code,
					redirect_uri: opts.redirectUri,
					code_verifier: expected.codeVerifier
				},
				true
			);
			const claims = await verifyIdToken(tokens.idToken!, { nonce: expected.nonce });
			return { claims, tokens };
		},

		exchangeCode({ code, codeVerifier }) {
			return tokenRequest(
				{ grant_type: 'authorization_code', code, redirect_uri: opts.redirectUri, code_verifier: codeVerifier },
				scopeHasOpenId(scope)
			);
		},

		async refresh(refreshToken, options) {
			const params: Record<string, string> = { grant_type: 'refresh_token', refresh_token: refreshToken };
			if (options?.scopes !== undefined) params.scope = normalizeScopes(options.scopes);
			const tokens = await tokenRequest(params, false);
			// An id_token on refresh (no nonce) must still be ours.
			if (tokens.idToken) await verifyIdToken(tokens.idToken);
			return tokens;
		},

		async revoke(token, tokenTypeHint = 'refresh_token') {
			const { revocation } = await internals.metadata.get();
			const body = new URLSearchParams({ token, token_type_hint: tokenTypeHint });
			const headers: Record<string, string> = { 'content-type': 'application/x-www-form-urlencoded' };
			applyClientAuth(body, headers);
			const res = await safeFetch(
				internals.fetchImpl,
				revocation,
				{ method: 'POST', headers, body: body.toString() },
				'revocation_failed'
			);
			if (!res.ok) throw new OidcError('revocation_failed', `Revocation returned ${res.status}.`, { status: res.status });
		},

		verifyIdToken,

		verifyAccessToken(token, options) {
			const audience = options?.audience !== undefined ? toList(options.audience) : [clientId];
			return verifyAccess(internals, token, audience, options?.remoteFallback ?? true);
		},

		fetchUserInfo: (accessToken) => userInfoRequest(internals, accessToken),

		async logoutUrl(options = {}) {
			const { endSession } = await internals.metadata.get();
			const url = new URL(endSession);
			url.searchParams.set('client_id', clientId);
			const target = options.postLogoutRedirectUri ?? opts.postLogoutRedirectUri;
			if (target) url.searchParams.set('post_logout_redirect_uri', target);
			if (options.state) url.searchParams.set('state', options.state);
			if (options.idTokenHint) url.searchParams.set('id_token_hint', options.idTokenHint);
			return url.toString();
		}
	};
}
