import { createHmac, timingSafeEqual } from 'node:crypto';

const SESSION_COOKIE_NAME = 'platform_session';
const STATE_COOKIE_NAME = 'accounts_auth_state';

function normalizeOptionalString(value: string | null | undefined): string | undefined {
	const trimmed = value?.trim();
	return trimmed ? trimmed : undefined;
}

export type PermissionSet = string[];

export type AccountsIdentity = {
	id: string;
	email: string;
	name: string;
	firstName?: string;
	lastName?: string;
	avatarUrl?: string;
};

export type LocalUser = {
	id: string;
	externalIdentityId: string;
	email: string;
	name: string;
	firstName?: string;
	lastName?: string;
	defaultTenantId?: string;
};

export type TenantMembership = {
	tenantId: string;
	role: 'customer' | 'admin' | 'owner';
	permissions: PermissionSet;
	isDefault?: boolean;
};

export type TenantContext = {
	id: string;
	slug: string;
	name: string;
	primaryDomain: string;
	locale: string;
	currency: string;
	themeKey: string;
	status: 'draft' | 'active' | 'archived';
};

export type TenantAccessContext = {
	activeTenantId?: string;
	memberships: TenantMembership[];
};

export type AuthenticatedPrincipal = {
	identity: AccountsIdentity;
	user: LocalUser;
	tenantAccess: TenantAccessContext;
};

export type PlatformSession = {
	principal: AuthenticatedPrincipal | null;
	tenant: TenantContext | null;
	accessToken?: string;
	refreshToken?: string;
	expiresAt?: string;
};

export type AccountsClientConfig = {
	baseUrl?: string;
	clientId: string;
	clientSecret?: string;
	redirectUri: string;
	logoutRedirectUri?: string;
	useMock?: boolean;
};

export type AuthorizationState = {
	nonce: string;
	nextPath: string;
	tenantSlug?: string;
};

export type AccountsTokenResponse = {
	access_token: string;
	refresh_token?: string;
	token_type: 'Bearer';
	expires_in: number;
	user: {
		id: string;
		// Axis Accounts returns camelCase (`emailAddress`, `firstName`, …); older/other providers
		// may use snake_case or `email`. We accept all and normalize in normalizeIdentity().
		email?: string;
		emailAddress?: string;
		name?: string;
		first_name?: string;
		firstName?: string;
		last_name?: string;
		lastName?: string;
		avatar_url?: string;
		avatarUrl?: string;
	};
};

export type SyncAccountsUserResult = {
	user: LocalUser;
	memberships: TenantMembership[];
	activeTenantId?: string;
};

export type SyncAccountsUser = (identity: AccountsIdentity) => SyncAccountsUserResult | Promise<SyncAccountsUserResult>;

export function createAccountsClientConfig(input: Partial<AccountsClientConfig> = {}): AccountsClientConfig {
	return {
		baseUrl: normalizeOptionalString(input.baseUrl ?? process.env.ACCOUNTS_BASE_URL),
		clientId: input.clientId ?? process.env.ACCOUNTS_CLIENT_ID ?? 'accounts-app',
		clientSecret: normalizeOptionalString(input.clientSecret ?? process.env.ACCOUNTS_CLIENT_SECRET),
		redirectUri:
			input.redirectUri ?? process.env.ACCOUNTS_REDIRECT_URI ?? 'http://localhost:5173/auth/callback',
		logoutRedirectUri:
			input.logoutRedirectUri ?? process.env.ACCOUNTS_LOGOUT_REDIRECT_URI ?? 'http://localhost:5173/',
		useMock:
			input.useMock ??
			(
				process.env.ACCOUNTS_USE_MOCK === 'true' ||
				!process.env.ACCOUNTS_BASE_URL ||
				!process.env.ACCOUNTS_CLIENT_ID
			)
	};
}

export function createPlatformAuth() {
	return {
		readSession(cookieHeader: string | null | undefined) {
			return readPlatformSessionCookie(cookieHeader);
		},
		requirePrincipal(session: PlatformSession) {
			if (!session.principal) {
				throw new Error('Authentication required.');
			}

			return session.principal;
		}
	};
}

export function beginAccountsLoginRedirect(
	config: AccountsClientConfig,
	options: {
		nextPath?: string;
		tenantSlug?: string;
		cookieOptions?: CookieOptions;
	}
) {
	const nonce = globalThis.crypto?.randomUUID?.() ?? Math.random().toString(36).slice(2);
	const state: AuthorizationState = {
		nonce,
		nextPath: options.nextPath && options.nextPath.startsWith('/') ? options.nextPath : '/',
		tenantSlug: options.tenantSlug
	};

	if (config.useMock) {
		const redirectUrl = new URL(config.redirectUri);
		redirectUrl.searchParams.set('code', `demo_${nonce}`);
		redirectUrl.searchParams.set('state', serializeAuthorizationState(state));

		return {
			redirectUrl: redirectUrl.toString(),
			stateValue: serializeAuthorizationState(state),
			stateCookie: createStateCookie(serializeAuthorizationState(state), options.cookieOptions)
		};
	}

	const authorizeUrl = new URL('/auth/authorize', config.baseUrl);
	authorizeUrl.searchParams.set('app_id', config.clientId);
	authorizeUrl.searchParams.set('redirect_uri', config.redirectUri);
	authorizeUrl.searchParams.set('state', serializeAuthorizationState(state));

	return {
		redirectUrl: authorizeUrl.toString(),
		stateValue: serializeAuthorizationState(state),
		stateCookie: createStateCookie(serializeAuthorizationState(state))
	};
}

export async function handleAccountsCallback(input: {
	config: AccountsClientConfig;
	code: string;
	state: string;
	storedState?: string | null;
	syncAccountsUser: SyncAccountsUser;
	fetchImpl?: typeof fetch;
	cookieOptions?: CookieOptions;
	/** When set, the session cookie is HMAC-signed so it cannot be forged/tampered. */
	secret?: string;
}) {
	if (!input.code) {
		throw new Error('Missing authorization code.');
	}

	if (input.storedState && input.state !== input.storedState) {
		throw new Error('Invalid authorization state.');
	}

	const parsedState = parseAuthorizationState(input.state);
	const tokenResponse = await exchangeAuthorizationCode({
		config: input.config,
		code: input.code,
		fetchImpl: input.fetchImpl
	});
	const identity = normalizeIdentity(tokenResponse.user);
	const local = await input.syncAccountsUser(identity);

	const session: PlatformSession = {
		principal: {
			identity,
			user: local.user,
			tenantAccess: {
				activeTenantId: local.activeTenantId,
				memberships: local.memberships
			}
		},
		tenant: null,
		accessToken: tokenResponse.access_token,
		refreshToken: tokenResponse.refresh_token,
		expiresAt: new Date(Date.now() + tokenResponse.expires_in * 1000).toISOString()
	};

	return {
		session,
		nextPath: parsedState.nextPath,
		tenantSlug: parsedState.tenantSlug,
		sessionCookie: createSessionCookie(session, input.cookieOptions, input.secret),
		clearStateCookie: clearStateCookie(input.cookieOptions)
	};
}

export async function exchangeAuthorizationCode(input: {
	config: AccountsClientConfig;
	code: string;
	fetchImpl?: typeof fetch;
}): Promise<AccountsTokenResponse> {
	if (input.config.useMock || input.code.startsWith('demo_')) {
		return createMockTokenResponse(input.code);
	}

	const fetchImpl = input.fetchImpl ?? fetch;
	const clientSecret = normalizeOptionalString(input.config.clientSecret);
	const tokenBody: Record<string, string> = {
		grant_type: 'authorization_code',
		code: input.code,
		redirect_uri: input.config.redirectUri,
		client_id: input.config.clientId
	};
	if (clientSecret) {
		tokenBody.client_secret = clientSecret;
	}

	const response = await fetchImpl(new URL('/api/auth/token', input.config.baseUrl), {
		method: 'POST',
		headers: {
			'content-type': 'application/json'
		},
		body: JSON.stringify(tokenBody)
	});

	if (!response.ok) {
		throw new Error(`Accounts token exchange failed with status ${response.status}.`);
	}

	return (await response.json()) as AccountsTokenResponse;
}

export function syncAccountsUser(identity: AccountsIdentity, syncer: SyncAccountsUser) {
	return syncer(identity);
}

/**
 * Default identity → local-user mapping for apps that do NOT keep their own users table
 * (e.g. a read-only companion app). Maps the Accounts identity straight through with no
 * memberships. Added 0.0.2; non-breaking.
 */
export const identityPassthroughSync: SyncAccountsUser = (identity) => ({
	user: {
		id: identity.id,
		externalIdentityId: identity.id,
		email: identity.email,
		name: identity.name,
		firstName: identity.firstName,
		lastName: identity.lastName
	},
	memberships: []
});

export function resolveActiveTenant(memberships: TenantMembership[], preferredTenantId?: string) {
	if (preferredTenantId && memberships.some((membership) => membership.tenantId === preferredTenantId)) {
		return preferredTenantId;
	}

	return memberships.find((membership) => membership.isDefault)?.tenantId ?? memberships[0]?.tenantId;
}

export function readPlatformSessionCookie(
	cookieHeader: string | null | undefined,
	opts?: { secret?: string }
): PlatformSession {
	const cookieValue = readCookie(cookieHeader, SESSION_COOKIE_NAME);
	if (!cookieValue) {
		return { principal: null, tenant: null };
	}

	let raw = cookieValue;
	if (opts?.secret) {
		// A secret is required: reject unsigned/forged/tampered cookies.
		const verified = unsignValue(cookieValue, opts.secret);
		if (verified == null) return { principal: null, tenant: null };
		raw = verified;
	}

	try {
		return JSON.parse(decodeURIComponent(raw)) as PlatformSession;
	} catch {
		return { principal: null, tenant: null };
	}
}

/**
 * Cookie attribute options. Set `sameSite: 'none'` (which implies `secure: true`) to make
 * the session usable on CROSS-SITE requests — required when an SDK on another origin calls
 * an API that relies on this cookie. Added 0.0.3; defaults preserve the prior Lax behavior.
 */
export type CookieOptions = { sameSite?: 'lax' | 'none' | 'strict'; secure?: boolean };

function cookieAttrs(opts?: CookieOptions): string {
	const sameSite = opts?.sameSite ?? 'lax';
	// SameSite=None is only honored with Secure; force it on.
	const secure = opts?.secure || sameSite === 'none';
	const cap = sameSite.charAt(0).toUpperCase() + sameSite.slice(1);
	return `Path=/; HttpOnly; SameSite=${cap}${secure ? '; Secure' : ''}`;
}

// ── Optional HMAC signing for the session cookie ─────────────────────────────────
// When a `secret` is supplied, the session value is signed `<value>.<hmac-sha256-hex>` so a
// client cannot forge or tamper with the session (e.g. fake tenant memberships). Read paths
// without a secret keep the legacy unsigned behavior, so existing apps are unaffected.
function signValue(value: string, secret: string): string {
	const sig = createHmac('sha256', secret).update(value).digest('hex');
	return `${value}.${sig}`;
}

function unsignValue(signed: string, secret: string): string | null {
	const dot = signed.lastIndexOf('.');
	if (dot < 0) return null; // unsigned cookie rejected when a secret is required
	const value = signed.slice(0, dot);
	const sig = signed.slice(dot + 1);
	if (!/^[0-9a-f]{64}$/.test(sig)) return null;
	const expected = createHmac('sha256', secret).update(value).digest('hex');
	const a = Buffer.from(sig, 'hex');
	const b = Buffer.from(expected, 'hex');
	if (a.length !== b.length) return null;
	return timingSafeEqual(a, b) ? value : null;
}

export function clearPlatformSessionCookie(opts?: CookieOptions) {
	return `${SESSION_COOKIE_NAME}=; ${cookieAttrs(opts)}; Max-Age=0`;
}

function createSessionCookie(session: PlatformSession, opts?: CookieOptions, secret?: string) {
	const raw = encodeURIComponent(JSON.stringify(session));
	const value = secret ? signValue(raw, secret) : raw;
	return `${SESSION_COOKIE_NAME}=${value}; ${cookieAttrs(opts)}; Max-Age=${60 * 60 * 24 * 7}`;
}

function createStateCookie(value: string, opts?: CookieOptions) {
	return `${STATE_COOKIE_NAME}=${encodeURIComponent(value)}; ${cookieAttrs(opts)}; Max-Age=${60 * 10}`;
}

function clearStateCookie(opts?: CookieOptions) {
	return `${STATE_COOKIE_NAME}=; ${cookieAttrs(opts)}; Max-Age=0`;
}

function serializeAuthorizationState(state: AuthorizationState) {
	return encodeURIComponent(JSON.stringify(state));
}

function parseAuthorizationState(value: string): AuthorizationState {
	try {
		return JSON.parse(decodeURIComponent(value)) as AuthorizationState;
	} catch {
		throw new Error('Invalid authorization state payload.');
	}
}

function normalizeIdentity(user: AccountsTokenResponse['user']): AccountsIdentity {
	const firstName = user.firstName ?? user.first_name;
	const lastName = user.lastName ?? user.last_name;
	return {
		id: user.id,
		// Prefer the real address under either key; only synthesize when truly absent.
		email: user.emailAddress ?? user.email ?? `${user.id}@accounts.local`,
		name: user.name ?? ([firstName, lastName].filter(Boolean).join(' ') || 'Accounts User'),
		firstName,
		lastName,
		avatarUrl: user.avatarUrl ?? user.avatar_url
	};
}

function createMockTokenResponse(code: string): AccountsTokenResponse {
	const suffix = code.replace('demo_', '').slice(0, 8) || 'demo';
	return {
		access_token: `access_${suffix}`,
		refresh_token: `refresh_${suffix}`,
		token_type: 'Bearer',
		expires_in: 60 * 60 * 24 * 7,
		user: {
			id: 'accounts-user-demo-admin',
			email: 'hello@babyplanet.example',
			name: 'Baby Planet Admin',
			first_name: 'Baby',
			last_name: 'Planet'
		}
	};
}

function readCookie(cookieHeader: string | null | undefined, name: string) {
	if (!cookieHeader) return null;

	for (const part of cookieHeader.split(';')) {
		const [key, ...rest] = part.trim().split('=');
		if (key === name) {
			return rest.join('=');
		}
	}

	return null;
}

// ── App-scoped API keys (service keys) ───────────────────────────────────────────
// A machine/SDK caller presents a key minted in Axis Accounts (prefix `sk_`). We introspect it
// against Accounts (`POST /api/auth/service-keys/introspect`), which — authenticating on the
// presented key itself — returns the scopes granted to the key and the apps it may act on. The
// CONSUMING app owns what those scopes MEAN and enforces them per route; this SDK performs only the
// authentication (verify the key + fetch its grant). Reusable by any app that consumes app-scoped
// keys. Added 0.0.8; non-breaking. See createServiceKeyHandle() for the turnkey SvelteKit wiring.

export type ServiceKeyApp = { id: string; slug: string; name?: string };

export type ServiceKeyContext = {
	keyId: string;
	tenantId: string | null;
	/** Scopes granted to this key (opaque strings owned by the consuming app). */
	scopes: string[];
	/** Apps this key may act on (auth resolves these from the key's app grant). */
	accessibleApps: ServiceKeyApp[];
	expiresAt: string | null;
};

// The raw key from a request: the dedicated `X-API-KEY` header, or `Authorization: Bearer sk_…`
// (so a single Authorization header can carry EITHER a user session bearer or a service key — they
// are told apart by the `sk_` prefix). Returns null when no service key is present.
export function serviceKeyFromRequest(request: Request): string | null {
	const explicit = request.headers.get('x-api-key');
	if (explicit && explicit.trim()) return explicit.trim();
	const auth = request.headers.get('authorization');
	if (auth && auth.startsWith('Bearer ')) {
		const token = auth.slice(7).trim();
		if (token.startsWith('sk_')) return token;
	}
	return null;
}

type ServiceKeyIntrospectResponse = {
	valid: boolean;
	keyId?: string;
	tenantId?: string | null;
	scopes?: string[];
	accessibleApps?: { id: string; slug: string; name?: string }[];
	accessibleAppIds?: string[];
	expiresAt?: string | null;
};

// Verify a service key against Axis Accounts and return its grant. Returns null (treat as
// unauthenticated) for an invalid/revoked/expired key (auth replies HTTP 200 `{ valid: false }`),
// a missing Accounts base URL, a non-200 upstream status, or a transport error.
export async function introspectServiceKey(input: {
	config: Pick<AccountsClientConfig, 'baseUrl'>;
	key: string;
	fetchImpl?: typeof fetch;
}): Promise<ServiceKeyContext | null> {
	const base = normalizeOptionalString(input.config.baseUrl);
	if (!input.key || !base) return null;
	const fetchImpl = input.fetchImpl ?? fetch;
	try {
		const res = await fetchImpl(new URL('/api/auth/service-keys/introspect', base), {
			method: 'POST',
			headers: { 'x-api-key': input.key, accept: 'application/json' }
		});
		if (!res.ok) return null;
		const data = (await res.json()) as ServiceKeyIntrospectResponse;
		if (!data.valid || !data.keyId) return null;
		const accessibleApps = (data.accessibleApps ?? [])
			.filter(
				(a): a is ServiceKeyApp =>
					Boolean(a) && typeof a.id === 'string' && typeof a.slug === 'string'
			)
			.map((a) => ({ id: a.id, slug: a.slug, name: a.name }));
		return {
			keyId: data.keyId,
			tenantId: data.tenantId ?? null,
			scopes: Array.isArray(data.scopes) ? data.scopes : [],
			accessibleApps,
			expiresAt: data.expiresAt ?? null
		};
	} catch {
		return null;
	}
}

// Revoke the user's session at Axis Accounts (server-side logout). Clearing the local session
// cookie logs the user out of THIS app; this additionally revokes the session upstream so it can't
// be reused. `all: true` revokes every session for the user (log out everywhere). Best-effort:
// returns `{ success: false }` rather than throwing so a logout flow always completes locally.
export async function logoutFromAccounts(input: {
	config: Pick<AccountsClientConfig, 'baseUrl'>;
	accessToken: string;
	all?: boolean;
	fetchImpl?: typeof fetch;
}): Promise<{ success: boolean; revokedCount?: number }> {
	const base = normalizeOptionalString(input.config.baseUrl);
	if (!base || !input.accessToken) return { success: false };
	const fetchImpl = input.fetchImpl ?? fetch;
	try {
		const res = await fetchImpl(new URL('/api/auth/logout', base), {
			method: 'POST',
			headers: {
				'content-type': 'application/json',
				authorization: `Bearer ${input.accessToken}`,
				accept: 'application/json'
			},
			body: JSON.stringify({ all: input.all ?? false })
		});
		if (!res.ok) return { success: false };
		return (await res.json()) as { success: boolean; revokedCount?: number };
	} catch {
		return { success: false };
	}
}

// Verify an Accounts webhook signature: HMAC-SHA256 of the RAW request body, hex-encoded, compared
// timing-safely. Accepts `sha256=<hex>` or a bare hex digest. Callers must verify BEFORE trusting a
// webhook payload (an unsigned/forged webhook must be rejected).
export function verifyWebhookSignature(rawBody: string, signature: string | null | undefined, secret: string): boolean {
	if (!signature || !secret) return false;
	const provided = (signature.startsWith('sha256=') ? signature.slice(7) : signature).toLowerCase();
	if (!/^[0-9a-f]{64}$/.test(provided)) return false;
	const expected = createHmac('sha256', secret).update(rawBody).digest('hex');
	const a = Buffer.from(provided, 'hex');
	const b = Buffer.from(expected, 'hex');
	if (a.length !== b.length) return false;
	return timingSafeEqual(a, b);
}

export type AccountsWebhookEvent = { type: string; [key: string]: unknown };

// True if `granted` satisfies `required`. Flat EXACT-match, mirroring how Axis Accounts enforces
// scopes on its own endpoints (`scopes.includes(required)`) and validates them at mint time (a key
// can only hold scopes from auth-native ∪ the app registry, so there is no wildcard to honor).
// Scope strings are opaque to this SDK — no prefix/wildcard semantics are assumed.
export function scopeSatisfied(granted: string[] | undefined, required: string): boolean {
	if (!granted || granted.length === 0) return false;
	return granted.includes(required);
}
