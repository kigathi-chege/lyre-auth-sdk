import { createHmac, timingSafeEqual } from 'node:crypto';

const SESSION_COOKIE_NAME = 'platform_session';
const STATE_COOKIE_NAME = 'accounts_auth_state';

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
		email?: string;
		name?: string;
		first_name?: string;
		last_name?: string;
		avatar_url?: string;
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
		baseUrl: input.baseUrl ?? process.env.ACCOUNTS_BASE_URL,
		clientId: input.clientId ?? process.env.ACCOUNTS_CLIENT_ID ?? 'accounts-app',
		clientSecret: input.clientSecret ?? process.env.ACCOUNTS_CLIENT_SECRET,
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
	const response = await fetchImpl(new URL('/api/auth/token', input.config.baseUrl), {
		method: 'POST',
		headers: {
			'content-type': 'application/json'
		},
		body: JSON.stringify({
			grant_type: 'authorization_code',
			code: input.code,
			redirect_uri: input.config.redirectUri,
			client_id: input.config.clientId,
			client_secret: input.config.clientSecret
		})
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
	return {
		id: user.id,
		email: user.email ?? `${user.id}@accounts.local`,
		name: user.name ?? ([user.first_name, user.last_name].filter(Boolean).join(' ') || 'Accounts User'),
		firstName: user.first_name,
		lastName: user.last_name,
		avatarUrl: user.avatar_url
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
