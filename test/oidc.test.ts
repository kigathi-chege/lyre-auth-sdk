import { createHash } from 'node:crypto';
import { beforeEach, describe, expect, it } from 'vitest';
import {
	OidcError,
	createAccessTokenVerifier,
	createLoginStateCookie,
	createOidcClient,
	readLoginStateCookie,
	type OidcClientOptions
} from '../src/index';
import { createUserSessionResolver } from '../src/nest';
import { FakeAccounts } from './fake-accounts';

let fake: FakeAccounts;
const confidential = (extra: Partial<OidcClientOptions> = {}) =>
	createOidcClient({
		issuer: fake.issuer,
		clientId: 'shop',
		clientSecret: 's3cret:with spaces',
		redirectUri: 'https://shop.test/auth/callback',
		postLogoutRedirectUri: 'https://shop.test/',
		fetchImpl: fake.fetch,
		...extra
	});
const publicClient = () =>
	createOidcClient({
		issuer: fake.issuer,
		clientId: 'cli',
		redirectUri: 'http://127.0.0.1:8765/callback',
		fetchImpl: fake.fetch
	});

async function expectOidcError(promise: Promise<unknown>, code: string) {
	const error = await promise.then(
		() => null,
		(e: unknown) => e
	);
	expect(error).toBeInstanceOf(OidcError);
	expect((error as OidcError).code).toBe(code);
	return error as OidcError;
}

beforeEach(() => {
	fake = new FakeAccounts();
});

describe('sign-in round trip', () => {
	it('sends PKCE S256, state and nonce, and verifies the id_token', async () => {
		const client = confidential();
		const login = await client.beginLogin();
		const url = new URL(login.url);
		expect(url.origin + url.pathname).toBe('https://accounts.test/auth/authorize');
		const p = url.searchParams;
		expect(p.get('client_id')).toBe('shop');
		expect(p.get('redirect_uri')).toBe('https://shop.test/auth/callback');
		expect(p.get('response_type')).toBe('code');
		expect(p.get('scope')).toBe('openid profile email offline_access');
		expect(p.get('state')).toBe(login.state);
		expect(p.get('nonce')).toBe(login.nonce);
		expect(p.get('code_challenge_method')).toBe('S256');
		expect(p.get('code_challenge')).toBe(createHash('sha256').update(login.codeVerifier).digest('base64url'));
		expect(login.codeVerifier.length).toBeGreaterThanOrEqual(43);

		const callback = fake.authorize(login.url);
		const { claims, tokens } = await client.handleCallback({ url: callback, expected: login });
		expect(claims.sub).toBe('user-1');
		expect(claims.email).toBe('ada@example.test');
		expect(claims.nonce).toBe(login.nonce);
		expect(tokens.refreshToken).toBeTruthy();
		expect(tokens.expiresIn).toBe(900);

		const tokenReq = fake.requests.find((r) => r.url.endsWith('/api/auth/token'))!;
		expect(tokenReq.headers.get('content-type')).toBe('application/x-www-form-urlencoded');
		const form = new URLSearchParams(tokenReq.body);
		expect(form.get('grant_type')).toBe('authorization_code');
		expect(form.get('code_verifier')).toBe(login.codeVerifier);
		expect(form.get('redirect_uri')).toBe('https://shop.test/auth/callback');

		const access = await client.verifyAccessToken(tokens.accessToken);
		expect(access.verifiedBy).toBe('jwks');
		expect(access.claims.tid).toBe('tenant-1');
	});

	it('round-trips the login through the signed state cookie', async () => {
		const login = await confidential().beginLogin();
		const cookie = createLoginStateCookie(login, { nextPath: '/orders', secret: 'k' }).split(';')[0];
		expect(readLoginStateCookie(cookie, { secret: 'k' })).toMatchObject({
			state: login.state,
			nonce: login.nonce,
			codeVerifier: login.codeVerifier,
			nextPath: '/orders'
		});
		expect(readLoginStateCookie(cookie, { secret: 'other' })).toBeNull();
		const evil = createLoginStateCookie(login, { nextPath: '//evil.test' }).split(';')[0];
		expect(readLoginStateCookie(evil)?.nextPath).toBe('/');
	});

	it('rejects a bad state before touching the token endpoint', async () => {
		const client = confidential();
		const login = await client.beginLogin();
		const callback = fake.authorize(login.url);
		await expectOidcError(client.handleCallback({ url: callback, expected: { ...login, state: 'other' } }), 'state_mismatch');
		await expectOidcError(client.handleCallback({ url: callback, expected: null }), 'state_mismatch');
		expect(fake.requests.some((r) => r.url.endsWith('/api/auth/token'))).toBe(false);
	});

	it('surfaces ?error= from Accounts as authorization_error', async () => {
		const client = confidential();
		const login = await client.beginLogin();
		const err = await expectOidcError(
			client.handleCallback({ params: { error: 'access_denied', state: login.state }, expected: login }),
			'authorization_error'
		);
		expect(err.oauthError).toBe('access_denied');
	});

	it('rejects an id_token with the wrong nonce', async () => {
		const client = confidential();
		const login = await client.beginLogin();
		fake.tamper.idTokenNonce = 'replayed';
		await expectOidcError(client.handleCallback({ url: fake.authorize(login.url), expected: login }), 'nonce_mismatch');
	});

	it('rejects an id_token issued to another app', async () => {
		const client = confidential();
		const login = await client.beginLogin();
		fake.tamper.idTokenAud = 'premail';
		await expectOidcError(client.handleCallback({ url: fake.authorize(login.url), expected: login }), 'audience_mismatch');
	});

	it('rejects an expired id_token', async () => {
		const client = confidential();
		const login = await client.beginLogin();
		fake.tamper.iatOffsetSec = -3600;
		await expectOidcError(client.handleCallback({ url: fake.authorize(login.url), expected: login }), 'token_expired');
	});

	it('fails the exchange when the PKCE verifier is wrong', async () => {
		const client = confidential();
		const login = await client.beginLogin();
		const err = await expectOidcError(
			client.handleCallback({ url: fake.authorize(login.url), expected: { ...login, codeVerifier: 'x'.repeat(43) } }),
			'token_request_failed'
		);
		expect(err.oauthError).toBe('invalid_grant');
	});
});

describe('client authentication', () => {
	it('confidential clients use client_secret_basic by default (form-encoded credentials)', async () => {
		const client = confidential();
		const login = await client.beginLogin();
		await client.handleCallback({ url: fake.authorize(login.url), expected: login });
		expect(fake.lastClientAuth()).toBe('basic');
		const req = fake.requests.find((r) => r.url.endsWith('/api/auth/token'))!;
		expect(new URLSearchParams(req.body).has('client_secret')).toBe(false);
	});

	it('supports client_secret_post', async () => {
		const client = confidential({ tokenEndpointAuthMethod: 'client_secret_post' });
		const login = await client.beginLogin();
		await client.handleCallback({ url: fake.authorize(login.url), expected: login });
		expect(fake.lastClientAuth()).toBe('post');
	});

	it('public clients send only client_id', async () => {
		const client = publicClient();
		expect(client.authMethod).toBe('none');
		const login = await client.beginLogin();
		const { claims } = await client.handleCallback({ url: fake.authorize(login.url), expected: login });
		expect(claims.aud).toBe('cli');
		expect(fake.lastClientAuth()).toBe('none');
		const req = fake.requests.find((r) => r.url.endsWith('/api/auth/token'))!;
		expect(new URLSearchParams(req.body).get('client_id')).toBe('cli');
		expect(req.headers.get('authorization')).toBeNull();
	});

	it('a wrong secret is reported as invalid_client', async () => {
		const client = confidential({ clientSecret: 'wrong' });
		const login = await client.beginLogin();
		const err = await expectOidcError(
			client.handleCallback({ url: fake.authorize(login.url), expected: login }),
			'token_request_failed'
		);
		expect(err.status).toBe(401);
		expect(err.oauthError).toBe('invalid_client');
	});

	it('refuses a secret-based method with no secret', () => {
		expect(() => publicClientWith({ tokenEndpointAuthMethod: 'client_secret_basic' })).toThrow(OidcError);
	});
});

function publicClientWith(extra: Partial<OidcClientOptions>) {
	return createOidcClient({
		issuer: fake.issuer,
		clientId: 'cli',
		redirectUri: 'http://127.0.0.1:8765/callback',
		fetchImpl: fake.fetch,
		...extra
	});
}

describe('access tokens and the JWKS', () => {
	it('caches keys and refetches once on an unknown kid (rotation)', async () => {
		const client = confidential({ jwksRefetchCooldownMs: 0 });
		await client.verifyAccessToken(fake.accessToken());
		await client.verifyAccessToken(fake.accessToken());
		expect(client._jwks.fetchCount).toBe(1);

		fake.rotateKey({ keepOld: true });
		const rotated = await client.verifyAccessToken(fake.accessToken());
		expect(rotated.claims.sub).toBe('user-1');
		expect(client._jwks.fetchCount).toBe(2);

		// A kid Accounts never published fails after one more refetch.
		const ghost = fake.accessToken();
		const forged = ghost.replace(ghost.split('.')[0], Buffer.from(JSON.stringify({ alg: 'RS256', kid: 'ghost' })).toString('base64url'));
		await expectOidcError(client.verifyAccessToken(forged), 'unknown_kid');
	});

	it('respects the refetch cooldown', async () => {
		const client = confidential({ jwksRefetchCooldownMs: 60_000 });
		await client.verifyAccessToken(fake.accessToken());
		fake.rotateKey();
		await expectOidcError(client.verifyAccessToken(fake.accessToken()), 'unknown_kid');
		expect(client._jwks.fetchCount).toBe(1);
	});

	it('rejects expired, wrong-audience, tampered, alg=none and id_token-as-access tokens', async () => {
		const client = confidential();
		await expectOidcError(client.verifyAccessToken(fake.accessToken({ exp: Math.floor(Date.now() / 1000) - 120 })), 'token_expired');
		await expectOidcError(client.verifyAccessToken(fake.accessToken({ aud: 'premail' })), 'audience_mismatch');
		await expectOidcError(client.verifyAccessToken(fake.accessToken({ iss: 'https://evil.test' })), 'issuer_mismatch');
		const [h, , s] = fake.accessToken().split('.');
		const p = Buffer.from(JSON.stringify({ iss: fake.issuer, aud: 'shop', sub: 'admin', exp: 9e9, iat: 0 })).toString('base64url');
		await expectOidcError(client.verifyAccessToken(`${h}.${p}.${s}`), 'invalid_signature');
		const none = Buffer.from(JSON.stringify({ alg: 'none' })).toString('base64url');
		await expectOidcError(client.verifyAccessToken(`${none}.${p}.`), 'unsupported_alg');
		await expectOidcError(client.verifyAccessToken(fake.accessToken({ nonce: 'n' })), 'wrong_token_type');
		// The audience can be widened explicitly.
		const ok = await client.verifyAccessToken(fake.accessToken({ aud: 'premail' }), { audience: ['shop', 'premail'] });
		expect(ok.claims.aud).toBe('premail');
	});

	it('falls back to userinfo when the JWKS is unreachable, but never for a bad token', async () => {
		const verifier = createAccessTokenVerifier({ issuer: fake.issuer, audience: 'shop', fetchImpl: fake.fetch });
		fake.jwksDown = true;
		const ok = await verifier.verify(fake.accessToken());
		expect(ok.verifiedBy).toBe('userinfo');
		const unknown = fake.accessToken();
		fake.issuedAccess.clear();
		await expectOidcError(verifier.verify(unknown), 'userinfo_failed');
		await expectOidcError(verifier.verify(fake.accessToken({ aud: 'premail' })), 'audience_mismatch');

		const strict = createAccessTokenVerifier({ issuer: fake.issuer, fetchImpl: fake.fetch, remoteFallback: false });
		await expectOidcError(strict.verify(fake.accessToken()), 'jwks_fetch_failed');
	});
});

describe('refresh, revoke, logout, discovery', () => {
	async function signIn() {
		const client = confidential();
		const login = await client.beginLogin();
		const { tokens } = await client.handleCallback({ url: fake.authorize(login.url), expected: login });
		return { client, tokens };
	}

	it('rotates refresh tokens; replaying an old one revokes the family', async () => {
		const { client, tokens } = await signIn();
		const first = await client.refresh(tokens.refreshToken!);
		expect(first.refreshToken).toBeTruthy();
		expect(first.refreshToken).not.toBe(tokens.refreshToken);
		const form = new URLSearchParams(fake.requests.at(-1)!.body);
		expect(form.get('grant_type')).toBe('refresh_token');
		expect(fake.lastClientAuth()).toBe('basic');

		const replay = await expectOidcError(client.refresh(tokens.refreshToken!), 'token_request_failed');
		expect(replay.oauthError).toBe('invalid_grant');
		// Theft detection: the newest token died with its family.
		await expectOidcError(client.refresh(first.refreshToken!), 'token_request_failed');
	});

	it('revokes refresh tokens at /api/auth/revoke with client auth', async () => {
		const { client, tokens } = await signIn();
		await client.revoke(tokens.refreshToken!);
		const req = fake.requests.at(-1)!;
		expect(req.url).toBe('https://accounts.test/api/auth/revoke');
		expect(new URLSearchParams(req.body).get('token_type_hint')).toBe('refresh_token');
		expect(req.headers.get('authorization')).toMatch(/^Basic /);
		await expectOidcError(client.refresh(tokens.refreshToken!), 'token_request_failed');
	});

	it('builds the sign-out URL', async () => {
		const url = new URL(await confidential().logoutUrl());
		expect(url.origin + url.pathname).toBe('https://accounts.test/auth/logout');
		expect(url.searchParams.get('client_id')).toBe('shop');
		expect(url.searchParams.get('post_logout_redirect_uri')).toBe('https://shop.test/');
	});

	it('loads endpoints from discovery once and falls back to contract paths for unadvertised ones', async () => {
		const client = confidential({ discovery: true });
		const login = await client.beginLogin();
		await client.handleCallback({ url: fake.authorize(login.url), expected: login });
		await client.logoutUrl();
		const discoveries = fake.requests.filter((r) => r.url.endsWith('/.well-known/openid-configuration'));
		expect(discoveries).toHaveLength(1);
		expect((await client.metadata()).revocation).toBe('https://accounts.test/api/auth/revoke');
	});

	it('rejects a discovery document for another issuer', async () => {
		const client = createOidcClient({
			issuer: fake.issuer,
			clientId: 'shop',
			redirectUri: 'https://shop.test/auth/callback',
			discovery: true,
			fetchImpl: async (input, init) => {
				const res = await fake.fetch(input, init);
				if (String(input).includes('openid-configuration')) {
					const doc = await res.json();
					return new Response(JSON.stringify({ ...doc, issuer: 'https://evil.test' }));
				}
				return res;
			}
		});
		await expectOidcError(client.beginLogin(), 'issuer_mismatch');
	});
});

describe('nest user-session resolver', () => {
	const bearer = (token: string) => ({ headers: { authorization: `Bearer ${token}` } });

	it('verifies JWT bearers locally and maps the claims', async () => {
		const sessions = createUserSessionResolver({ config: { baseUrl: fake.issuer }, audience: 'shop', fetchImpl: fake.fetch });
		const ctx = await sessions.resolve(bearer(fake.accessToken()));
		expect(ctx).toMatchObject({ userId: 'user-1', sessionId: 'sess-1', appId: 'shop', tenantId: 'tenant-1', verifiedBy: 'jwks' });
		expect(ctx?.scopes).toContain('openid');
		expect(await sessions.resolve(bearer(fake.accessToken({ aud: 'premail' })))).toBeNull();
		expect(fake.requests.some((r) => r.url.endsWith('/api/auth/me'))).toBe(false);
	});

	it('keeps the legacy /api/auth/me path for opaque tokens', async () => {
		const fetchImpl: typeof fetch = async (input) => {
			if (String(input).endsWith('/api/auth/me')) {
				return new Response(JSON.stringify({ user: { id: 'u2' }, session: { id: 's2', appId: 'shop', tenantId: null } }));
			}
			return new Response('{}', { status: 404 });
		};
		const sessions = createUserSessionResolver({ config: { baseUrl: fake.issuer }, fetchImpl });
		expect(await sessions.resolve(bearer('opaque-session-id'))).toMatchObject({ userId: 'u2', verifiedBy: 'legacy-me' });
		const strict = createUserSessionResolver({ config: { baseUrl: fake.issuer }, fetchImpl, legacySessionTokens: false });
		expect(await strict.resolve(bearer('opaque-session-id'))).toBeNull();
	});
});
