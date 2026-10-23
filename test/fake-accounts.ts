// A fake Nipate Accounts that speaks the OIDC contract (docs/12-accounts-oidc.md), as a fetch
// implementation. Signs tokens with test RSA keys and serves discovery + JWKS.
import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from 'node:crypto';

type Client = { secret?: string; redirectUris: string[] };
type CodeGrant = {
	clientId: string;
	redirectUri: string;
	challenge: string;
	nonce: string;
	scope: string;
	expires: number;
	used: boolean;
};
type RefreshGrant = { family: string; clientId: string; scope: string; used: boolean };

export type RecordedRequest = { url: string; method: string; headers: Headers; body: string };

const b64 = (v: Buffer | string) => Buffer.from(v).toString('base64url');

export class FakeAccounts {
	readonly issuer = 'https://accounts.test';
	readonly user = { sub: 'user-1', email: 'ada@example.test', name: 'Ada Lovelace', tid: 'tenant-1' };
	keys: { kid: string; privateKey: KeyObject; jwk: Record<string, unknown> }[] = [];
	activeKid = '';
	clients = new Map<string, Client>();
	codes = new Map<string, CodeGrant>();
	refreshTokens = new Map<string, RefreshGrant>();
	revokedFamilies = new Set<string>();
	issuedAccess = new Set<string>();
	requests: RecordedRequest[] = [];
	/** Misbehaviours for negative tests. */
	tamper: { idTokenAud?: string; idTokenNonce?: string; ttlSec?: number; iatOffsetSec?: number } = {};
	jwksDown = false;

	constructor() {
		this.rotateKey();
		this.clients.set('shop', { secret: 's3cret:with spaces', redirectUris: ['https://shop.test/auth/callback'] });
		this.clients.set('cli', { redirectUris: ['http://127.0.0.1:8765/callback'] });
	}

	rotateKey(options: { keepOld?: boolean } = {}) {
		const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
		const kid = `k${this.keys.length + 1}`;
		const jwk = { ...(publicKey.export({ format: 'jwk' }) as Record<string, unknown>), kid, use: 'sig', alg: 'RS256' };
		if (!options.keepOld) this.keys = [];
		this.keys.push({ kid, privateKey, jwk });
		this.activeKid = kid;
		return kid;
	}

	sign(payload: Record<string, unknown>, kid = this.activeKid, header: Record<string, unknown> = {}) {
		const key = this.keys.find((k) => k.kid === kid);
		if (!key) throw new Error(`no key ${kid}`);
		const head = b64(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid, ...header }));
		const body = b64(JSON.stringify(payload));
		const sig = sign('RSA-SHA256', Buffer.from(`${head}.${body}`), key.privateKey);
		return `${head}.${body}.${b64(sig)}`;
	}

	accessToken(overrides: Record<string, unknown> = {}, kid?: string) {
		const now = Math.floor(Date.now() / 1000) + (this.tamper.iatOffsetSec ?? 0);
		const jti = b64(randomBytes(8));
		this.issuedAccess.add(jti);
		return this.sign(
			{
				iss: this.issuer,
				aud: 'shop',
				sub: this.user.sub,
				tid: this.user.tid,
				sid: 'sess-1',
				scope: 'openid profile email offline_access',
				iat: now,
				exp: now + (this.tamper.ttlSec ?? 900),
				jti,
				...overrides
			},
			kid
		);
	}

	/** Simulate the browser visiting /auth/authorize and the person signing in. Returns the redirect. */
	authorize(authorizeUrl: string): string {
		const url = new URL(authorizeUrl);
		const p = url.searchParams;
		const clientId = p.get('client_id') ?? '';
		const client = this.clients.get(clientId);
		const redirectUri = p.get('redirect_uri') ?? '';
		if (!client || !client.redirectUris.includes(redirectUri)) throw new Error('error page: client/redirect');
		if (p.get('response_type') !== 'code') throw new Error('error page: response_type');
		if (p.get('code_challenge_method') !== 'S256' || !p.get('code_challenge')) throw new Error('error page: PKCE');
		if (!p.get('state')) throw new Error('error page: state');
		const code = b64(randomBytes(16));
		this.codes.set(code, {
			clientId,
			redirectUri,
			challenge: p.get('code_challenge')!,
			nonce: p.get('nonce') ?? '',
			scope: p.get('scope') ?? '',
			expires: Date.now() + 60_000,
			used: false
		});
		const back = new URL(redirectUri);
		back.searchParams.set('code', code);
		back.searchParams.set('state', p.get('state')!);
		return back.toString();
	}

	fetch: typeof fetch = async (input, init) => {
		const url = new URL(typeof input === 'string' || input instanceof URL ? input.toString() : input.url);
		const method = (init?.method ?? 'GET').toUpperCase();
		const headers = new Headers(init?.headers);
		const body = typeof init?.body === 'string' ? init.body : '';
		this.requests.push({ url: url.toString(), method, headers, body });
		if (url.origin !== this.issuer) throw new TypeError('fetch failed');
		const json = (status: number, data: unknown) =>
			new Response(JSON.stringify(data), { status, headers: { 'content-type': 'application/json' } });

		switch (`${method} ${url.pathname}`) {
			case 'GET /.well-known/openid-configuration':
				return json(200, {
					issuer: this.issuer,
					authorization_endpoint: `${this.issuer}/auth/authorize`,
					token_endpoint: `${this.issuer}/api/auth/token`,
					userinfo_endpoint: `${this.issuer}/api/auth/userinfo`,
					jwks_uri: `${this.issuer}/api/.well-known/jwks.json`,
					response_types_supported: ['code'],
					grant_types_supported: ['authorization_code', 'refresh_token'],
					code_challenge_methods_supported: ['S256'],
					token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
					id_token_signing_alg_values_supported: ['RS256'],
					scopes_supported: ['openid', 'profile', 'email', 'offline_access']
				});
			case 'GET /api/.well-known/jwks.json':
				if (this.jwksDown) throw new TypeError('fetch failed');
				return json(200, { keys: this.keys.map((k) => k.jwk) });
			case 'POST /api/auth/token':
				return this.token(headers, body, json);
			case 'POST /api/auth/revoke': {
				const form = new URLSearchParams(body);
				const grant = this.refreshTokens.get(form.get('token') ?? '');
				if (grant) this.revokedFamilies.add(grant.family);
				return new Response(null, { status: 200 });
			}
			case 'GET /api/auth/userinfo': {
				const token = headers.get('authorization')?.replace(/^Bearer /, '') ?? '';
				const payload = JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString() || '{}');
				if (!this.issuedAccess.has(payload.jti)) return json(401, { error: 'invalid_token' });
				return json(200, { sub: payload.sub, email: this.user.email, name: this.user.name, email_verified: true });
			}
		}
		return json(404, { error: 'not_found' });
	};

	/** Which client authentication the last token/revoke request used. */
	lastClientAuth(): 'basic' | 'post' | 'none' {
		const req = [...this.requests].reverse().find((r) => r.url.endsWith('/api/auth/token'))!;
		if (req.headers.get('authorization')?.startsWith('Basic ')) return 'basic';
		return new URLSearchParams(req.body).has('client_secret') ? 'post' : 'none';
	}

	private authenticate(headers: Headers, form: URLSearchParams): { clientId: string } | { error: string } {
		let clientId = form.get('client_id') ?? '';
		let secret = form.get('client_secret') ?? undefined;
		const basic = headers.get('authorization');
		if (basic?.startsWith('Basic ')) {
			const [id, sec] = Buffer.from(basic.slice(6), 'base64').toString().split(':');
			const dec = (v: string) => decodeURIComponent(v.replace(/\+/g, ' '));
			clientId = dec(id ?? '');
			secret = dec(sec ?? '');
		}
		const client = this.clients.get(clientId);
		if (!client) return { error: 'invalid_client' };
		if (client.secret && client.secret !== secret) return { error: 'invalid_client' };
		return { clientId };
	}

	private token(headers: Headers, body: string, json: (s: number, d: unknown) => Response): Response {
		if (headers.get('content-type') !== 'application/x-www-form-urlencoded') return json(400, { error: 'invalid_request' });
		const form = new URLSearchParams(body);
		const auth = this.authenticate(headers, form);
		if ('error' in auth) return json(401, auth);
		const { clientId } = auth;

		if (form.get('grant_type') === 'authorization_code') {
			const grant = this.codes.get(form.get('code') ?? '');
			if (!grant || grant.used || grant.expires < Date.now() || grant.clientId !== clientId) {
				return json(400, { error: 'invalid_grant' });
			}
			grant.used = true;
			if (grant.redirectUri !== form.get('redirect_uri')) return json(400, { error: 'invalid_grant' });
			const verifier = form.get('code_verifier') ?? '';
			const challenge = createHash('sha256').update(verifier).digest('base64url');
			if (challenge !== grant.challenge) return json(400, { error: 'invalid_grant', error_description: 'PKCE' });
			return json(200, this.issue(clientId, grant.scope, grant.nonce, b64(randomBytes(8))));
		}

		if (form.get('grant_type') === 'refresh_token') {
			const presented = form.get('refresh_token') ?? '';
			const grant = this.refreshTokens.get(presented);
			if (!grant || grant.clientId !== clientId || this.revokedFamilies.has(grant.family)) {
				return json(400, { error: 'invalid_grant' });
			}
			if (grant.used) {
				this.revokedFamilies.add(grant.family); // theft detection
				return json(400, { error: 'invalid_grant', error_description: 'reused' });
			}
			grant.used = true;
			return json(200, this.issue(clientId, grant.scope, undefined, grant.family));
		}
		return json(400, { error: 'unsupported_grant_type' });
	}

	private issue(clientId: string, scope: string, nonce: string | undefined, family: string) {
		const now = Math.floor(Date.now() / 1000) + (this.tamper.iatOffsetSec ?? 0);
		const ttl = this.tamper.ttlSec ?? 900;
		const scopes = scope.split(' ');
		const out: Record<string, unknown> = {
			access_token: this.accessToken({ aud: clientId, scope }),
			token_type: 'Bearer',
			expires_in: ttl,
			scope
		};
		if (scopes.includes('offline_access')) {
			const rt = b64(randomBytes(24));
			this.refreshTokens.set(rt, { family, clientId, scope, used: false });
			out.refresh_token = rt;
		}
		if (scopes.includes('openid') && nonce !== undefined) {
			out.id_token = this.sign({
				iss: this.issuer,
				aud: this.tamper.idTokenAud ?? clientId,
				sub: this.user.sub,
				iat: now,
				exp: now + ttl,
				auth_time: now,
				nonce: this.tamper.idTokenNonce ?? nonce,
				email: this.user.email,
				email_verified: true,
				name: this.user.name
			});
		}
		return out;
	}
}
