import { beforeEach, describe, expect, it } from 'vitest';
import { createAccountsClientConfig, readPlatformSessionCookie, type PlatformSession } from '../src/index';
import { createAuthHandle, type PlatformLocals } from '../src/sveltekit';
import { FakeAccounts } from './fake-accounts';

let fake: FakeAccounts;
let handle: ReturnType<typeof createAuthHandle>;
const SECRET = 'session-secret';

function cookieJar() {
	const jar = new Map<string, string>();
	return {
		header: () => [...jar].map(([k, v]) => `${k}=${v}`).join('; '),
		store(res: Response) {
			for (const c of res.headers.getSetCookie()) {
				const [pair, ...attrs] = c.split(';');
				const [k, ...v] = pair.split('=');
				if (attrs.some((a) => a.trim() === 'Max-Age=0')) jar.delete(k);
				else jar.set(k, v.join('='));
			}
		}
	};
}

async function request(path: string, jar: ReturnType<typeof cookieJar>) {
	const url = new URL(path, 'https://shop.test');
	const req = new Request(url, { headers: { cookie: jar.header() } });
	const locals = {} as PlatformLocals;
	const event = {
		url,
		request: req,
		locals,
		cookies: { get: (n: string) => jar.header().split('; ').find((c) => c.startsWith(`${n}=`))?.slice(n.length + 1) }
	};
	const res = await handle({ event, resolve: async () => new Response('page') } as never);
	jar.store(res);
	return { res, locals };
}

beforeEach(() => {
	fake = new FakeAccounts();
	handle = createAuthHandle({
		config: createAccountsClientConfig({
			baseUrl: fake.issuer,
			clientId: 'shop',
			clientSecret: 's3cret:with spaces',
			redirectUri: 'https://shop.test/auth/callback',
			logoutRedirectUri: 'https://shop.test/',
			useMock: false
		}),
		fetchImpl: fake.fetch,
		sessionSecret: SECRET,
		endAccountsSession: true
	});
});

describe('createAuthHandle (OIDC)', () => {
	it('logs in with PKCE via a signed state cookie, refreshes, and logs out', async () => {
		const jar = cookieJar();
		const login = await request('/auth/login?next=/orders', jar);
		expect(login.res.status).toBe(302);
		const authorize = login.res.headers.get('location')!;
		expect(new URL(authorize).searchParams.get('code_challenge_method')).toBe('S256');
		expect(jar.header()).toContain('accounts_oidc_login=');

		const back = new URL(fake.authorize(authorize));
		const cb = await request(back.pathname + back.search, jar);
		expect(cb.res.status).toBe(302);
		expect(cb.res.headers.get('location')).toBe('/orders');
		expect(jar.header()).not.toContain('accounts_oidc_login=');
		const session = readPlatformSessionCookie(jar.header(), { secret: SECRET }) as PlatformSession;
		expect(session.principal?.identity).toMatchObject({ id: 'user-1', email: 'ada@example.test' });
		const firstRefresh = session.refreshToken;

		// Access token near expiry: the handle refreshes and stores the rotated refresh token.
		const stale = { ...session, expiresAt: new Date(Date.now() - 1000).toISOString() };
		const { createPlatformSessionCookie } = await import('../src/index');
		jar.store(new Response(null, { headers: { 'set-cookie': createPlatformSessionCookie(stale, undefined, SECRET) } }));
		const page = await request('/', jar);
		expect(await page.res.text()).toBe('page');
		const refreshed = readPlatformSessionCookie(jar.header(), { secret: SECRET });
		expect(refreshed.refreshToken).toBeTruthy();
		expect(refreshed.refreshToken).not.toBe(firstRefresh);
		expect(page.locals.principal?.identity.id).toBe('user-1');

		const out = await request('/auth/logout', jar);
		expect(new URL(out.res.headers.get('location')!).pathname).toBe('/auth/logout');
		expect(fake.requests.at(-1)!.url).toBe('https://accounts.test/api/auth/revoke');
		expect(readPlatformSessionCookie(jar.header(), { secret: SECRET }).principal).toBeNull();
	});

	it('rejects a callback whose state does not match the cookie', async () => {
		const jar = cookieJar();
		const login = await request('/auth/login', jar);
		const back = new URL(fake.authorize(login.res.headers.get('location')!));
		back.searchParams.set('state', 'forged');
		const cb = await request(back.pathname + back.search, jar);
		expect(cb.res.status).toBe(400);
		expect(await cb.res.text()).toContain('state_mismatch');
	});

	it('logs the session out when the refresh token was already spent', async () => {
		const jar = cookieJar();
		const login = await request('/auth/login', jar);
		const back = new URL(fake.authorize(login.res.headers.get('location')!));
		await request(back.pathname + back.search, jar);
		const session = readPlatformSessionCookie(jar.header(), { secret: SECRET });
		fake.revokedFamilies.add([...fake.refreshTokens.values()][0].family);
		const { createPlatformSessionCookie } = await import('../src/index');
		const stale = { ...session, expiresAt: new Date(0).toISOString() };
		jar.store(new Response(null, { headers: { 'set-cookie': createPlatformSessionCookie(stale, undefined, SECRET) } }));
		const page = await request('/', jar);
		expect(page.locals.principal).toBeNull();
		expect(readPlatformSessionCookie(jar.header(), { secret: SECRET }).principal).toBeNull();
	});
});
