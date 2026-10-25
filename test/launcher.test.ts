import { beforeEach, describe, expect, it } from 'vitest';
import { clearLauncherCache, fetchLauncherApps, launcherScriptUrl } from '../src/launcher';
import { loadLauncherApps } from '../src/sveltekit';

const BASE = 'https://accounts.test/';
const APP = {
	id: 'a1',
	slug: 'tasks',
	name: 'Nipate Tasks',
	description: 'Plan your work',
	iconUrl: 'https://accounts.test/brand/tasks.svg',
	color: '#A3FF12',
	launchUrl: 'https://tasks.test/auth/login?iss=https%3A%2F%2Faccounts.test',
	displayOrder: 0,
	current: true
};

function fakeFetch(responses: Array<(req: Request) => Response>) {
	const calls: Request[] = [];
	const impl = (async (input: RequestInfo | URL, init?: RequestInit) => {
		const req = new Request(input, init);
		calls.push(req);
		const next = responses.shift();
		if (!next) throw new Error('unexpected fetch');
		return next(req);
	}) as typeof fetch;
	return { impl, calls };
}

const ok = (etag = 'W/"1"') => () =>
	new Response(JSON.stringify({ apps: [APP, { bogus: true }], chooserUrl: 'https://accounts.test/auth/gateways?choose=1' }), {
		headers: { 'content-type': 'application/json', etag }
	});

beforeEach(() => clearLauncherCache());

describe('fetchLauncherApps', () => {
	it('calls /api/auth/me/launcher with the bearer token and drops malformed entries', async () => {
		const f = fakeFetch([ok()]);
		const data = await fetchLauncherApps({ baseUrl: BASE, accessToken: 'tok', fetchImpl: f.impl });
		expect(f.calls[0].url).toBe('https://accounts.test/api/auth/me/launcher');
		expect(f.calls[0].headers.get('authorization')).toBe('Bearer tok');
		expect(data.apps).toEqual([APP]);
		expect(data.chooserUrl).toBe('https://accounts.test/auth/gateways?choose=1');
	});

	it('caches per token, then revalidates with If-None-Match', async () => {
		const f = fakeFetch([ok('W/"x"'), () => new Response(null, { status: 304 })]);
		await fetchLauncherApps({ baseUrl: BASE, accessToken: 'tok', fetchImpl: f.impl });
		await fetchLauncherApps({ baseUrl: BASE, accessToken: 'tok', fetchImpl: f.impl });
		expect(f.calls.length).toBe(1);
		const again = await fetchLauncherApps({ baseUrl: BASE, accessToken: 'tok', fetchImpl: f.impl, cacheTtlMs: -1 });
		expect(f.calls[1].headers.get('if-none-match')).toBe('W/"x"');
		expect(again.apps).toEqual([APP]);
	});

	it('never throws: no token, a 401 or a network error give an empty list', async () => {
		expect(await fetchLauncherApps({ baseUrl: BASE, accessToken: null })).toEqual({ apps: [], chooserUrl: null });
		const f = fakeFetch([() => new Response('{}', { status: 401 }), () => { throw new Error('down'); }]);
		expect((await fetchLauncherApps({ baseUrl: BASE, accessToken: 't1', fetchImpl: f.impl })).apps).toEqual([]);
		expect((await fetchLauncherApps({ baseUrl: BASE, accessToken: 't2', fetchImpl: f.impl })).apps).toEqual([]);
	});

	it('knows where the script lives', () => {
		expect(launcherScriptUrl(BASE)).toBe('https://accounts.test/embed/apps.js');
	});
});

describe('loadLauncherApps (SvelteKit)', () => {
	it("uses the signed-in session's access token", async () => {
		const f = fakeFetch([ok()]);
		const locals = { session: { principal: { identity: {} }, tenant: null, accessToken: 'session-token' } };
		const data = await loadLauncherApps({ locals } as never, { baseUrl: BASE, fetchImpl: f.impl });
		expect(f.calls[0].headers.get('authorization')).toBe('Bearer session-token');
		expect(data.apps).toEqual([APP]);
		expect(data.scriptUrl).toBe('https://accounts.test/embed/apps.js');
	});

	it('signed out: no request, empty list', async () => {
		const f = fakeFetch([]);
		const data = await loadLauncherApps({ locals: { session: { principal: null, tenant: null } } } as never, {
			baseUrl: BASE,
			fetchImpl: f.impl
		});
		expect(f.calls.length).toBe(0);
		expect(data.apps).toEqual([]);
	});
});
