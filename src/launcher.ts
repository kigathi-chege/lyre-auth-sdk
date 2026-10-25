// App switcher data for the `<nipate-apps>` menu. Browser-safe (fetch only, no node:*), so it is
// usable from an app's server (recommended: no CORS, the token never reaches the page) or straight
// from a browser that holds an access token (Accounts allows CORS from registered app origins,
// without credentials). Added 0.13.0.

/** One app in the switcher (`GET /api/auth/me/launcher`). */
export type LauncherApp = {
	id: string;
	slug: string;
	name: string;
	/** One short line about the app. */
	description: string | null;
	/** Absolute URL of the app's mark, or null. */
	iconUrl: string | null;
	/** Brand colour, #rrggbb. */
	color: string;
	/** Open the app here: its initiate_login_uri (silent sign-in via Accounts), else its origin. */
	launchUrl: string;
	displayOrder: number;
	/** True for the app whose access token asked. */
	current: boolean;
};

export type LauncherData = {
	apps: LauncherApp[];
	/** Accounts' full app chooser, for an "All apps" link. */
	chooserUrl: string | null;
};

export type FetchLauncherOptions = {
	/** Accounts base URL (the issuer), e.g. https://accounts.nipate.africa */
	baseUrl: string;
	/** The signed-in user's Accounts access token (at+jwt). */
	accessToken: string | null | undefined;
	fetchImpl?: typeof fetch;
	/** Reuse a result for this long per token (ms). Default 60000, matching Accounts' max-age. 0 disables. */
	cacheTtlMs?: number;
	/** Abort after this long (ms). Default 3000: a slow Accounts must not slow the app's page. */
	timeoutMs?: number;
};

const EMPTY: LauncherData = { apps: [], chooserUrl: null };
const cache = new Map<string, { at: number; etag: string | null; data: LauncherData }>();
const MAX_CACHE = 500;

function trimBase(baseUrl: string): string {
	return baseUrl.replace(/\/+$/, '');
}

/** URL of the `<nipate-apps>` script Accounts serves. */
export function launcherScriptUrl(baseUrl: string): string {
	return `${trimBase(baseUrl)}/embed/apps.js`;
}

/** URL of the switcher list endpoint. */
export function launcherEndpoint(baseUrl: string): string {
	return `${trimBase(baseUrl)}/api/auth/me/launcher`;
}

function isLauncherApp(value: unknown): value is LauncherApp {
	const a = value as LauncherApp;
	return Boolean(a) && typeof a.id === 'string' && typeof a.name === 'string' && typeof a.launchUrl === 'string';
}

/**
 * The apps the user can switch to. Never throws: no token, a refusal or an unreachable Accounts
 * gives `{ apps: [], chooserUrl: null }` (the menu then shows nothing rather than breaking a page).
 * Results are cached per token for `cacheTtlMs` and revalidated with ETag after that.
 */
export async function fetchLauncherApps(opts: FetchLauncherOptions): Promise<LauncherData> {
	const token = opts.accessToken;
	if (!token || !opts.baseUrl) return EMPTY;
	const ttl = opts.cacheTtlMs ?? 60_000;
	const now = Date.now();
	const hit = cache.get(token);
	if (hit && ttl > 0 && now - hit.at < ttl) return hit.data;

	const doFetch = opts.fetchImpl ?? fetch;
	const controller = typeof AbortController === 'undefined' ? null : new AbortController();
	const timer = controller ? setTimeout(() => controller.abort(), opts.timeoutMs ?? 3000) : null;
	try {
		const headers: Record<string, string> = { authorization: `Bearer ${token}`, accept: 'application/json' };
		if (hit?.etag) headers['if-none-match'] = hit.etag;
		const res = await doFetch(launcherEndpoint(opts.baseUrl), { headers, signal: controller?.signal });
		if (res.status === 304 && hit) {
			cache.set(token, { ...hit, at: now });
			return hit.data;
		}
		if (!res.ok) {
			cache.delete(token);
			return EMPTY;
		}
		const body = (await res.json()) as Partial<LauncherData>;
		const data: LauncherData = {
			apps: Array.isArray(body.apps) ? body.apps.filter(isLauncherApp) : [],
			chooserUrl: typeof body.chooserUrl === 'string' ? body.chooserUrl : null
		};
		if (ttl > 0) {
			if (cache.size >= MAX_CACHE) {
				for (const [k, v] of cache) if (now - v.at >= ttl) cache.delete(k);
				if (cache.size >= MAX_CACHE) cache.clear();
			}
			cache.set(token, { at: now, etag: res.headers.get('etag'), data });
		}
		return data;
	} catch {
		return hit?.data ?? EMPTY;
	} finally {
		if (timer) clearTimeout(timer);
	}
}

/** Forget cached lists (tests, or after a sign-out when you want the next call to go upstream). */
export function clearLauncherCache(): void {
	cache.clear();
}
