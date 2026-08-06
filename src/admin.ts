// Accounts management client — typed wrappers over the Axis Accounts admin/management HTTP surface.
//
// The rest of the SDK resolves incoming credentials (sessions, service keys, webhooks). This module is
// the OUTBOUND half: a small client an app's server uses to MANAGE users in Accounts — list them,
// invite them to an app, update their profile, list/remove app members, and read/write app-scoped
// profile fields (used for per-app preferences like availability/sound that Accounts stores in
// `profile_data`). It is framework-agnostic and does no caching; hosts own that.
//
// Auth: some endpoints are session-authed (invites, profile update — the acting user's Accounts
// session bearer), others take a machine service key via `x-api-key` (group-member reads gated by
// `stats:read`). Provide whichever the calls you make require; each method documents which it uses.

export interface AccountsAdminOptions {
	/** Accounts base URL, e.g. `https://accounts.example.com`. */
	baseUrl: string;
	/** A user session id (bearer) for session-authed endpoints (invites, profile update, user list). */
	sessionToken?: string;
	/** A machine service key (`sk_…`) for `x-api-key`-authed reads (group members). */
	serviceKey?: string;
	/** Override the fetch implementation (defaults to the global). */
	fetchImpl?: typeof fetch;
}

export interface AccountsUser {
	id: string;
	email: string;
	name?: string | null;
	firstName?: string | null;
	lastName?: string | null;
	emailVerified?: boolean;
	/** The user's avatar URL (from their latest OAuth sign-in with a picture, or their upload). */
	avatarUrl?: string | null;
	profileData?: Record<string, string>;
	userGroups?: Array<{ id: string; slug?: string; displayName?: string; role?: string }>;
	apps?: Array<{ id: string; slug: string; name?: string }>;
	[key: string]: unknown;
}

export interface ChangePasswordResult {
	success: boolean;
	mode?: 'set' | 'changed';
	revokedCount?: number;
	error?: string;
}

export interface ListUsersQuery {
	tenantId?: string;
	appId?: string;
	q?: string;
	name?: string;
	email?: string;
	limit?: number;
	offset?: number;
}

export interface ListUsersResult {
	users: AccountsUser[];
	pagination?: { total: number; limit: number; offset: number };
}

export interface AppMember {
	id: string;
	email: string;
	name?: string | null;
	via?: 'member' | 'role';
}

export interface InviteResult {
	/** `added` = the email already had an Accounts user and was granted app access immediately;
	 *  `invited` = a new invite was created and an accept link emailed. */
	status: 'added' | 'invited';
	[key: string]: unknown;
}

export interface GroupMember {
	id: string;
	email: string;
	name?: string | null;
	firstName?: string | null;
	lastName?: string | null;
	role?: string | null;
}

/** Thrown on a non-2xx Accounts response so callers can surface the upstream message + status. */
export class AccountsAdminError extends Error {
	constructor(
		readonly status: number,
		message: string,
		readonly body?: unknown
	) {
		super(message);
		this.name = 'AccountsAdminError';
	}
}

export class AccountsAdmin {
	private readonly base: string;
	private readonly f: typeof fetch;

	constructor(private readonly opts: AccountsAdminOptions) {
		const base = (opts.baseUrl ?? '').trim();
		if (!base) throw new Error('AccountsAdmin: baseUrl is required.');
		this.base = base.replace(/\/+$/, '');
		this.f = opts.fetchImpl ?? fetch;
	}

	// ── Users ──────────────────────────────────────────────────────────────────

	/** List/search users in a tenant. Session-authed (caller must be privileged in the tenant). */
	async listUsers(query: ListUsersQuery = {}): Promise<ListUsersResult> {
		const qs = new URLSearchParams();
		for (const [k, v] of Object.entries(query)) {
			if (v !== undefined && v !== null) qs.set(k, String(v));
		}
		const suffix = qs.toString() ? `?${qs.toString()}` : '';
		const data = await this.request<{ users?: AccountsUser[]; pagination?: ListUsersResult['pagination'] }>(
			'GET',
			`/api/auth/users${suffix}`,
			{ auth: 'session' }
		);
		return { users: data.users ?? [], ...(data.pagination ? { pagination: data.pagination } : {}) };
	}

	/** One user's full detail (includes `profileData`, `userGroups`, `apps`). Session-authed. */
	async getUser(userId: string): Promise<AccountsUser> {
		return this.request<AccountsUser>('GET', `/api/auth/users/${encodeURIComponent(userId)}`, {
			auth: 'session'
		});
	}

	/** Update a user (self, or admin/owner/super-admin). `profileData` requires `appId`. Session-authed.
	 *  Password is NOT set here — use {@link changePassword} (Accounts verifies the current password). */
	async updateUser(
		userId: string,
		input: {
			name?: string;
			email?: string;
			appId?: string;
			profileData?: Record<string, string>;
		}
	): Promise<AccountsUser> {
		return this.request<AccountsUser>('PATCH', `/api/auth/users/${encodeURIComponent(userId)}`, {
			auth: 'session',
			body: input
		});
	}

	/** Change the signed-in user's password. Session-authed; Accounts verifies `currentPassword` and,
	 *  with `revokeOtherSessions`, logs the user out everywhere else. The target is the session's own
	 *  user — no id is passed. */
	async changePassword(input: {
		currentPassword: string;
		newPassword: string;
		confirmPassword?: string;
		revokeOtherSessions?: boolean;
	}): Promise<ChangePasswordResult> {
		return this.request<ChangePasswordResult>('POST', '/api/auth/change-password', {
			auth: 'session',
			body: {
				currentPassword: input.currentPassword,
				newPassword: input.newPassword,
				confirmPassword: input.confirmPassword ?? input.newPassword,
				...(input.revokeOtherSessions !== undefined
					? { revokeOtherSessions: input.revokeOtherSessions }
					: {})
			}
		});
	}

	// ── App membership (invite / list / remove) ─────────────────────────────────

	/** Invite an email to an app: adds an existing Accounts user immediately, else emails an accept
	 *  link. Session-authed (caller must have access to the app). */
	async inviteToApp(appSlug: string, input: { email: string }): Promise<InviteResult> {
		return this.request<InviteResult>('POST', `/api/auth/apps/${encodeURIComponent(appSlug)}/invites`, {
			auth: 'session',
			body: input
		});
	}

	/** Everyone with access to an app. Session-authed. */
	async listAppUsers(appSlug: string): Promise<AppMember[]> {
		const data = await this.request<{ users?: AppMember[] }>(
			'GET',
			`/api/auth/apps/${encodeURIComponent(appSlug)}/users`,
			{ auth: 'session' }
		);
		return data.users ?? [];
	}

	/** Revoke a user's access to an app. Session-authed. */
	async removeAppUser(appSlug: string, userId: string): Promise<void> {
		await this.request<unknown>(
			'DELETE',
			`/api/auth/apps/${encodeURIComponent(appSlug)}/users?userId=${encodeURIComponent(userId)}`,
			{ auth: 'session' }
		);
	}

	// ── Groups (agent picker) ───────────────────────────────────────────────────

	/** Members of a user_group (the workspace's agents). Service-key authed (`stats:read`). */
	async listGroupMembers(groupId: string, opts: { appId?: string } = {}): Promise<GroupMember[]> {
		const suffix = opts.appId ? `?appId=${encodeURIComponent(opts.appId)}` : '';
		const data = await this.request<{ members?: GroupMember[] }>(
			'GET',
			`/api/auth/user-groups/${encodeURIComponent(groupId)}/members${suffix}`,
			{ auth: 'key' }
		);
		return data.members ?? [];
	}

	// ── App-scoped profile (availability / sound / any per-app preference) ───────

	/** Read a user's app-scoped `profileData` (the store for per-app preferences). Session-authed. */
	async getAppProfile(userId: string): Promise<Record<string, string>> {
		const user = await this.getUser(userId);
		return user.profileData ?? {};
	}

	/** Write app-scoped `profileData` fields for a user (e.g. availability, soundEnabled). All values
	 *  are stored as strings by Accounts; booleans are serialised. Session-authed. */
	async setAppProfile(
		userId: string,
		appId: string,
		profile: Record<string, string | number | boolean>
	): Promise<AccountsUser> {
		const profileData: Record<string, string> = {};
		for (const [k, v] of Object.entries(profile)) profileData[k] = String(v);
		return this.updateUser(userId, { appId, profileData });
	}

	// ── Avatar (uploaded image; social avatars are captured server-side on sign-in) ─

	/** Upload a user's avatar image. The bytes are stored by Accounts and a public URL is returned +
	 *  persisted (source = 'upload', which survives later OAuth sign-ins). Session-authed, self-only.
	 *  `image` is the file bytes (Blob/Buffer/Uint8Array); `mimeType` + `filename` describe it. */
	async uploadAvatar(
		userId: string,
		image: Blob | ArrayBuffer | Uint8Array,
		opts: { mimeType?: string; filename?: string } = {}
	): Promise<{ avatarUrl: string }> {
		if (!this.opts.sessionToken) {
			throw new Error('AccountsAdmin: a session token is required to upload an avatar.');
		}
		const mimeType = opts.mimeType ?? 'application/octet-stream';
		const blob =
			image instanceof Blob ? image : new Blob([image as BlobPart], { type: mimeType });
		const form = new FormData();
		form.append('avatar', blob, opts.filename ?? 'avatar');
		const res = await this.f(
			new URL(`/api/auth/users/${encodeURIComponent(userId)}/avatar`, this.base),
			{
				method: 'POST',
				headers: { authorization: `Bearer ${this.opts.sessionToken}`, accept: 'application/json' },
				body: form
			}
		);
		const text = await res.text();
		const parsed = text ? JSON.parse(text) : {};
		if (!res.ok) {
			throw new AccountsAdminError(res.status, parsed?.error ?? 'Avatar upload failed.', parsed);
		}
		return parsed as { avatarUrl: string };
	}

	/** Remove a user's uploaded avatar (clears it, or reverts to their latest OAuth picture if any).
	 *  Session-authed, self-only. */
	async removeAvatar(userId: string): Promise<{ avatarUrl: string | null }> {
		return this.request<{ avatarUrl: string | null }>(
			'DELETE',
			`/api/auth/users/${encodeURIComponent(userId)}/avatar`,
			{ auth: 'session' }
		);
	}

	// ── internals ───────────────────────────────────────────────────────────────

	private async request<T>(
		method: string,
		path: string,
		opts: { auth: 'session' | 'key'; body?: unknown }
	): Promise<T> {
		const headers: Record<string, string> = { accept: 'application/json' };
		if (opts.auth === 'session') {
			if (!this.opts.sessionToken) {
				throw new Error(`AccountsAdmin: a session token is required for ${method} ${path}.`);
			}
			headers.authorization = `Bearer ${this.opts.sessionToken}`;
		} else {
			if (!this.opts.serviceKey) {
				throw new Error(`AccountsAdmin: a service key is required for ${method} ${path}.`);
			}
			headers['x-api-key'] = this.opts.serviceKey;
		}
		let bodyStr: string | undefined;
		if (opts.body !== undefined) {
			bodyStr = JSON.stringify(opts.body);
			headers['content-type'] = 'application/json';
		}
		const res = await this.f(new URL(path, this.base), { method, headers, body: bodyStr });
		const text = await res.text();
		let parsed: unknown;
		try {
			parsed = text ? JSON.parse(text) : undefined;
		} catch {
			parsed = text;
		}
		if (!res.ok) {
			const message =
				(parsed && typeof parsed === 'object' && 'error' in parsed
					? String((parsed as { error?: unknown }).error)
					: undefined) ?? `Accounts request failed with status ${res.status}.`;
			throw new AccountsAdminError(res.status, message, parsed);
		}
		return parsed as T;
	}
}

/** Convenience factory mirroring the SDK's other `create*` helpers. */
export function createAccountsAdmin(opts: AccountsAdminOptions): AccountsAdmin {
	return new AccountsAdmin(opts);
}
