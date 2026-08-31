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
	/** `invited` = an invite was created and an accept link emailed;
	 *  `already_member` = that email already has access to the app (returned with HTTP 409).
	 *  (`added` is legacy: Accounts no longer grants access without acceptance.) */
	status: 'invited' | 'already_member' | 'added';
	/** The workspace the invitee joins on acceptance, echoed back; null when none was requested. */
	userGroupId?: string | null;
	[key: string]: unknown;
}

/**
 * A profile field an app collects about a user — the spec a consumer renders a form input from.
 * Mirrors Accounts' `fields` registry, so a consumer never hardcodes one app's idea of a person.
 */
export interface ProfileFieldSpec {
	id: string;
	fieldName: string;
	label: string;
	fieldType: string;
	required: boolean;
	hidden: boolean;
	enumValues: string[] | null;
	inputPrefix: string | null;
	validationRegex: string | null;
	validationMessage: string | null;
	displayOrder: number;
}

/** Whether an email can be invited to an app. See `checkInviteEmail`. */
export interface InviteEmailCheck {
	email: string;
	/** `member` = already has app access; `invited` = a live invite exists; `available` = go ahead. */
	state: 'member' | 'invited' | 'available';
	/** Whether an Accounts user already exists for this address (they keep their own profile). */
	hasAccount: boolean;
	/** When the pending invite lapses — only for `invited`. */
	expiresAt?: string;
}

/** A pending (not yet accepted, not yet expired) app invitation. */
export interface PendingInvite {
	id: string;
	email: string;
	/** The workspace the invitee joins on acceptance; null for a group-less invite. */
	userGroupId: string | null;
	/** Values captured on the invite form, keyed by field name. Prefills the accept form. */
	profileData?: Record<string, string>;
	createdAt: string;
	expiresAt: string;
	/** The inviter's email, when still resolvable. */
	invitedByEmail?: string | null;
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

	/**
	 * Invite an email to an app, emailing them an accept link. Session-authed (the caller must have
	 * access to the app).
	 *
	 * Pass `userGroupId` to say which WORKSPACE the invitee joins when they accept. Omit it and they
	 * join the app but no workspace — Accounts then treats them as a brand-new user on first login and
	 * sends them to create their own, instead of landing in the workspace that invited them. Accounts
	 * validates the group against the CALLER's own memberships, so this cannot target a foreign group.
	 */
	async inviteToApp(
		appSlug: string,
		input: {
			email: string;
			userGroupId?: string | null;
			/** Profile values from the invite form, keyed by field name (see `listAppProfileFields`).
			 *  Accounts drops any key the app does not collect, so authorization-shaped values
			 *  (role, assignability) can never be set from here. */
			profileData?: Record<string, string> | null;
		}
	): Promise<InviteResult> {
		return this.request<InviteResult>('POST', `/api/auth/apps/${encodeURIComponent(appSlug)}/invites`, {
			auth: 'session',
			body: input
		});
	}

	/**
	 * The profile fields this app collects about a user — the spec to render an invite form from.
	 * Session-authed. Never includes email: that is the invite's identity, not a profile value.
	 */
	async listAppProfileFields(appSlug: string): Promise<ProfileFieldSpec[]> {
		const data = await this.request<{ fields?: ProfileFieldSpec[] }>(
			'GET',
			`/api/auth/apps/${encodeURIComponent(appSlug)}/profile-fields`,
			{ auth: 'session' }
		);
		return data.fields ?? [];
	}

	/**
	 * Whether an email can be invited — for a live check on an invite form, so the inviter learns
	 * BEFORE submitting that someone is already a member or already invited. Email only, exact match.
	 * Session-authed.
	 */
	async checkInviteEmail(appSlug: string, email: string): Promise<InviteEmailCheck> {
		return this.request<InviteEmailCheck>(
			'GET',
			`/api/auth/apps/${encodeURIComponent(appSlug)}/invites/lookup?email=${encodeURIComponent(email)}`,
			{ auth: 'session' }
		);
	}

	/**
	 * Add a user to a workspace group. Service-key authed (`users:write`).
	 *
	 * Membership was read-only over the API, which is why "reactivate user" had to fall back to
	 * re-INVITING an existing colleague. Use this to restore membership instead.
	 */
	async addGroupMember(
		groupId: string,
		userId: string,
		opts: { role?: string } = {}
	): Promise<void> {
		await this.request<unknown>(
			'POST',
			`/api/auth/user-groups/${encodeURIComponent(groupId)}/members`,
			{ auth: 'key', body: { userId, ...(opts.role ? { role: opts.role } : {}) } }
		);
	}

	/**
	 * Remove a user from a workspace group. Service-key authed (`users:write`). Idempotent.
	 *
	 * Removing a user's APP access does NOT remove their group membership, and the members list
	 * reads membership — so without this a "deleted" user keeps reappearing in the workspace.
	 */
	async removeGroupMember(groupId: string, userId: string): Promise<void> {
		await this.request<unknown>(
			'DELETE',
			`/api/auth/user-groups/${encodeURIComponent(groupId)}/members?userId=${encodeURIComponent(userId)}`,
			{ auth: 'key' }
		);
	}

	/** Revoke a pending invite (withdraw one sent in error). Session-authed. */
	async revokeAppInvite(appSlug: string, inviteId: string): Promise<void> {
		await this.request<unknown>(
			'DELETE',
			`/api/auth/apps/${encodeURIComponent(appSlug)}/invites?inviteId=${encodeURIComponent(inviteId)}`,
			{ auth: 'session' }
		);
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

	/**
	 * Restore an existing user's access to an app. Session-authed. Idempotent.
	 *
	 * The counterpart to `removeAppUser`. Distinct from `inviteToApp`: this is for an account that
	 * already exists and already consented, so it must NOT put the person through registration again.
	 */
	async addAppUser(appSlug: string, userId: string): Promise<void> {
		await this.request<unknown>(
			'POST',
			`/api/auth/apps/${encodeURIComponent(appSlug)}/users`,
			{ auth: 'session', body: { userId } }
		);
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
	async listGroupMembers(
		groupId: string,
		opts: { appId?: string; search?: string; limit?: number; offset?: number } = {}
	): Promise<GroupMember[]> {
		const { members } = await this.listGroupMembersPage(groupId, opts);
		return members;
	}

	/**
	 * A PAGE of a group's members, plus the total before paging — what a paginated, searchable user
	 * list needs. `listGroupMembers` stays the "give me everyone" convenience for the agent picker.
	 *
	 * Search and paging are applied by Accounts in SQL: fetching every member to filter in the browser
	 * does not scale, and leaves the pager unable to know how many pages exist. Omit `limit` and the
	 * full list comes back (with `totalCount` equal to its length).
	 */
	async listGroupMembersPage(
		groupId: string,
		opts: { appId?: string; search?: string; limit?: number; offset?: number } = {}
	): Promise<{ members: GroupMember[]; totalCount: number }> {
		const qs = new URLSearchParams();
		if (opts.appId) qs.set('appId', opts.appId);
		if (opts.search) qs.set('search', opts.search);
		if (opts.limit !== undefined) qs.set('limit', String(opts.limit));
		if (opts.offset !== undefined) qs.set('offset', String(opts.offset));
		const suffix = qs.size ? `?${qs}` : '';
		const data = await this.request<{ members?: GroupMember[]; totalCount?: number }>(
			'GET',
			`/api/auth/user-groups/${encodeURIComponent(groupId)}/members${suffix}`,
			{ auth: 'key' }
		);
		const members = data.members ?? [];
		return { members, totalCount: data.totalCount ?? members.length };
	}

	/**
	 * The app's PENDING invites — people invited but not yet accepted. Session-authed.
	 *
	 * An invitee is not a membership, so they appear in no member list; without this a successful
	 * invite looks like nothing happened until the person accepts. Pass `userGroupId` to scope to one
	 * workspace. Accounts excludes consumed and expired invites.
	 */
	async listAppInvites(
		appSlug: string,
		opts: { userGroupId?: string; search?: string; limit?: number; offset?: number } = {}
	): Promise<{ invites: PendingInvite[]; totalCount: number }> {
		const qs = new URLSearchParams();
		if (opts.userGroupId) qs.set('userGroupId', opts.userGroupId);
		if (opts.search) qs.set('search', opts.search);
		if (opts.limit !== undefined) qs.set('limit', String(opts.limit));
		if (opts.offset !== undefined) qs.set('offset', String(opts.offset));
		const suffix = qs.size ? `?${qs}` : '';
		const data = await this.request<{ invites?: PendingInvite[]; totalCount?: number }>(
			'GET',
			`/api/auth/apps/${encodeURIComponent(appSlug)}/invites${suffix}`,
			{ auth: 'session' }
		);
		const invites = data.invites ?? [];
		return { invites, totalCount: data.totalCount ?? invites.length };
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
