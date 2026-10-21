import { describe, expect, it } from 'vitest';
import { createAccountsClientConfig, exchangeAuthorizationCode } from '../src/index';

const realConfig = createAccountsClientConfig({
	baseUrl: 'https://accounts.example',
	clientId: 'shop',
	redirectUri: 'https://shop.example/auth/callback',
	useMock: false
});

describe('exchangeAuthorizationCode', () => {
	it('never returns the mock identity for a demo_ code when mock mode is off', async () => {
		let calledTokenEndpoint = false;
		const fetchImpl = (async () => {
			calledTokenEndpoint = true;
			return new Response('invalid code', { status: 400 });
		}) as typeof fetch;
		await expect(
			exchangeAuthorizationCode({ config: realConfig, code: 'demo_forged', fetchImpl })
		).rejects.toThrow(/status 400/);
		expect(calledTokenEndpoint).toBe(true);
	});

	it('returns the mock identity in mock mode', async () => {
		const config = createAccountsClientConfig({ useMock: true });
		const token = await exchangeAuthorizationCode({ config, code: 'demo_abc' });
		expect(token.user.id).toBe('accounts-user-demo-admin');
	});
});
