import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { generateKeyPair, SignJWT, exportJWK, createLocalJWKSet } from 'jose';

import {
	createAithneClient,
	isJWKSInfraError,
	createServeStaleJWKS,
	parseCookies,
} from './index.js';

// ─── parseCookies ───────────────────────────────────────────────────────────

describe('parseCookies', () => {
	it('returns empty object for undefined header', () => {
		assert.deepEqual(parseCookies(undefined), {});
	});

	it('returns empty object for empty string', () => {
		assert.deepEqual(parseCookies(''), {});
	});

	it('parses a single cookie', () => {
		assert.deepEqual(parseCookies('foo=bar'), { foo: 'bar' });
	});

	it('parses multiple cookies', () => {
		assert.deepEqual(parseCookies('foo=bar; baz=qux'), { foo: 'bar', baz: 'qux' });
	});

	it('preserves = within cookie value (e.g. base64 JWT padding)', () => {
		assert.deepEqual(
			parseCookies('aithne_session=abc.def.ghi=='),
			{ aithne_session: 'abc.def.ghi==' }
		);
	});

	it('only splits on the first = in a pair', () => {
		assert.deepEqual(parseCookies('k=a=b=c'), { k: 'a=b=c' });
	});
});

// ─── isJWKSInfraError ───────────────────────────────────────────────────────

describe('isJWKSInfraError', () => {
	it('true for error.code ECONNREFUSED (direct-throw shape)', () => {
		assert.equal(isJWKSInfraError(Object.assign(new Error('x'), { code: 'ECONNREFUSED' })), true);
	});

	it('true for error.code ENOTFOUND', () => {
		assert.equal(isJWKSInfraError(Object.assign(new Error('x'), { code: 'ENOTFOUND' })), true);
	});

	it('true for error.code ERR_JWKS_TIMEOUT', () => {
		assert.equal(isJWKSInfraError(Object.assign(new Error('x'), { code: 'ERR_JWKS_TIMEOUT' })), true);
	});

	it('true for error.cause.code ECONNREFUSED (native-fetch wrapped shape — bug #1)', () => {
		const error = new TypeError('fetch failed', { cause: Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }) });
		assert.equal(isJWKSInfraError(error), true);
	});

	it('true for error.cause.code ENOTFOUND (native-fetch wrapped shape)', () => {
		const error = new TypeError('fetch failed', { cause: Object.assign(new Error('nx'), { code: 'ENOTFOUND' }) });
		assert.equal(isJWKSInfraError(error), true);
	});

	it('false for ERR_JWKS_NO_MATCHING_KEY — a genuine token rejection, not an outage', () => {
		assert.equal(isJWKSInfraError(Object.assign(new Error('x'), { code: 'ERR_JWKS_NO_MATCHING_KEY' })), false);
	});

	it('false for an unrelated error with no code', () => {
		assert.equal(isJWKSInfraError(new Error('boom')), false);
	});

	it('false for a plain signature-verification error', () => {
		assert.equal(isJWKSInfraError(Object.assign(new Error('bad sig'), { code: 'ERR_JWS_SIGNATURE_VERIFICATION_FAILED' })), false);
	});
});

// ─── createServeStaleJWKS ───────────────────────────────────────────────────

describe('createServeStaleJWKS', () => {
	function infraError(code = 'ECONNREFUSED') {
		return Object.assign(new Error('connect failed'), { code });
	}

	it('cold start (no last-known-good) rethrows on infra failure', async () => {
		const remote = async () => { throw infraError(); };
		remote.jwks = () => null;
		const wrapped = createServeStaleJWKS(remote, { logger: { warn() {} } });
		await assert.rejects(() => wrapped({}, 'token'), (err) => err.code === 'ECONNREFUSED');
	});

	it('serves last-known-good on infra failure after a prior success', async () => {
		let callCount = 0;
		const fakeJwks = { keys: [{ kid: 'k1' }] };
		const remote = async () => {
			callCount += 1;
			if (callCount === 1) return 'first-key';
			throw infraError();
		};
		remote.jwks = () => fakeJwks;

		const warnings = [];
		const wrapped = createServeStaleJWKS(remote, { logger: { warn: (...args) => warnings.push(args) } });

		// First call succeeds and snapshots the key set.
		await wrapped({}, 'token1');
		// Second call: remote throws, so serve-stale should fall back instead
		// of propagating — createLocalJWKSet(fakeJwks) will itself throw
		// (no matching kid 'k1' unless requested), but the point under test
		// is that it attempted the fallback rather than rethrowing the raw
		// connection error.
		await assert.rejects(() => wrapped({ kid: 'nonexistent' }, 'token2'));
		assert.equal(warnings.length, 1);
		assert.match(warnings[0][0], /serving last-known-good/);
	});

	it('propagates non-infra errors without touching the cache', async () => {
		const remote = async () => { throw new Error('some other jose error'); };
		remote.jwks = () => null;
		const wrapped = createServeStaleJWKS(remote, { logger: { warn() {} } });
		await assert.rejects(() => wrapped({}, 'token'), /some other jose error/);
	});
});

// ─── loginUrl ───────────────────────────────────────────────────────────────

describe('loginUrl', () => {
	it('bare login URL when no returnUrl given', () => {
		const aithne = createAithneClient({ origin: 'https://aithne.l42.eu' });
		assert.equal(aithne.loginUrl(), 'https://aithne.l42.eu/auth/login');
	});

	it('embeds a returnUrl on the configured origin', () => {
		const aithne = createAithneClient({ origin: 'https://aithne.l42.eu' });
		const url = aithne.loginUrl('https://aithne.l42.eu/some/page');
		assert.equal(url, 'https://aithne.l42.eu/auth/login?next=https%3A%2F%2Faithne.l42.eu%2Fsome%2Fpage');
	});

	it('embeds a returnUrl on an *.l42.eu subdomain (the common case — the caller\'s own origin)', () => {
		const aithne = createAithneClient({ origin: 'https://aithne.l42.eu' });
		const url = aithne.loginUrl('https://notes.l42.eu/page?x=1');
		assert.match(url, /^https:\/\/aithne\.l42\.eu\/auth\/login\?next=/);
		assert.equal(decodeURIComponent(url.split('next=')[1]), 'https://notes.l42.eu/page?x=1');
	});

	it('drops an untrusted returnUrl (different domain) — falls back to a bare login URL', () => {
		const aithne = createAithneClient({ origin: 'https://aithne.l42.eu' });
		assert.equal(aithne.loginUrl('https://evil.example.com/'), 'https://aithne.l42.eu/auth/login');
	});

	it('drops a returnUrl that merely contains l42.eu as a substring, not a suffix', () => {
		const aithne = createAithneClient({ origin: 'https://aithne.l42.eu' });
		assert.equal(aithne.loginUrl('https://l42.eu.evil.com/'), 'https://aithne.l42.eu/auth/login');
	});

	it('drops a non-https returnUrl even on l42.eu', () => {
		const aithne = createAithneClient({ origin: 'https://aithne.l42.eu' });
		assert.equal(aithne.loginUrl('http://notes.l42.eu/'), 'https://aithne.l42.eu/auth/login');
	});

	it('drops a malformed returnUrl rather than throwing', () => {
		const aithne = createAithneClient({ origin: 'https://aithne.l42.eu' });
		assert.equal(aithne.loginUrl('not a url'), 'https://aithne.l42.eu/auth/login');
	});
});

// ─── hasScope ───────────────────────────────────────────────────────────────

describe('hasScope', () => {
	it('true when payload has the required scope', () => {
		const aithne = createAithneClient({});
		assert.equal(aithne.hasScope({ scopes: ['notes:use'] }, 'notes:use'), true);
	});

	it('false when payload lacks the required scope', () => {
		const aithne = createAithneClient({});
		assert.equal(aithne.hasScope({ scopes: ['other:scope'] }, 'notes:use'), false);
	});

	it('false when payload has no scopes at all', () => {
		const aithne = createAithneClient({});
		assert.equal(aithne.hasScope({}, 'notes:use'), false);
	});

	it('accepts an array of acceptable scopes (OR semantics)', () => {
		const aithne = createAithneClient({});
		assert.equal(aithne.hasScope({ scopes: ['notes:use'] }, ['creds:admin', 'notes:use']), true);
	});

	it('render-ui bypass grants access when environment is development', () => {
		const aithne = createAithneClient({ environment: 'development' });
		assert.equal(aithne.hasScope({ scopes: ['render-ui'] }, 'notes:use'), true);
	});

	it('render-ui bypass does NOT apply when environment is production', () => {
		const aithne = createAithneClient({ environment: 'production' });
		assert.equal(aithne.hasScope({ scopes: ['render-ui'] }, 'notes:use'), false);
	});

	it('render-ui bypass does NOT apply when environment is unset', () => {
		const aithne = createAithneClient({});
		assert.equal(aithne.hasScope({ scopes: ['render-ui'] }, 'notes:use'), false);
	});
});

// ─── verifySession / verifyToken — classification via the _setVerifier seam ─

describe('verifySession / verifyToken classification', () => {
	function makeClient(opts = {}) {
		return createAithneClient({ origin: 'https://aithne.l42.eu', ...opts });
	}

	it('no cookie at all → unauthenticated, no error', async () => {
		const aithne = makeClient();
		const result = await aithne.verifySession(undefined);
		assert.deepEqual(result, { outcome: 'unauthenticated', payload: null, error: null });
	});

	it('cookie header present but no aithne_session cookie → unauthenticated, no error', async () => {
		const aithne = makeClient();
		const result = await aithne.verifySession('other=1');
		assert.deepEqual(result, { outcome: 'unauthenticated', payload: null, error: null });
	});

	it('valid token, no gate → authorized (authenticated-only meaning), payload present', async () => {
		const aithne = makeClient();
		aithne._setVerifier(async () => ({ payload: { sub: '42', scopes: [] } }));
		const result = await aithne.verifySession('aithne_session=valid.jwt.token');
		assert.equal(result.outcome, 'authorized');
		assert.deepEqual(result.payload, { sub: '42', scopes: [] });
		assert.equal(result.error, null);
	});

	it('valid token + requiredScope present → authorized', async () => {
		const aithne = makeClient();
		aithne._setVerifier(async () => ({ payload: { sub: '42', scopes: ['notes:use'] } }));
		const result = await aithne.verifySession('aithne_session=t', { requiredScope: 'notes:use' });
		assert.equal(result.outcome, 'authorized');
	});

	it('valid token + requiredScope missing → forbidden, payload still present (so consumer can log sub)', async () => {
		const aithne = makeClient();
		aithne._setVerifier(async () => ({ payload: { sub: '42', scopes: ['other:scope'] } }));
		const result = await aithne.verifySession('aithne_session=t', { requiredScope: 'notes:use' });
		assert.equal(result.outcome, 'forbidden');
		assert.deepEqual(result.payload, { sub: '42', scopes: ['other:scope'] });
	});

	it('valid token + authorize predicate: granted', async () => {
		const aithne = makeClient();
		aithne._setVerifier(async () => ({ payload: { sub: '7' } }));
		const result = await aithne.verifySession('aithne_session=t', { authorize: (p) => p.sub === '7' });
		assert.equal(result.outcome, 'authorized');
	});

	it('valid token + authorize predicate: denied', async () => {
		const aithne = makeClient();
		aithne._setVerifier(async () => ({ payload: { sub: '7' } }));
		const result = await aithne.verifySession('aithne_session=t', { authorize: (p) => p.sub === '999' });
		assert.equal(result.outcome, 'forbidden');
	});

	it('genuine JWT validation failure → unauthenticated, sanitised error present, no payload', async () => {
		const aithne = makeClient();
		aithne._setVerifier(async () => { throw new Error('signature verification failed'); });
		const result = await aithne.verifySession('aithne_session=bad.jwt');
		assert.equal(result.outcome, 'unauthenticated');
		assert.equal(result.payload, null);
		assert.equal(result.error.message, 'signature verification failed');
	});

	it('JWKS infra failure (ECONNREFUSED) → unavailable, sanitised error present, no payload', async () => {
		const aithne = makeClient();
		aithne._setVerifier(async () => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); });
		const result = await aithne.verifySession('aithne_session=t');
		assert.equal(result.outcome, 'unavailable');
		assert.equal(result.payload, null);
		assert.equal(result.error.message, 'connect ECONNREFUSED');
	});

	it('JWKS infra failure via native-fetch-wrapped cause.code → unavailable', async () => {
		const aithne = makeClient();
		aithne._setVerifier(async () => {
			throw new TypeError('fetch failed', { cause: Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }) });
		});
		const result = await aithne.verifySession('aithne_session=t');
		assert.equal(result.outcome, 'unavailable');
	});

	it('ERR_JWKS_NO_MATCHING_KEY is classified unauthenticated, not unavailable', async () => {
		const aithne = makeClient();
		aithne._setVerifier(async () => { throw Object.assign(new Error('no matching key found for kid "abc"'), { code: 'ERR_JWKS_NO_MATCHING_KEY' }); });
		const result = await aithne.verifySession('aithne_session=t');
		assert.equal(result.outcome, 'unauthenticated');
	});

	it('sanitises control characters out of a kid-bearing error message before returning it', async () => {
		const aithne = makeClient();
		const maliciousKid = 'abc\n\x1b[31mFAKE LOG LINE\x1b[0m\x7f';
		aithne._setVerifier(async () => {
			throw Object.assign(new Error(`no matching key found for kid "${maliciousKid}"`), { code: 'ERR_JWKS_NO_MATCHING_KEY' });
		});
		const result = await aithne.verifySession('aithne_session=t');
		assert.ok(!/[\x00-\x1f\x7f]/.test(result.error.message), 'error.message must not contain control characters');
		assert.ok(result.error.message.includes('FAKE LOG LINE'), 'sanitisation strips control chars, not the surrounding text');
	});

	it('verifyToken applies the identical gate semantics as verifySession (no cookie-extraction footgun)', async () => {
		const aithne = makeClient();
		aithne._setVerifier(async () => ({ payload: { sub: '1', scopes: [] } }));
		const result = await aithne.verifyToken('raw.jwt.token', { requiredScope: 'notes:use' });
		assert.equal(result.outcome, 'forbidden');
	});

	it('verifyToken with no token → unauthenticated, no error', async () => {
		const aithne = makeClient();
		const result = await aithne.verifyToken(undefined);
		assert.deepEqual(result, { outcome: 'unauthenticated', payload: null, error: null });
	});

	it('two independently-created clients do not share verifier state', async () => {
		const a = makeClient();
		const b = makeClient();
		a._setVerifier(async () => ({ payload: { sub: 'a', scopes: [] } }));
		// b's real verifier is untouched — calling it with a fake token must
		// fail (not silently reuse a's stub), proving each client instance
		// carries independent internal state.
		const result = await b.verifySession('aithne_session=not.a.real.jwt');
		assert.notEqual(result.outcome, 'authorized');
	});
});

// ─── End-to-end: real jose crypto, no network (local JWKS swapped in) ──────

describe('end-to-end verification against real jose crypto', () => {
	async function makeSignedToken({ payload, alg = 'ES256', kid = 'test-key-1' } = {}) {
		const { privateKey, publicKey } = await generateKeyPair(alg, { extractable: true });
		const jwk = await exportJWK(publicKey);
		jwk.kid = kid;
		jwk.alg = alg;
		const localJWKS = createLocalJWKSet({ keys: [jwk] });

		const token = await new SignJWT(payload)
			.setProtectedHeader({ alg, kid })
			.setIssuedAt()
			.setIssuer('https://aithne.l42.eu')
			.setAudience('l42.eu')
			.setExpirationTime('5m')
			.sign(privateKey);

		return { token, localJWKS };
	}

	it('a validly-signed, well-formed token verifies and authorizes', async () => {
		const { token, localJWKS } = await makeSignedToken({ payload: { sub: '42', scopes: ['notes:use'] } });
		const aithne = createAithneClient({ origin: 'https://aithne.l42.eu' });
		// Bypass the network JWKS fetch with a real local key set — this still
		// exercises jose's actual signature/issuer/audience/algorithm checks.
		aithne._setVerifier(async (t, _jwks, opts) => {
			const { jwtVerify } = await import('jose');
			return jwtVerify(t, localJWKS, opts);
		});

		const result = await aithne.verifySession('aithne_session=' + token, { requiredScope: 'notes:use' });
		assert.equal(result.outcome, 'authorized');
		assert.equal(result.payload.sub, '42');
	});

	it('rejects a token signed with a non-ES256 algorithm (algorithm-confusion defence)', async () => {
		const { token, localJWKS } = await makeSignedToken({ payload: { sub: '42', scopes: [] }, alg: 'RS256' });
		const aithne = createAithneClient({ origin: 'https://aithne.l42.eu' });
		aithne._setVerifier(async (t, _jwks, opts) => {
			const { jwtVerify } = await import('jose');
			return jwtVerify(t, localJWKS, opts);
		});

		const result = await aithne.verifySession('aithne_session=' + token);
		assert.equal(result.outcome, 'unauthenticated');
	});

	it('rejects a token with the wrong issuer', async () => {
		const { privateKey, publicKey } = await generateKeyPair('ES256', { extractable: true });
		const jwk = await exportJWK(publicKey);
		jwk.kid = 'k1';
		jwk.alg = 'ES256';
		const localJWKS = createLocalJWKSet({ keys: [jwk] });
		const token = await new SignJWT({ sub: '1', scopes: [] })
			.setProtectedHeader({ alg: 'ES256', kid: 'k1' })
			.setIssuedAt()
			.setIssuer('https://evil.example.com')
			.setAudience('l42.eu')
			.setExpirationTime('5m')
			.sign(privateKey);

		const aithne = createAithneClient({ origin: 'https://aithne.l42.eu' });
		aithne._setVerifier(async (t, _jwks, opts) => {
			const { jwtVerify } = await import('jose');
			return jwtVerify(t, localJWKS, opts);
		});

		const result = await aithne.verifySession('aithne_session=' + token);
		assert.equal(result.outcome, 'unauthenticated');
	});
});
