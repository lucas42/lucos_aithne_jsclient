// lucos_aithne_jsclient — shared JS verify-and-classify library for aithne
// session tokens (ADR-0001, docs/adr/0001-foundational-design.md).
//
// The library VERIFIES and CLASSIFIES; the consumer PRESENTS (ADR-0001 §1).
// It reads no process.env itself — all environment-varying config is
// injected via createAithneClient(config).

import { jwtVerify, createRemoteJWKSet, createLocalJWKSet } from 'jose';

// Strips control characters (C0 + DEL) from a string before it reaches a log
// line or a Classification.error. `kid` is an attacker-controlled JWT header
// field that jose embeds verbatim in some error messages (e.g.
// ERR_JWKS_NO_MATCHING_KEY) — an unsanitised message is a log-injection /
// terminal-forging vector (ADR-0001 §5, lucas42/lucos_arachne#646).
const CONTROL_CHARS = /[\x00-\x1f\x7f]/g;

function sanitiseMessage(message) {
	return typeof message === 'string' ? message.replace(CONTROL_CHARS, '') : message;
}

/**
 * Build a sanitised Error safe to log or surface on Classification.error.
 * Preserves name/code (useful for a consumer's own logging) but never the
 * raw, unsanitised message.
 *
 * Falls back to error.cause?.code when error.code is absent — the same
 * native-fetch-wrapped shape isJWKSInfraError() checks (bug #1). Without
 * this fallback, a consumer inspecting Classification.error.code on an
 * 'unavailable' outcome produced by that shape would see undefined even
 * though the classification correctly identified it as a JWKS infra error.
 */
function sanitiseError(error) {
	const safe = new Error(sanitiseMessage(error?.message));
	if (error?.name) safe.name = error.name;
	const code = error?.code ?? error?.cause?.code;
	if (code) safe.code = code;
	return safe;
}

/**
 * True if a jose error indicates a JWKS infrastructure failure (aithne
 * unreachable or timed out) rather than a JWT validation failure (bad
 * signature, expired token, wrong audience, or an unrecognised kid).
 *
 * Checks BOTH `error.code` (the older direct-throw shape) and
 * `error.cause?.code` — Node's native `fetch` (which jose's
 * createRemoteJWKSet uses) wraps connection failures as
 * `TypeError('fetch failed', { cause: <err with .code> })`, so a real
 * ECONNREFUSED/ENOTFOUND lands on `error.cause.code`, not `error.code`.
 * Checking only `error.code` (as every copy-pasted consumer module did)
 * means the serve-stale fallback this function gates plausibly never
 * engages on a genuine connection-refused (lucas42/lucos#260 bug #1).
 *
 * Deliberately narrower than "any ERR_JWKS_* code": ERR_JWKS_NO_MATCHING_KEY
 * (thrown by RemoteJWKSet.getKey() when a token's kid isn't found) already
 * reflects a completed reload against the freshest keys jose could fetch —
 * aithne responded fine and the kid genuinely isn't in it. Treating that as
 * an infra failure would log a false "aithne unreachable" warning on
 * routine token rejections (rotated-out kids, forged tokens) and trigger a
 * fallback against a last-known-good snapshot that can never be fresher
 * than what jose just checked — so it can never actually rescue the
 * request. It is a genuine token rejection, classified 'unauthenticated'.
 */
export function isJWKSInfraError(error) {
	const code = error?.code ?? error?.cause?.code;
	return code === 'ERR_JWKS_TIMEOUT' || code === 'ECONNREFUSED' || code === 'ENOTFOUND';
}

/**
 * Wrap a jose remote JWKS getter (as returned by createRemoteJWKSet) with
 * serve-stale behaviour, per aithne's docs/local-verification-contract.md
 * §"Serve last-known-good on a failed refresh".
 *
 * createRemoteJWKSet does NOT serve stale keys by default: a failed
 * re-fetch (5-minute cache expiry, or an unrecognised kid triggering a
 * re-fetch) throws straight through, even though the previously-fetched key
 * set is still valid. That turns a brief aithne outage into an
 * authentication storm for every user. This wrapper snapshots the key set
 * after every successful fetch and, on a JWKS infrastructure failure, falls
 * back to verifying against that last-known-good snapshot instead of
 * rejecting outright. A kid that is genuinely unknown (not present even in
 * the last-known-good set) still fails verification and is rejected.
 *
 * Exported (rather than only used internally) so it can be unit tested
 * against a fake remote getter, without needing a live JWKS endpoint.
 *
 * `logger` defaults to `console` — pass the client's injected logger so the
 * distinct-WARNING-before-fallback obligation (ADR-0001 §5) goes to the
 * same place as the rest of the client's logging.
 */
export function createServeStaleJWKS(remoteJWKS, { logger = console } = {}) {
	let lastKnownGoodJWKS = null;

	return async function serveStaleJWKS(protectedHeader, token) {
		try {
			const key = await remoteJWKS(protectedHeader, token);
			lastKnownGoodJWKS = remoteJWKS.jwks() ?? lastKnownGoodJWKS;
			return key;
		} catch (error) {
			if (isJWKSInfraError(error) && lastKnownGoodJWKS) {
				logger.warn('JWKS fetch failed, serving last-known-good key set:', sanitiseMessage(error.message));
				const staleJWKS = createLocalJWKSet(lastKnownGoodJWKS);
				return staleJWKS(protectedHeader, token);
			}
			throw error;
		}
	};
}

/**
 * Parse a Cookie header string into a key-value object.
 * Splits on '; ' between pairs and on the first '=' only within each pair,
 * so cookie values that contain '=' (e.g. base64-encoded tokens) are
 * preserved.
 */
export function parseCookies(header) {
	if (!header) return {};
	return Object.fromEntries(
		header.split('; ')
			.filter((part) => part.includes('='))
			.map((part) => {
				const idx = part.indexOf('=');
				return [part.slice(0, idx), part.slice(idx + 1)];
			})
	);
}

// A returnUrl is trusted for loginUrl() if its origin is https and its host
// is exactly `l42.eu` or a subdomain of it — the same origin-suffix rule
// aithne applies to /auth/remint (aithne ADR-0003 Amendment 2026-06-23).
const L42_SUFFIX_ORIGIN = /^https:\/\/([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)*l42\.eu$/;

function isTrustedReturnUrl(returnUrl, origin) {
	let url;
	try {
		url = new URL(returnUrl);
	} catch {
		return false;
	}
	if (url.origin === origin) return true;
	return L42_SUFFIX_ORIGIN.test(url.origin);
}

/**
 * Create a configured aithne client.
 *
 * config:
 *   origin                  default 'https://aithne.l42.eu'
 *   jwksUrl                 optional dev override for the JWKS fetch address only
 *                            (does NOT affect the issuer check or loginUrl(), both
 *                            of which derive from `origin` — this invariant is a
 *                            security property, not a convenience)
 *   audience                default 'l42.eu'
 *   clockToleranceSeconds   default 30
 *   environment              gates the dev-only render-ui scope bypass; the
 *                            library never reads process.env itself
 *   logger                  default console
 */
export function createAithneClient(config = {}) {
	const origin = config.origin ?? 'https://aithne.l42.eu';
	const jwksUrl = new URL(config.jwksUrl ?? `${origin}/.well-known/jwks.json`);
	const issuer = origin;
	const audience = config.audience ?? 'l42.eu';
	const clockTolerance = config.clockToleranceSeconds ?? 30;
	const environment = config.environment;
	const logger = config.logger ?? console;

	const JWKS = createServeStaleJWKS(createRemoteJWKSet(jwksUrl), { logger });

	// Internal verify function — replaced in tests via _setVerifier so unit
	// tests never need a live JWKS endpoint.
	let _verifyFn = (token, jwks, opts) => jwtVerify(token, jwks, opts);

	function hasScope(payload, requiredScope) {
		const scopes = payload?.scopes ?? [];
		const required = Array.isArray(requiredScope) ? requiredScope : [requiredScope];
		if (required.some((scope) => scopes.includes(scope))) return true;
		// Dev-only render-ui bypass (contract §"Development-only render-ui
		// bypass") — strictly gated on the injected environment, never on
		// process.env, so a test/consumer controls it explicitly.
		if (environment === 'development' && scopes.includes('render-ui')) return true;
		return false;
	}

	function evaluateGate(payload, gate) {
		if (!gate) return true;
		if (gate.authorize) return !!gate.authorize(payload);
		if (gate.requiredScope !== undefined) return hasScope(payload, gate.requiredScope);
		return true;
	}

	async function classify(rawToken, gate) {
		if (!rawToken) {
			return { outcome: 'unauthenticated', payload: null, error: null };
		}
		try {
			const { payload } = await _verifyFn(rawToken, JWKS, {
				issuer,
				audience,
				clockTolerance,
				algorithms: ['ES256'], // pin to ES256 — defence-in-depth against algorithm confusion
			});
			const granted = evaluateGate(payload, gate);
			return { outcome: granted ? 'authorized' : 'forbidden', payload, error: null };
		} catch (rawError) {
			const error = sanitiseError(rawError);
			if (isJWKSInfraError(rawError)) {
				// Reaching here means serve-stale (above) also failed: either
				// there was no last-known-good key set yet (cold start), or the
				// stale re-verify itself failed (kid genuinely not present).
				logger.warn('JWKS infrastructure error (aithne unreachable):', error.message);
				return { outcome: 'unavailable', payload: null, error };
			}
			// Ordinary JWT validation failure (bad signature, expired, wrong
			// audience, unknown kid with aithne reachable) — expected noise,
			// not a service incident.
			return { outcome: 'unauthenticated', payload: null, error };
		}
	}

	/**
	 * Verify the aithne_session cookie from a Cookie header string.
	 * gate: { requiredScope } | { authorize } | undefined — see ADR-0001 §2.
	 */
	async function verifySession(cookieHeader, gate) {
		const { aithne_session: token } = parseCookies(cookieHeader);
		return classify(token, gate);
	}

	/**
	 * Verify a raw JWT string directly (no cookie extraction) — for callers
	 * that already hold a token, e.g. a WebSocket handshake. Takes the same
	 * gate options as verifySession, deliberately: outcome: 'authorized' must
	 * mean the same thing regardless of which function produced it.
	 */
	async function verifyToken(rawToken, gate) {
		return classify(rawToken, gate);
	}

	/**
	 * Build the aithne login URL, embedding a validated `next=` return URL.
	 * A returnUrl that fails validation (wrong origin, not *.l42.eu, not a
	 * valid URL) is dropped — loginUrl() never redirects to an untrusted
	 * destination; it just omits next= and returns a bare login URL.
	 */
	function loginUrl(returnUrl) {
		if (returnUrl && isTrustedReturnUrl(returnUrl, origin)) {
			return `${origin}/auth/login?next=${encodeURIComponent(returnUrl)}`;
		}
		return `${origin}/auth/login`;
	}

	function _setVerifier(fn) {
		_verifyFn = fn;
	}

	return {
		verifySession,
		verifyToken,
		hasScope,
		parseCookies,
		loginUrl,
		_setVerifier,
	};
}
