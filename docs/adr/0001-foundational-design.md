# ADR-0001: lucos_aithne_jsclient foundational design — a shared JS verify-and-classify library for aithne session tokens

**Date:** 2026-07-10
**Status:** Proposed
**Discussion:** https://github.com/lucas42/lucos/issues/264

## Context

Four server-side JavaScript services verify `aithne` session tokens locally, and each carries a **copy-pasted** copy of the same auth module: `lucos_creds`, `lucos_notes`, `lucos_media_seinn`, `lucos_loganne`. The duplication came from the estate-wide serve-stale JWKS rollout (lucas42/lucos_aithne#241), which landed the same reference implementation in each repo by hand.

Reading all four from `origin/main`, the verification **core is byte-identical** across every consumer:

- the config block (`AITHNE_ORIGIN`, `AITHNE_JWKS_URL`, issuer, audience, login URL);
- `isJWKSInfraError()`;
- `createServeStaleJWKS()` (the last-known-good wrapper mandated by the aithne local-verification-contract §"Serve last-known-good on a failed refresh");
- the `createRemoteJWKSet` → serve-stale-wrap → `jwtVerify(...)` setup, with identical options (`algorithms: ['ES256']`, `clockTolerance: 30`, issuer/audience);
- `parseCookies()` and the `_setVerifier`/`_verifyFn` test seam.

Only the surrounding **presentation** diverges per consumer: the required scope string, the styled 403 template, the login-redirect construction, CSRF policy (three variants), `lucos_loganne`'s Bearer/`CLIENT_KEYS` machine path, and `lucos_notes`' WebSocket handshake reuse.

The lucas42/lucos#260 audit found **two bugs that are structural consequences of the duplication** — present, identically, in all four copies:

1. **`isJWKSInfraError` misclassifies the real error shape.** It checks `error.code`, but `jose`'s native-`fetch` path wraps connection failures as `TypeError('fetch failed', { cause: <err with .code> })` — the real `ECONNREFUSED`/`ENOTFOUND` lands on `error.cause.code`. So the serve-stale fallback the whole aithne#241 rollout was built for plausibly **never engages** on a real connection-refused.
2. **No local page when aithne is confirmed unreachable.** On an infra failure with no last-known-good snapshot, the middleware falls through the same branch as an invalid token and 302-redirects into the (dead) aithne origin — the browser then shows its own "can't reach this page", the exact failure lucos#260 audited against.

One wrong predicate and one missing branch, copied four times, and every fix is an N-place change that can silently drift. This is JWT-verification code — the estate's authentication hot path — so keeping four copies in lockstep is also a standing **security** liability: a subtle fix (algorithm pinning, audience check) applied to one copy and missed in another is a real risk, and there is no single place to audit.

lucas42 approved building a shared library (lucos#264) and created this repo. `lucos_navbar` is already an estate npm package consumed across services, so the publish/consume/dependabot pattern is proven and the per-release overhead is low.

## Decision

### 0. Implementation stack — Node.js ESM, `jose`, no framework dependency

`lucos_aithne_jsclient` is a **Node.js ES-module npm package** whose only runtime dependency is **`jose`**. Rationale:

- **Match the consumers.** All four consumers are Node ESM services already depending on `jose`; the library must be a drop-in for the code it replaces. A different JS runtime or JWT library would mean re-validating the crypto path against the aithne contract, defeating the point.
- **`jose` is the contract's named reference.** The aithne local-verification-contract explicitly discusses `jose`'s `createRemoteJWKSet` failure behaviour; this library is the JS embodiment of that contract's serve-stale requirement.
- **No web-framework dependency.** The library MUST NOT depend on Express (or any framework). It accepts a cookie header **string** and returns a classification; the consumer writes its own middleware around it. This is what lets `lucos_notes` reuse the same verification for both its HTTP middleware and its WebSocket handshake, and lets `lucos_loganne` keep its Bearer path in front of the cookie path.
- **No `process.env` reads inside the library.** All environment-varying config is **injected** by the consumer (see §2). This is the clean resolution of the "browser-vs-container" framing on lucos#264: there is no browser build here — every consumer is server-side — the only real split is the dev/prod `AITHNE_JWKS_URL` override, which is passed in as config.

The `js` suffix in the repo name (`lucos_aithne_jsclient`, matching `lucos_loganne_pythonclient`) deliberately reserves room for future per-language aithne clients; this ADR governs the JS one only.

### 1. The boundary — the library **verifies and classifies**; the consumer **presents**

This is the load-bearing decision. Getting the boundary wrong — trying to pull per-app presentation into the library — is the one way this ends up worse than duplication (a config-explosion chasing four divergent render paths). The split:

| Concern | Owner |
|---|---|
| config resolution, `parseCookies`, `isJWKSInfraError` (fixed), serve-stale JWKS wrapper, `jwtVerify` + options, **classification** | **library** |
| required scope string(s) + the dev-only `render-ui` bypass | **library**, from consumer-injected config |
| styled 403 "missing scope" page | **consumer** (its own template/copy) |
| local "sign-in unavailable" page (audit bug #2) | **consumer** (its own template/copy — it is UX) |
| login-redirect construction / `next=` return URL | **consumer** (library offers a URL helper) |
| CSRF middleware | **consumer** (diverges three ways today — out of scope for v1; see §6) |
| Bearer / `CLIENT_KEYS` machine path | **consumer** (`lucos_loganne`-only) |
| WebSocket handshake wiring | **consumer** (`lucos_notes`-only; consumes the same verify primitive) |
| `/_info` and other auth-exempt paths (contract §"Exempt paths") | **consumer** (routing) |

### 2. Public API

A factory takes injected config and returns a configured client:

```js
import { createAithneClient } from 'lucos_aithne_jsclient';

const aithne = createAithneClient({
  origin:      process.env.AITHNE_ORIGIN,        // default 'https://aithne.l42.eu'
  jwksUrl:     process.env.AITHNE_JWKS_URL,      // optional dev override; default `${origin}/.well-known/jwks.json`
  audience:    'l42.eu',                         // default
  clockToleranceSeconds: 30,                     // default, per contract §"Token TTL and clock skew"
  environment: process.env.ENVIRONMENT,          // injected; gates the dev-only render-ui bypass (lib reads no process.env)
  logger:      console,                          // injectable; default console
});
```

- `jwksUrl` overrides **only** the JWKS fetch address (the dev Docker-bridge case). It MUST NOT influence the issuer check or the `next=` redirect, both of which derive from `origin` — this invariant is carried over verbatim from the current modules and is a security property, not a convenience.

Methods:

- **`aithne.verifySession(cookieHeader, { requiredScope | authorize })` → `Promise<Classification>`** — the primary entry point. Extracts the `aithne_session` cookie, verifies the JWT (ES256-pinned, issuer/audience/skew per contract §"Verify the signature"/§"Validate standard claims"), applies serve-stale on JWKS infra failure, and applies the scope gate.
- **`aithne.verifyToken(rawToken, { requiredScope | authorize })` → `Promise<Classification>`** — the same verification and gate without cookie extraction, for callers that already hold a token (e.g. `lucos_notes`' WebSocket handshake, which reads the cookie itself). **It takes the identical gate options as `verifySession`, deliberately**: an earlier design in which `verifyToken` skipped the scope check made `outcome: 'authorized'` mean two different things depending on which function produced it — a footgun for a migration PR that treats `'authorized'` as "go ahead". See the gate-semantics note below.
- **`aithne.hasScope(payload, requiredScope)` → boolean** — the exported scope predicate both verify functions use internally: true when `payload.scopes` contains `requiredScope`, or (when the client's injected `environment === 'development'`) when it contains the estate-wide `render-ui` scope. Exported so a caller that deliberately runs a gate-less verify can apply the *same* check itself rather than hand-rolling a divergent one.
- **`aithne.parseCookies(header)` → object** — exported utility (cookie values may contain `=`).
- **`aithne.loginUrl(returnUrl)` → string** — builds `${origin}/auth/login?next=${encodeURIComponent(returnUrl)}`, **and validates `returnUrl` before embedding it**. Because the library already holds `origin` and receives the resolved `returnUrl`, it enforces the open-redirect guard rather than leaving it to consumer honour-system: `returnUrl` is accepted only if its host matches the `*.l42.eu` suffix — the same origin-suffix rule aithne applies to `/auth/remint` (aithne ADR-0003 Amendment 2026-06-23, `^https://[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)*\.l42\.eu$`) — **or** matches the consumer's own injected `appOrigin` config (Amendment 2026-07-10, lucas42/lucos_aithne_jsclient#8: an earlier draft of this rule compared `returnUrl` against aithne's *own* `origin`, which a consumer's return URL practically never equals; `appOrigin` is what that comparison was meant to be, and it's also what lets a dev consumer on a non-`l42.eu` `localhost:<port>` origin get a working round-trip). A `returnUrl` that fails validation is dropped and a bare `${origin}/auth/login` (no `next=`) is returned — never a redirect to an untrusted destination. This also removes the consumer's ability to reintroduce the `Host`-header open-redirect smell currently latent in `lucos_creds`.

**The gate — `requiredScope` or `authorize`.** `requiredScope` accepts a string or array and is evaluated by `hasScope` (above), including the dev-only `render-ui` bypass gated strictly on the injected `environment` (contract §"Development-only `render-ui` bypass"). For consumers needing a read/write-split or an identity (`sub`) check (contract §6), an `{ authorize: (payload) => boolean }` predicate is accepted instead; the library still classifies authentication/availability and defers only the grant decision.

**Gate-semantics (removing the footgun).** With a gate supplied, `outcome: 'authorized'` means *authenticated **and** the gate passed*. If a caller supplies **neither** `requiredScope` nor `authorize`, a valid token yields `outcome: 'authorized'` meaning **authenticated only** — and such a caller MUST then apply its own capability check via `hasScope()` before treating the principal as permitted. This is stated because "there is a valid session" is never sufficient authorisation on its own — a machine principal passes it (contract §6). Consumers SHOULD pass a gate rather than rely on the gate-less path.

### 3. The classification — a single `outcome` enum that maps 1:1 to the consumer's branches

The return shape is what makes both audit bugs fixable **consistently**:

```js
// Classification
{
  outcome: 'authorized' | 'forbidden' | 'unauthenticated' | 'unavailable',
  payload: <JWT payload | null>,   // present for 'authorized' and 'forbidden' (so the consumer can log sub)
  error:   <Error | null>,         // present for 'unavailable' and non-infra 'unauthenticated'; message is kid-sanitised (§5)
}
```

`error.message` is sanitised by the library before it is surfaced — see §5. A consumer may log `error.message` directly.

| `outcome` | Meaning | Consumer action |
|---|---|---|
| `authorized` | valid token + required scope | proceed |
| `forbidden` | valid token, **missing** required scope | styled **403**, naming the required scope; **do not** redirect (re-login yields the same scopeless token — an infinite loop). Contract §"Name the missing scope in the denial response". |
| `unauthenticated` | no token, or a genuine JWT validation failure (bad signature, expired, wrong audience, unknown `kid` with aithne **reachable**) | 302 redirect to `aithne.loginUrl(returnUrl)` |
| `unavailable` | JWKS infra failure (aithne unreachable/timed out) **and** serve-stale could not rescue the request | render the consumer's **local "sign-in unavailable" page**; **do not** redirect into a dead aithne |

Today all four consumers collapse `unavailable` into `unauthenticated` and redirect — that collapse **is** audit bug #2. Surfacing `unavailable` as a distinct outcome is the fix, applied once.

### 4. Bug #1, fixed in the one place it now lives

`isJWKSInfraError` becomes a single library function that classifies an error as a JWKS infrastructure failure when the infra code (`ERR_JWKS_TIMEOUT`, `ECONNREFUSED`, `ENOTFOUND`) appears **either** on `error.code` (the older direct-throw shape) **or** on `error.cause?.code` (the `TypeError('fetch failed', { cause })` shape that Node's native `fetch` — and therefore `jose`'s `createRemoteJWKSet` — actually produces). It stays deliberately narrower than "any `ERR_JWKS_*` code": `ERR_JWKS_NO_MATCHING_KEY` reflects a completed reload against the freshest keys and is a genuine token rejection, not an outage (this reasoning is preserved from the current modules). Both shapes get a unit test.

### 5. Resilience & logging obligations carried from the contract

- **Serve last-known-good.** The wrapper snapshots the key set after every successful fetch and, on a JWKS infra failure, verifies against the last-known-good snapshot rather than rejecting outright — an unknown `kid` still fails (contract §"Serve last-known-good on a failed refresh").
- **Distinct WARNING log before fallback.** A failed JWKS fetch is logged at `WARNING` via the injected `logger`, distinctly from ordinary per-token validation failures (which are low-severity expected noise). Centralising this guarantees the severity split the contract requires (from lucas42/lucos_arachne#641) rather than relying on each consumer to get it right.
- **Sanitise `kid` before it reaches a log or the returned `error` (contract §"Locate the signing key").** `kid` is an attacker-controlled JWT header field that `jose` embeds **verbatim** in error messages (e.g. `ERR_JWKS_NO_MATCHING_KEY`), so an unmodified message logged by a consumer is a log-injection/forging vector (newlines, terminal control sequences). The library strips C0 control characters (`\x00`–`\x1f`) and DEL (`\x7f`) from any `kid`-bearing string **before** it logs it **and** before it places any message on `Classification.error` — so a consumer can safely log `error.message`. This is the same class of obligation as bugs #1/#2: it lived, unaddressed, in the copied modules, and centralising it fixes it once (requirement from lucas42/lucos_arachne#646). It gets a unit test with a `kid` containing `\n`/`\x1b` sequences.

### 6. Explicitly out of scope for v1

- **CSRF middleware.** It diverges three ways across the consumers (same-host-only in creds; `*.l42.eu` in notes/seinn; `*.l42.eu` + Bearer-skip in loganne). Folding three policies behind one config knob in v1 would be premature; each consumer keeps its own. If CSRF drift later proves a maintenance problem, a future ADR amendment can revisit a separate `csrf` export. This is a permanent-for-now scoping call, not deferred committed work.
- **The Bearer / machine-principal path** (loganne) and **WebSocket wiring** (notes) stay in their consumers; both compose over `verifyToken`/`verifySession`.
- **Non-JS consumers.** The other ~7 lucos#260 follow-ups are Python/PHP and out of an npm library's reach. This is not a regression: the aithne **`local-verification-contract.md` remains the cross-language source of truth**; this library is simply the JS reference implementation of it.

## Consequences

### Positive

- **One place to fix, one place to audit** the estate's JS token-verification path — the core security argument. Both lucos#260 bugs are fixed once, in code that four services then pick up by version bump.
- **The contract gains an authoritative JS implementation** that co-evolves with `docs/local-verification-contract.md`; future contract changes (alg agility, new claims, serve-stale tuning) become single-point changes.
- **A crisp boundary** keeps per-app UX (403 pages, unavailable pages, CSRF, Bearer, WS) where it belongs, so the library stays small and framework-agnostic.
- **Latent divergences get normalised, and shared hardening is enforced not just documented** on adoption — `lucos_creds`' `Host`-header-based `next=` (a latent open-redirect smell) is superseded by `loginUrl`, which *validates* the return URL against the `*.l42.eu` suffix (§2); and the contract's `kid`-log-sanitisation obligation (§5), previously unaddressed in every copy, is applied once in the library. Centralising security obligations — not just the happy-path core — is where the single-point-of-audit argument pays off most.

### Negative / trade-offs (stated plainly)

- **A library does NOT make a fix instantly estate-live.** A security fix is live only once every consumer bumps the version and redeploys — the same N-place redeploy as today, minus the code edit. The mitigation is real but partial: the error-prone part (the code change) becomes single-point, and the version bump is mechanical and dependabot-automatable. The release-coupling must be owned, not wished away.
- **New moving parts:** a repo, its CI, an npm publish pipeline, dependabot, semver discipline, and four migration PRs. Justified here by four existing consumers, more JS-behind-aithne services likely, security-criticality, and the low overhead the `lucos_navbar` precedent demonstrates — but it would **not** be justified at one or two consumers.
- **A shared library is a shared blast radius.** A defect published to the one package reaches every consumer that upgrades. Mitigated by the test seam (`_verifyFn`, fake-remote-JWKS unit tests carried over from the current modules — Amendment 2026-07-10, lucas42/lucos_aithne_jsclient#7: injected only at construction time via `createAithneClient(config)`, replacing an earlier runtime `_setVerifier(fn)` setter per security's #6 review, so a client's verify function can never be swapped after creation), ES256 pinning, and staged rollout via independent consumer version bumps.

## Alternatives considered

- **Fix the two bugs in place, four times (status quo + patch).** Rejected as the durable answer: it leaves the duplication, so the *next* verification change is again a four-place edit with drift risk. Retained only as an **interim** measure — if library delivery slips materially, the bug-#1 one-liner (`error.cause?.code`) is the *identical* change destined for the library and may be landed in the four consumers meanwhile to restore serve-stale; bug #2 (the local page) waits for the library's `unavailable` outcome.
- **A framework (Express) middleware package.** Rejected: it would exclude the WebSocket and Bearer consumers and couple the library to a framework. The verify-primitive + thin per-app middleware keeps all consumers in scope. (An optional Express adapter could be added later without breaking the primitive.)
- **Vendoring / a git submodule instead of npm.** Rejected: npm + semver + dependabot is the estate's established shared-code mechanism (`lucos_navbar`); a submodule gives worse update ergonomics and no version pinning.

## Next steps (tracked outside this ADR)

Implementation is sequenced on lucas42/lucos#264 and dispatched by the coordinator:

1. Scaffold the repo to the chosen stack (Node ESM package, CI, dependabot) — the stack is settled by §0, so the scaffold ticket is unblocked.
2. Extract and publish **v1** implementing §2–§5.
3. Re-scope the four lucos#260 follow-ups (lucas42/lucos_creds#449, lucas42/lucos_notes#459, lucas42/lucos_media_seinn#553, lucas42/lucos_loganne#565) to "adopt `lucos_aithne_jsclient` + render a local sign-in-unavailable page", each **Blocked** on v1.
