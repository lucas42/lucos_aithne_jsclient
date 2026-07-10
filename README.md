# lucos_aithne_jsclient
Javascript library for clients of lucos_aithne

Shared JS verify-and-classify library for `aithne` session tokens. See
[`docs/adr/0001-foundational-design.md`](docs/adr/0001-foundational-design.md)
for the full design and rationale — this README covers usage only.

The library **verifies and classifies**; the consumer **presents**. It has a
single runtime dependency (`jose`), reads no `process.env` itself, and does
not depend on any web framework.

## Install

```sh
npm install lucos_aithne_jsclient
```

## Usage

```js
import { createAithneClient } from 'lucos_aithne_jsclient';

const aithne = createAithneClient({
  origin:      process.env.AITHNE_ORIGIN,   // default 'https://aithne.l42.eu'
  jwksUrl:     process.env.AITHNE_JWKS_URL, // optional dev override (JWKS fetch address only)
  appOrigin:   process.env.APP_ORIGIN,      // this consumer's own origin — trusted as a loginUrl() return target
  environment: process.env.ENVIRONMENT,     // gates the dev-only render-ui bypass
});

// In Express middleware:
app.use(async (req, res, next) => {
  const { outcome, payload, error } = await aithne.verifySession(req.headers.cookie, {
    requiredScope: 'notes:use',
  });

  switch (outcome) {
    case 'authorized':
      res.auth_agent = payload;
      return next();
    case 'forbidden':
      // Valid session, missing scope — render your own styled 403. Do not
      // redirect: re-login yields the same scopeless token.
      return res.status(403).render('forbidden', { requiredScope: 'notes:use' });
    case 'unauthenticated':
      // No token, or a genuine validation failure — redirect to login.
      return res.redirect(302, aithne.loginUrl(`${process.env.APP_ORIGIN}${req.originalUrl}`));
    case 'unavailable':
      // aithne itself is unreachable — do NOT redirect into a dead aithne.
      // Render your own local "sign-in unavailable" page instead.
      console.warn('aithne unavailable:', error.message);
      return res.status(503).render('unavailable');
  }
});
```

`verifyToken(rawToken, gate)` is the same primitive without cookie
extraction, for callers that already hold a token (e.g. a WebSocket
handshake) — it takes identical gate options, so `outcome: 'authorized'`
means the same thing regardless of which function produced it.

See ADR-0001 §2–§5 for the full API surface (`hasScope`, `parseCookies`,
the `outcome` enum, and the resilience/logging obligations), and §6 for
what is deliberately out of scope for v1 (CSRF middleware, the Bearer/
machine-principal path, WebSocket wiring, non-JS consumers).

## Development

```sh
npm install
npm test
```

Tests run on Node's built-in test runner (`node --test`) — no test
framework dependency.
