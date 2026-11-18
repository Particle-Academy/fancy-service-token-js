# Using @particle-academy/fancy-service-token — guide for agents

How an agent installs and uses this package in a consumer app. What the package
is, is in [README.md](./README.md). Notes for working ON this repo's code are in
[CONTRIBUTING.md](./CONTRIBUTING.md).

## Install

```bash
npm install @particle-academy/fancy-service-token
```

- **Node:** `>=22`. Zero runtime dependencies.
- The signer is the Laravel package `particle-academy/fancy-service-token`; this
  package only verifies. A Python verifier is `fancy-service-token` on PyPI.

## Find it on the Fancy MCP server

The catalog server is `https://ui.particle.academy/mcp` (streamable HTTP, no API
key; MCP id `fancy-ui`). This package is not yet listed there; it appears once
published. Find it then with `search-backend-packages` (stack `node`).

## API essentials

```ts
import { Verifier, serviceTokenMiddleware, currentRequestId } from "@particle-academy/fancy-service-token";

const verifier = new Verifier({
  keys: [{ kid: "k2026b", secret: Buffer.from(process.env.SERVICE_TOKEN_KEY!, "hex") }],
  audience: "ocr-sidecar",
  issuer: "laravel-app",
});

app.use(serviceTokenMiddleware({ verifier, log: (e) => logger[e.level](e) })); // before any body parser
```

- `Verifier.verify(token, now?)` returns `{ ok: true, claims }` or
  `{ ok: false, reason }` and never throws.
- `serviceTokenMiddleware({ verifier, header, requestIdHeader, exemptPaths, log })` is
  connect-style `(req, res, next)`: Express, Connect, Polka and bare `node:http`
  all take it. Default header `x-fancy-service-token`.
- The verified request id is on `req.serviceToken.requestId`, and
  `currentRequestId()` returns it anywhere inside `next()`.
- `REASONS` is the fixed set of refusal reasons: `missing`, `malformed`,
  `bad_signature`, `expired`, `not_yet_valid`, `wrong_audience`, `replayed`.
  A refusal is `401` with the Fancy error envelope
  `{"error": "service_token_refused", "message": "<fixed sentence>", "requestId": "<id>"}`
  and nothing else. **Read the reason from the header**,
  `WWW-Authenticate: FancyServiceToken error="<reason>"`, never the body. The
  request id is the incoming `x-request-id` when safe, else a UUID v4, and is
  echoed as `x-request-id`. Sentences: `REFUSAL_MESSAGES`.
- Options and defaults (`clockSkew`, `maxLifetime`, `maxTokenBytes`,
  `requireNonce`, `minKeyBytes`, `replayStore`, `clock`) are in the README's
  Configuration table.

## Traps

- **Mount the middleware BEFORE any body parser.** It decides from headers alone;
  a parser mounted first reads the body of a request that should be refused.
- **Secrets must be at least `minKeyBytes` (32) bytes** and passed as bytes
  (`Uint8Array` / `Buffer`), not a string.
- **`MemoryReplayStore` is per process.** With several processes, supply a
  shared store (anything with `add(key, expiresAt, now): boolean`). A full store
  refuses (`replayed`); `replayStore: null` turns replay checks off.
- **Key rotation:** sign with the new key in Laravel; here hold both and give
  the old one `acceptUntil` (unix seconds, inclusive).
- **Stream callbacks** such as `req.on("data")` run outside the request's async
  context; read `req.serviceToken` there, not `currentRequestId()`.
- **`exemptPaths` are exact path matches** (query string ignored), meant for a
  health check.
- **A duplicated token header is `malformed`.**
- **Pre-1.0:** breaking changes land in MINOR releases.
