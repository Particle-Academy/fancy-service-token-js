# @particle-academy/fancy-service-token

Verify Fancy service tokens in a Node sidecar. A Laravel app signs a
short-lived token on every request it makes to its sidecar
([`particle-academy/fancy-service-token`](https://github.com/Particle-Academy/fancy-service-token));
this package checks it **before the request body is read** and refuses every
other caller with a named reason.

- The verifier mirror of the PHP signer and the Python verifier
  ([`fancy-service-token`](https://github.com/Particle-Academy/fancy-service-token-py) on PyPI).
  All three run the same fixture file byte for byte.
- HMAC-SHA256 with `node:crypto` only (`createHmac`, `timingSafeEqual`). No JWT
  library, no cryptography of our own, zero runtime dependencies.
- Refusals carry one reason from a fixed set, never exception text; nothing it
  logs contains a token, a nonce or a secret.

<!-- fancy-agents-note:start -->
> **For agents.** This package is not listed on the Fancy MCP catalog server
> yet. The server, `https://ui.particle.academy/mcp` (streamable HTTP, no API key; MCP id
> `fancy-ui`), lists the released Fancy packages with install commands and
> docs. How an agent installs and uses this package is in [AGENTS.md](https://github.com/Particle-Academy/fancy-service-token-js/blob/main/AGENTS.md).
<!-- fancy-agents-note:end -->

## Install

```bash
npm install @particle-academy/fancy-service-token
```

Node 22 or later.

## Use

```ts
import express from "express";
import { Verifier, serviceTokenMiddleware, currentRequestId } from "@particle-academy/fancy-service-token";

const verifier = new Verifier({
  keys: [{ kid: "k2026b", secret: Buffer.from(process.env.SERVICE_TOKEN_KEY!, "hex") }],
  audience: "ocr-sidecar",
  issuer: "laravel-app",
});

const app = express();
app.use(serviceTokenMiddleware({ verifier, log: (e) => logger[e.level](e) })); // BEFORE any body parser
app.use(express.json());

app.post("/ocr", (req, res) => {
  const { requestId } = req.serviceToken!;
});
```

The middleware is connect-style `(req, res, next)`, so Express, Connect, Polka
and a bare `node:http` handler all take it. **Mount it before any body parser**:
it decides from `req.headers` alone and, on a refusal, never reads the body and
never calls `next()`. The refusal also sets `Connection: close`, so the unread
body is not parsed as a next request on the socket.

`Verifier.verify(token, now?)` works without the middleware too, and never
throws: it returns `{ ok: true, claims }` or `{ ok: false, reason }`.

## Refusals

`401`, `Cache-Control: no-store`, `WWW-Authenticate: FancyServiceToken error="<reason>"`:

```json
{"error": "service_token_refused", "reason": "expired"}
```

| reason | means |
|---|---|
| `missing` | no token header, or an empty one |
| `malformed` | not a well-formed `fst1` token, longer than `maxTokenBytes`, a lifetime above `maxLifetime`, no nonce while `requireNonce` is on, or the header sent twice |
| `bad_signature` | HMAC mismatch, unknown key id, a previous key past its grace window, or an issuer other than the configured one |
| `expired` | `now >= exp + clockSkew` |
| `not_yet_valid` | `now + clockSkew < iat` |
| `wrong_audience` | signed correctly, for a different sidecar |
| `replayed` | the nonce was already accepted (or the replay store is full: it fails closed) |

## Request id

The caller's request id is signed into the token. After verification it is on
`req.serviceToken.requestId` and, for code running inside `next()` (including
after an `await`), in `currentRequestId()`. Stream event callbacks such as
`req.on("data")` are emitted from the socket's own async context, so read
`req.serviceToken` there. The `log` option receives `{ level, message, reason?,
requestId?, errorClass? }` events.

## Configuration

| option | default | |
|---|---|---|
| `keys` | required | `{ kid, secret: Uint8Array, acceptUntil? }`; secrets of at least `minKeyBytes` |
| `audience` | required | this sidecar's name |
| `issuer` | required | the Laravel app's name |
| `clockSkew` | `10` | seconds of tolerance on both ends |
| `maxLifetime` | `300` | the longest `exp - iat` accepted |
| `maxTokenBytes` | `1024` | checked before any parsing |
| `requireNonce` | `true` | |
| `minKeyBytes` | `32` | |
| `replayStore` | `new MemoryReplayStore()` | anything with `add(key, expiresAt, now): boolean`; `null` turns replay checks off |
| `clock` | `Date.now` | milliseconds |

`serviceTokenMiddleware({ verifier, header = "x-fancy-service-token", exemptPaths = [], log })`.
`exemptPaths` are exact path matches (the query string is ignored), for a health
check. `MemoryReplayStore(maxEntries = 100_000)` is per process; run several
processes and you need a shared store.

### Key rotation

Sign with the new key in Laravel; here, hold both and give the old one an
`acceptUntil` (unix seconds, inclusive):

```ts
keys: [{ kid: "k2026b", secret: next }, { kid: "k2026a", secret: previous, acceptUntil: 1793000030 }]
```

## The token format (`fst1`)

```
fst1.<payload>.<signature>
```

- `payload` is the **unpadded base64url** (RFC 4648 section 5) of seven ASCII
  fields joined by a single LF (`0x0A`), in this order, with no trailing LF:

  | # | field | grammar |
  |---|---|---|
  | 1 | `kid` key id | 1-64 of `[A-Za-z0-9._-]` |
  | 2 | `iss` issuer | 1-128 of `[A-Za-z0-9._:/-]` |
  | 3 | `aud` audience | 1-128 of `[A-Za-z0-9._:/-]` |
  | 4 | `iat` issued at | unix seconds, decimal, 1-12 digits, no leading zero |
  | 5 | `exp` expires at | as `iat`; must be greater than `iat` |
  | 6 | `rid` request id | 1-128 of `[A-Za-z0-9._:-]` |
  | 7 | `nonce` | empty, or 16-128 of `[A-Za-z0-9_-]` |

- `signature` is the unpadded base64url of
  `HMAC-SHA256(secret, ASCII("fst1." + payload))`: 32 bytes, so 43 characters.
- base64url must be **canonical**: right alphabet, no padding, no whitespace,
  and the unused low bits of the last character clear.
- Sent in one header, `X-Fancy-Service-Token` by default.

Checks run in this order and stop at the first failure (the fixtures pin it):

1. absent or empty: `missing`
2. longer than `maxTokenBytes`: `malformed`
3. not three dot-separated parts, prefix not `fst1`, signature not 43
   characters, either part not canonical base64url: `malformed`
4. payload not ASCII, not seven fields, a field outside its grammar,
   `exp <= iat`, `exp - iat > maxLifetime`, or no nonce while one is required:
   `malformed`
5. unknown `kid`, HMAC mismatch (constant time), a previous key past
   `acceptUntil`, or `iss` not the configured issuer: `bad_signature`
6. `aud` not this sidecar: `wrong_audience`
7. `now + clockSkew < iat`: `not_yet_valid`
8. `now >= exp + clockSkew`: `expired`
9. nonce already recorded: `replayed`. Recorded only here, so a token refused
   for an earlier reason never spends one.

## Conformance

`conformance/service-token-v1.json` is the shared fixture file, generated in
`fancy-service-token-py` from the format definition alone and copied here byte
for byte; the suite pins its SHA-256.

## License

MIT
