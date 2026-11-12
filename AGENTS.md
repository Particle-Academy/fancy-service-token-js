# AGENTS.md — fancy-service-token-js

The Node leg of the Fancy service-token set: a verifier for `fst1` tokens and a
connect-style middleware. `CLAUDE.md` points here. Process rules live in the
envelope's `RULES.md`, not here.

Siblings, held to the same fixture file: `fancy-service-token` (PHP signer and
verifier) and `fancy-service-token-py` (Python verifier, and where the fixtures
are generated).

## Where things are

- `src/verifier.ts`: `Verifier`, `MemoryReplayStore`, `REASONS`, the types.
  Follows the README's numbered check order step by step.
- `src/middleware.ts`: `serviceTokenMiddleware`, `currentRequestId`.
- `conformance/service-token-v1.json`: shared fixtures, a byte copy from
  `fancy-service-token-py`. Never edit it here; regenerate there and copy.
- `tests/sabotage.mjs`: the mutation sweep CI runs.

## Invariants a change must keep

- **Zero runtime dependencies**; `node:crypto`, `node:async_hooks` and Buffer
  only. No JWT library, no cryptography beyond HMAC-SHA256.
- **Refuse from the headers.** On a refusal the middleware never touches the
  body stream and never calls `next()`. Duplicate token headers are `malformed`
  (read through `headersDistinct`).
- **The check order is the contract**, shared with PHP and Python through the
  fixtures. A nonce is recorded only after every other check passes.
- **Constant time:** `timingSafeEqual` on equal-length buffers, and an HMAC is
  computed even for an unknown key id.
- **Strict parsing:** canonical unpadded base64url, ASCII only, lengths bounded
  before parsing, character sets checked per character (the only regex is a
  bounded single character class).
- **Nothing secret leaves:** `Claims` holds no token or nonce; log events carry
  a reason, a verified request id or an error class name, never a message.
- **Fail closed:** `verify()` never throws; a full replay store refuses.
- `REASONS` is a fixed public contract across all three legs.

## Tests

`npm test` (vitest), `npm run lint` (tsc), `npm run build`, then
`node tests/sabotage.mjs`.
