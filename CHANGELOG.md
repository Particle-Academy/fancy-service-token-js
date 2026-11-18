# Changelog

All notable changes to `@particle-academy/fancy-service-token` are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Pre-1.0, breaking changes land in MINOR releases.** Read those entries before
upgrading.

## [Unreleased]

## [0.2.0] - 2026-11-18

### Changed

- **BREAKING: the 401 refusal body is now the Fancy error envelope**
  (`fancy-http-errors` `envelope.schema.json`), exactly
  `{"error": "service_token_refused", "message": "<sentence>", "requestId": "<id>"}`.
  **The body no longer has `reason`; read it from `WWW-Authenticate`**
  (`FancyServiceToken error="<reason>"`, unchanged since 0.1.0). If you only
  checked the 401 status, do nothing.

### Added

- `message`: one fixed English sentence per reason, exported as
  `REFUSAL_MESSAGES`. Identical to the Python leg; both are pinned to
  `conformance/refusal-messages.json` (shipped in the package).
- `requestId`: the incoming `x-request-id` when it matches
  `^[A-Za-z0-9._:-]{1,128}$` (sent once), else `crypto.randomUUID()`; echoed as
  an `x-request-id` response header. The `requestIdHeader` option changes the
  header name.
- The suite validates every refusal body against a byte copy of the envelope
  schema with a small first-party validator (no new dependency).

## [0.1.0] - 2026-11-18

First release (CC-fancy-0030).

### Added

- **`Verifier`** for `fst1` service tokens: HMAC-SHA256 with `node:crypto`
  (`createHmac`, `timingSafeEqual`), no JWT library, zero runtime dependencies.
  `verify()` never throws and refuses with one reason from a fixed set:
  `missing`, `malformed`, `bad_signature`, `expired`, `not_yet_valid`,
  `wrong_audience`, `replayed`.
- **Key rotation:** a previous key with `acceptUntil` is accepted until then,
  and is `bad_signature` after.
- **Every limit is configurable, with secure defaults:** `clockSkew` 10 s,
  `maxLifetime` 300 s, `maxTokenBytes` 1024, `requireNonce` on, keys of at
  least 32 bytes, and a per-process `MemoryReplayStore` (100,000 entries, fails
  closed when full).
- **`serviceTokenMiddleware`**, connect-style, for Express, Connect, Polka and
  bare `node:http`: refuses with `401` from the headers alone, never reading the
  body and never calling `next()`; sets `Connection: close` on a refusal.
- **The verified request id** on `req.serviceToken` and in `currentRequestId()`
  (AsyncLocalStorage), plus structured `log` events that never carry a token,
  nonce or secret.
- **Shared conformance fixtures** (`conformance/service-token-v1.json`), the
  same bytes as the PHP and Python legs, pinned by SHA-256; and a sabotage sweep
  in CI.

### Changed

- **CI: the lab-certificate gate verifies against the lab's rotated key list.**
  The lab's first signing key is retired: certificates it already issued still
  verify, and nothing new it signs ever can. Consumers do nothing.

- **Docs:** `AGENTS.md` is now the guide to using this package (install, how to find it on the Fancy MCP catalog server once it is listed, API essentials, traps), and it ships in the package. The contributor notes it held moved to `CONTRIBUTING.md`, and `CLAUDE.md` is now a symlink to it. The README points to the MCP server and to `AGENTS.md`. No code changed; nothing to do.
