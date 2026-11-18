/**
 * A connect-style `(req, res, next)` middleware: Express, Connect, Polka and a
 * bare node:http handler all take it. It decides from `req.headers` alone, so
 * on a refusal nothing ever reads, parses or buffers the request body, and the
 * handler is never called. Mount it BEFORE any body parser.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { randomUUID } from "node:crypto";
import type { IncomingMessage, ServerResponse } from "node:http";

import type { Claims, Reason, Verifier } from "./verifier";

/**
 * The `message` of a refusal: one fixed sentence per reason. The Python leg
 * carries the same table; both are compared against
 * `conformance/refusal-messages.json` in their suites.
 */
export const REFUSAL_MESSAGES: Readonly<Record<Reason, string>> = Object.freeze({
  missing: "This request carries no service token.",
  malformed: "The service token could not be read.",
  bad_signature: "The service token signature does not match a known key.",
  expired: "The service token has expired.",
  not_yet_valid: "The service token is not valid yet.",
  wrong_audience: "The service token was issued for a different service.",
  replayed: "The service token has already been used.",
});

/** `^[A-Za-z0-9._:-]{1,128}$`, checked per character. */
function safeRequestId(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 1 || value.length > 128) return false;
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    const ok =
      (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 46 || c === 95 || c === 58 || c === 45;
    if (!ok) return false;
  }
  return true;
}

export interface LogEvent {
  level: "debug" | "warn" | "error";
  message: string;
  reason?: Reason;
  requestId?: string;
  errorClass?: string;
}

export interface MiddlewareOptions {
  verifier: Verifier;
  /** Header carrying the token. Case-insensitive. */
  header?: string;
  /**
   * Header a refusal reads its `requestId` from, and echoes it in. Case-insensitive.
   * An incoming value is reused only when it matches `^[A-Za-z0-9._:-]{1,128}$`;
   * otherwise the refusal gets a fresh UUID v4.
   */
  requestIdHeader?: string;
  /** Exact paths (query string ignored) that skip verification, e.g. a health check. */
  exemptPaths?: Iterable<string>;
  /** Receives structured events. Never given a token, a nonce or a secret. */
  log?: (event: LogEvent) => void;
}

export type ServiceTokenRequest = IncomingMessage & { serviceToken?: Claims };

const storage = new AsyncLocalStorage<string>();

/** The VERIFIED request id of the request being handled, or undefined outside one. */
export function currentRequestId(): string | undefined {
  return storage.getStore();
}

export function serviceTokenMiddleware(options: MiddlewareOptions) {
  const header = (options.header ?? "x-fancy-service-token").toLowerCase();
  const requestIdHeader = (options.requestIdHeader ?? "x-request-id").toLowerCase();
  const exempt = new Set(options.exemptPaths ?? []);
  const log = options.log ?? (() => undefined);

  return function serviceToken(req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void): void {
    const path = (req.url ?? "").split("?")[0]!;
    if (exempt.has(path)) {
      next();
      return;
    }

    let reason: Reason | undefined;
    let claims: Claims | undefined;
    const distinct = req.headersDistinct?.[header];
    if (distinct && distinct.length > 1) {
      reason = "malformed";
    } else {
      try {
        const verdict = options.verifier.verify(distinct ? distinct[0] : req.headers[header]);
        if (verdict.ok) claims = verdict.claims;
        else reason = verdict.reason;
      } catch (err) {
        // Fail closed; record the class, never the message.
        log({ level: "error", message: "service token verifier threw; refusing", errorClass: (err as Error)?.constructor?.name ?? "unknown" });
        reason = "malformed";
      }
    }

    if (!claims) {
      const refused: Reason = reason ?? "malformed";
      log({ level: "warn", message: `service token refused: ${refused}`, reason: refused });
      // The Fancy error envelope, exactly {error, message, requestId}. The
      // reason is in WWW-Authenticate, never in the body.
      const incomingIds = req.headersDistinct?.[requestIdHeader];
      const incomingId = incomingIds ? (incomingIds.length === 1 ? incomingIds[0] : undefined) : req.headers[requestIdHeader];
      const requestId = safeRequestId(incomingId) ? incomingId : randomUUID();
      const body = JSON.stringify({ error: "service_token_refused", message: REFUSAL_MESSAGES[refused], requestId });
      res.statusCode = 401;
      res.setHeader("content-type", "application/json");
      res.setHeader("content-length", String(Buffer.byteLength(body)));
      res.setHeader("cache-control", "no-store");
      res.setHeader("www-authenticate", `FancyServiceToken error="${refused}"`);
      res.setHeader(requestIdHeader, requestId);
      // The unread body must not be parsed as a next request on this socket.
      res.setHeader("connection", "close");
      res.end(body);
      return;
    }

    (req as ServiceTokenRequest).serviceToken = claims;
    log({ level: "debug", message: `service token accepted for request ${claims.requestId}`, requestId: claims.requestId });
    storage.run(claims.requestId, () => next());
  };
}
