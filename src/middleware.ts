/**
 * A connect-style `(req, res, next)` middleware: Express, Connect, Polka and a
 * bare node:http handler all take it. It decides from `req.headers` alone, so
 * on a refusal nothing ever reads, parses or buffers the request body, and the
 * handler is never called. Mount it BEFORE any body parser.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import type { IncomingMessage, ServerResponse } from "node:http";

import type { Claims, Reason, Verifier } from "./verifier";

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
      const body = JSON.stringify({ error: "service_token_refused", reason: refused });
      res.statusCode = 401;
      res.setHeader("content-type", "application/json");
      res.setHeader("content-length", String(Buffer.byteLength(body)));
      res.setHeader("cache-control", "no-store");
      res.setHeader("www-authenticate", `FancyServiceToken error="${refused}"`);
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
