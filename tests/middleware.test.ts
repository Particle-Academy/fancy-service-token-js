import { createServer, request as httpRequest, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

import { readFileSync } from "node:fs";

import { afterEach, describe, expect, it } from "vitest";

import {
  MemoryReplayStore,
  REASONS,
  REFUSAL_MESSAGES,
  Verifier,
  currentRequestId,
  serviceTokenMiddleware,
  type LogEvent,
  type ServiceTokenRequest,
} from "../src/index";
import { NOW, SECRET, VALID, caseToken } from "./fixtures";
import { SCHEMA_SHA256, schemaBytes, sha256, validate } from "./schema";

const MESSAGES_PATH = new URL("../conformance/refusal-messages.json", import.meta.url);
// Pinned in the Python and Node legs: the refusal sentences are identical in
// both by test result, not by care.
const MESSAGES_SHA256 = "80a951939bd9fcca2e555bbdd337a60481966a0ec3adabed573c46c735e231eb";
const MESSAGES = JSON.parse(readFileSync(MESSAGES_PATH, "utf8")) as {
  status: number;
  error: string;
  messages: Record<string, string>;
};
const UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

const WRONG_AUDIENCE = caseToken("wrong_audience");
const TAMPERED = caseToken("tampered_signature");
const HEADER = "x-fancy-service-token";

const makeVerifier = (): Verifier =>
  new Verifier({
    keys: [{ kid: "k2026b", secret: SECRET }],
    audience: "ocr-sidecar",
    issuer: "laravel-app",
    clock: () => NOW * 1000,
    replayStore: new MemoryReplayStore(),
  });

/** A request whose every body-reading method throws. Headers only. */
function trapRequest(headers: Record<string, string | string[]>, url = "/work"): IncomingMessage {
  const boom = (): never => {
    throw new Error("the body stream was touched");
  };
  const distinct: Record<string, string[]> = {};
  const flat: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) {
    distinct[k] = Array.isArray(v) ? v : [v];
    flat[k] = Array.isArray(v) ? v.join(", ") : v;
  }
  return {
    method: "POST",
    url,
    headers: flat,
    headersDistinct: distinct,
    on: boom,
    once: boom,
    addListener: boom,
    read: boom,
    pipe: boom,
    resume: boom,
    [Symbol.asyncIterator]: boom,
  } as unknown as IncomingMessage;
}

interface Captured {
  status: number;
  headers: Record<string, string>;
  body: string;
}

function fakeResponse(): { res: ServerResponse; out: Captured } {
  const out: Captured = { status: 0, headers: {}, body: "" };
  const res = {
    set statusCode(v: number) {
      out.status = v;
    },
    setHeader(k: string, v: string) {
      out.headers[k.toLowerCase()] = String(v);
    },
    end(b?: string) {
      out.body = b ?? "";
    },
  } as unknown as ServerResponse;
  return { res, out };
}

describe("serviceTokenMiddleware: refusal never touches the handler or the body", () => {
  const cases: [Record<string, string | string[]>, string][] = [
    [{}, "missing"],
    [{ [HEADER]: "" }, "missing"],
    [{ [HEADER]: "not-a-token" }, "malformed"],
    [{ [HEADER]: WRONG_AUDIENCE }, "wrong_audience"],
    [{ [HEADER]: TAMPERED }, "bad_signature"],
    [{ [HEADER]: [VALID, VALID] }, "malformed"],
  ];
  for (const [headers, reason] of cases) {
    it(`refuses ${reason} (${Object.keys(headers).length ? "header" : "no header"})`, () => {
      let nextCalls = 0;
      const { res, out } = fakeResponse();
      serviceTokenMiddleware({ verifier: makeVerifier() })(trapRequest(headers), res, () => {
        nextCalls++;
      });
      expect(nextCalls).toBe(0);
      expect(out.status).toBe(401);
      const body = JSON.parse(out.body);
      expect(validate(body)).toEqual([]);
      expect(Object.keys(body).sort()).toEqual(["error", "message", "requestId"]);
      expect(body.error).toBe("service_token_refused");
      expect(body.message).toBe(MESSAGES.messages[reason]);
      expect(body.requestId).toMatch(UUID_V4);
      expect(out.headers["x-request-id"]).toBe(body.requestId);
      expect(out.headers["cache-control"]).toBe("no-store");
      expect(out.headers["www-authenticate"]).toBe(`FancyServiceToken error="${reason}"`);
      expect(out.headers["connection"]).toBe("close");
    });
  }

  it("refuses a replayed nonce before the body", () => {
    const mw = serviceTokenMiddleware({ verifier: makeVerifier() });
    let nextCalls = 0;
    mw(trapRequest({ [HEADER]: VALID }), fakeResponse().res, () => {
      nextCalls++;
    });
    expect(nextCalls).toBe(1);
    const { res, out } = fakeResponse();
    mw(trapRequest({ [HEADER]: VALID }), res, () => {
      nextCalls++;
    });
    expect(nextCalls).toBe(1);
    expect(out.headers["www-authenticate"]).toBe('FancyServiceToken error="replayed"');
    expect(JSON.parse(out.body).message).toBe(MESSAGES.messages.replayed);
  });

  it("fails closed, without exception text, when the verifier throws", () => {
    const v = makeVerifier();
    v.verify = () => {
      throw new Error("secret detail " + SECRET.toString("hex"));
    };
    const events: LogEvent[] = [];
    const { res, out } = fakeResponse();
    let nextCalls = 0;
    serviceTokenMiddleware({ verifier: v, log: (e) => events.push(e) })(trapRequest({ [HEADER]: VALID }), res, () => {
      nextCalls++;
    });
    expect(nextCalls).toBe(0);
    const body = JSON.parse(out.body);
    expect(validate(body)).toEqual([]);
    expect(body.message).toBe(MESSAGES.messages.malformed);
    expect(out.headers["www-authenticate"]).toBe('FancyServiceToken error="malformed"');
    expect(out.body).not.toContain("secret detail");
    const logged = JSON.stringify(events);
    expect(logged).not.toContain("secret detail");
    expect(logged).not.toContain(SECRET.toString("hex"));
    expect(logged).toContain("Error");
  });
});

describe("serviceTokenMiddleware: the refusal is the Fancy error envelope", () => {
  const refuse = (headers: Record<string, string | string[]>, options: { requestIdHeader?: string } = {}): Captured => {
    const { res, out } = fakeResponse();
    serviceTokenMiddleware({ verifier: makeVerifier(), ...options })(trapRequest(headers), res, () => undefined);
    return out;
  };

  it("validates against the copied schema, byte for byte", () => {
    expect(sha256(schemaBytes())).toBe(SCHEMA_SHA256);
  });

  it("the validator rejects the 0.1.0 body, so a pass above means something", () => {
    expect(validate({ error: "service_token_refused", reason: "expired" })).not.toEqual([]);
    expect(validate({ error: "service_token_refused", message: "x", requestId: "r", reason: "expired" })).not.toEqual([]);
    expect(validate({ error: "service_token_refused", message: "x", requestId: "r" })).toEqual([]);
  });

  it("carries one fixed sentence per reason, identical to the shared fixture", () => {
    expect(sha256(readFileSync(MESSAGES_PATH))).toBe(MESSAGES_SHA256);
    expect(REFUSAL_MESSAGES).toEqual(MESSAGES.messages);
    expect(Object.keys(MESSAGES.messages).sort()).toEqual([...REASONS].sort());
    expect(MESSAGES.status).toBe(401);
    expect(MESSAGES.error).toBe("service_token_refused");
  });

  it("echoes a well-formed incoming x-request-id in the body and the header", () => {
    const out = refuse({ "x-request-id": "req-01HZX3K8Q2.a:b_c" });
    expect(JSON.parse(out.body).requestId).toBe("req-01HZX3K8Q2.a:b_c");
    expect(out.headers["x-request-id"]).toBe("req-01HZX3K8Q2.a:b_c");
  });

  for (const bad of ["has space", "x".repeat(129), "semi;colon", "", "caf\u00e9", "line\nbreak"]) {
    it(`replaces an unsafe incoming request id (${JSON.stringify(bad).slice(0, 20)})`, () => {
      const out = refuse({ "x-request-id": bad });
      const body = JSON.parse(out.body);
      expect(validate(body)).toEqual([]);
      expect(body.requestId).toMatch(UUID_V4);
      expect(out.headers["x-request-id"]).toBe(body.requestId);
    });
  }

  it("replaces a duplicated incoming request id", () => {
    const body = JSON.parse(refuse({ "x-request-id": ["a", "b"] }).body);
    expect(body.requestId).toMatch(UUID_V4);
  });

  it("generates a fresh id per refusal", () => {
    expect(JSON.parse(refuse({}).body).requestId).not.toBe(JSON.parse(refuse({}).body).requestId);
  });

  it("reads the request id from a configurable header", () => {
    const out = refuse({ "x-correlation-id": "corr-1" }, { requestIdHeader: "X-Correlation-Id" });
    expect(JSON.parse(out.body).requestId).toBe("corr-1");
    expect(out.headers["x-correlation-id"]).toBe("corr-1");
  });

  it("sets content-length to the byte length of the body", () => {
    const out = refuse({});
    expect(out.headers["content-length"]).toBe(String(Buffer.byteLength(out.body)));
  });
});

describe("serviceTokenMiddleware: acceptance", () => {
  it("passes claims and the request id to the handler", () => {
    const req = trapRequest({ [HEADER]: VALID });
    let seen: string | undefined;
    serviceTokenMiddleware({ verifier: makeVerifier() })(req, fakeResponse().res, () => {
      seen = currentRequestId();
    });
    expect(seen).toBe("req-01HZX3K8Q2");
    expect((req as IncomingMessage & { serviceToken?: { requestId: string } }).serviceToken?.requestId).toBe("req-01HZX3K8Q2");
    expect(currentRequestId()).toBeUndefined();
  });

  it("uses a configurable header name, case-insensitively", () => {
    const mw = serviceTokenMiddleware({ verifier: makeVerifier(), header: "X-Sidecar-Auth" });
    let nextCalls = 0;
    mw(trapRequest({ "x-sidecar-auth": VALID }), fakeResponse().res, () => {
      nextCalls++;
    });
    expect(nextCalls).toBe(1);
    const { res, out } = fakeResponse();
    mw(trapRequest({ [HEADER]: VALID }), res, () => {
      nextCalls++;
    });
    expect(nextCalls).toBe(1);
    expect(out.headers["www-authenticate"]).toBe('FancyServiceToken error="missing"');
  });

  it("exempts exact paths only, query string ignored", () => {
    const mw = serviceTokenMiddleware({ verifier: makeVerifier(), exemptPaths: ["/healthz"] });
    const pass: string[] = [];
    for (const url of ["/healthz", "/healthz?x=1", "/healthz/../work", "/healthzz"]) {
      const { res } = fakeResponse();
      mw(trapRequest({}, url), res, () => pass.push(url));
    }
    expect(pass).toEqual(["/healthz", "/healthz?x=1"]);
  });

  it("logs the reason and the verified request id, never a token or secret", () => {
    const events: LogEvent[] = [];
    const mw = serviceTokenMiddleware({ verifier: makeVerifier(), log: (e) => events.push(e) });
    for (const tok of [VALID, VALID, WRONG_AUDIENCE, TAMPERED, "garbage"]) {
      mw(trapRequest({ [HEADER]: tok }), fakeResponse().res, () => undefined);
    }
    const text = JSON.stringify(events);
    expect(text).toContain("replayed");
    expect(text).toContain("wrong_audience");
    expect(text).toContain("req-01HZX3K8Q2");
    for (const needle of [VALID, VALID.split(".")[1]!, VALID.split(".")[2]!, WRONG_AUDIENCE, TAMPERED, SECRET.toString("hex"), "garbage"]) {
      expect(text).not.toContain(needle);
    }
  });
});

describe("serviceTokenMiddleware over a real node:http server", () => {
  let close: (() => Promise<void>) | undefined;
  afterEach(async () => {
    await close?.();
    close = undefined;
  });

  it("answers 401 while the client is still sending, and never reads the body", async () => {
    const seen: { handler: number; dataListeners: number[]; flowing: (boolean | null)[] } = { handler: 0, dataListeners: [], flowing: [] };
    const mw = serviceTokenMiddleware({ verifier: makeVerifier() });
    const server = createServer((req, res) => {
      mw(req, res, async () => {
        seen.handler++;
        await Promise.resolve();
        // Survives an await inside the handler. Stream events below are
        // emitted from the socket's context, so read the claims off req there.
        const ridAfterAwait = currentRequestId();
        let body = "";
        req.on("data", (c: Buffer) => (body += c.toString()));
        req.on("end", () =>
          res.end(JSON.stringify({ rid: ridAfterAwait, claimed: (req as ServiceTokenRequest).serviceToken?.requestId, body })),
        );
      });
      // Measured synchronously after the middleware ran, before Node's own
      // post-response cleanup drains the socket.
      seen.dataListeners.push(req.listenerCount("data"));
      seen.flowing.push(req.readableFlowing);
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    close = () => new Promise<void>((r) => server.close(() => r()));
    const { port } = server.address() as AddressInfo;

    const send = (
      token: string | undefined,
      finishBody: boolean,
    ): Promise<{ status: number; body: string; wwwAuthenticate?: string; requestId?: string }> =>
      new Promise((resolve, reject) => {
        const req = httpRequest(
          { host: "127.0.0.1", port, method: "POST", path: "/work", headers: token ? { [HEADER]: token } : {} },
          (res) => {
            let b = "";
            res.on("data", (c: Buffer) => (b += c.toString()));
            res.on("end", () =>
              resolve({
                status: res.statusCode ?? 0,
                body: b,
                wwwAuthenticate: res.headers["www-authenticate"] as string | undefined,
                requestId: res.headers["x-request-id"] as string | undefined,
              }),
            );
          },
        );
        req.on("error", reject);
        req.write('{"hello":');
        if (finishBody) req.end('"world"}');
        else setTimeout(() => req.destroy(), 500);
      });

    const refused = await send(TAMPERED, false);
    expect(refused.status).toBe(401);
    expect(refused.wwwAuthenticate).toBe('FancyServiceToken error="bad_signature"');
    const refusedBody = JSON.parse(refused.body);
    expect(validate(refusedBody)).toEqual([]);
    expect(refused.requestId).toBe(refusedBody.requestId);
    expect(seen.handler).toBe(0);
    expect(seen.dataListeners[0]).toBe(0);
    expect(seen.flowing[0]).toBe(null);

    const ok = await send(VALID, true);
    expect(ok.status).toBe(200);
    expect(JSON.parse(ok.body)).toEqual({ rid: "req-01HZX3K8Q2", claimed: "req-01HZX3K8Q2", body: '{"hello":"world"}' });
    expect(seen.handler).toBe(1);
  });
});
