import { describe, expect, it } from "vitest";

import { MemoryReplayStore, Verifier, type VerifierOptions } from "../src/index";
import { NOW, SECRET, VALID } from "./fixtures";

const verifier = (over: Partial<VerifierOptions> = {}): Verifier =>
  new Verifier({ keys: [{ kid: "k2026b", secret: SECRET }], audience: "ocr-sidecar", issuer: "laravel-app", ...over });

describe("Verifier", () => {
  it("has secure defaults", () => {
    const v = verifier();
    expect(v.clockSkew).toBe(10);
    expect(v.maxLifetime).toBe(300);
    expect(v.maxTokenBytes).toBe(1024);
    expect(v.requireNonce).toBe(true);
    expect(v.replayStore).toBeInstanceOf(MemoryReplayStore);
  });

  it("refuses a short key at construction without echoing it", () => {
    const secret = Buffer.from("short-secret-value");
    let message = "";
    try {
      new Verifier({ keys: [{ kid: "k1", secret }], audience: "a", issuer: "i" });
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toContain("k1");
    expect(message).not.toContain("short-secret-value");
  });

  it("lets minKeyBytes be configured", () => {
    expect(() => new Verifier({ keys: [{ kid: "k1", secret: Buffer.alloc(16, 1) }], audience: "a", issuer: "i", minKeyBytes: 16 })).not.toThrow();
  });

  it("refuses duplicate key ids, no keys, and negative limits", () => {
    expect(() => verifier({ keys: [{ kid: "k2026b", secret: SECRET }, { kid: "k2026b", secret: SECRET }] })).toThrow();
    expect(() => verifier({ keys: [] })).toThrow();
    for (const field of ["clockSkew", "maxLifetime", "maxTokenBytes"] as const) {
      expect(() => verifier({ [field]: -1 })).toThrow();
    }
  });

  it("never puts the token or a secret in a verdict", () => {
    const verdict = verifier().verify(VALID, NOW);
    expect(verdict.ok).toBe(true);
    const text = JSON.stringify(verdict);
    expect(text).not.toContain(VALID);
    expect(text).not.toContain(VALID.split(".")[2]!);
    expect(text).not.toContain(SECRET.toString("hex"));
    expect(text).not.toContain("n0nce-AAAAAAAAAAAAAAAA");
  });

  it("turns garbage of every type into a named refusal, never an exception", () => {
    const v = verifier();
    const junk: unknown[] = [Buffer.from([0xff, 0xfe]), "fst1..", "fst1.%%%.%%%", "fst1." + "\u0000".repeat(50) + ".x", 12345, {}, [], Symbol("x")];
    for (const j of junk) {
      const verdict = v.verify(j, NOW);
      expect(verdict.ok).toBe(false);
      if (!verdict.ok) expect(["malformed", "missing"]).toContain(verdict.reason);
    }
  });

  it("accepts Buffer header values", () => {
    expect(verifier().verify(Buffer.from(VALID), NOW).ok).toBe(true);
  });

  it("uses the clock when no time is given", () => {
    expect(verifier({ clock: () => (NOW + 0.9) * 1000 }).verify(VALID).ok).toBe(true);
    const late = verifier({ clock: () => (NOW + 3600) * 1000 }).verify(VALID);
    expect(late.ok ? null : late.reason).toBe("expired");
  });

  it("exposes the verified claims", () => {
    const verdict = verifier().verify(VALID, NOW);
    if (!verdict.ok) throw new Error("expected ok");
    expect(verdict.claims).toEqual({
      kid: "k2026b",
      issuer: "laravel-app",
      audience: "ocr-sidecar",
      issuedAt: 1793000000,
      expiresAt: 1793000060,
      requestId: "req-01HZX3K8Q2",
    });
  });

  it("holds a nonce until exp + skew", () => {
    const v = verifier();
    expect(v.verify(VALID, NOW).ok).toBe(true);
    const again = v.verify(VALID, 1793000060 + 9);
    expect(again.ok ? null : again.reason).toBe("replayed");
  });

  it("can turn replay checks off explicitly", () => {
    const v = verifier({ replayStore: null });
    expect(v.verify(VALID, NOW).ok).toBe(true);
    expect(v.verify(VALID, NOW).ok).toBe(true);
  });
});

describe("MemoryReplayStore", () => {
  it("fails closed when full", () => {
    const store = new MemoryReplayStore(1);
    expect(store.add("a", NOW + 60, NOW)).toBe(true);
    expect(store.add("b", NOW + 60, NOW)).toBe(false);
  });

  it("forgets expired entries", () => {
    const store = new MemoryReplayStore(1);
    expect(store.add("a", NOW + 1, NOW)).toBe(true);
    expect(store.add("b", NOW + 60, NOW + 2)).toBe(true);
    expect(store.add("a", NOW + 60, NOW + 2)).toBe(false);
  });
});
