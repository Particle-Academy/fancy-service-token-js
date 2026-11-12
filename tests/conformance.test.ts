import { describe, expect, it } from "vitest";

import { REASONS } from "../src/index";
import { FIXTURES_SHA256, FX, RAW, build, sha256 } from "./fixtures";

describe("shared conformance fixtures", () => {
  it("is the pinned file, byte for byte", () => {
    expect(sha256(RAW)).toBe(FIXTURES_SHA256);
  });

  it("covers every reason", () => {
    const seen = new Set(FX.verify.flatMap((c) => c.steps.map((s) => s.expect.reason)));
    expect([...seen].sort()).toEqual([null, ...REASONS].sort());
  });

  it("names exactly the contract's reasons, in order", () => {
    expect(REASONS).toEqual([
      "missing",
      "malformed",
      "bad_signature",
      "expired",
      "not_yet_valid",
      "wrong_audience",
      "replayed",
    ]);
  });

  for (const c of FX.verify) {
    it(c.name, () => {
      const verifier = build(c.verifier);
      c.steps.forEach((step, i) => {
        const verdict = verifier.verify(step.token, step.now);
        expect({ step: i, ok: verdict.ok }).toEqual({ step: i, ok: step.expect.ok });
        expect({ step: i, reason: verdict.ok ? null : verdict.reason }).toEqual({ step: i, reason: step.expect.reason });
        expect({ step: i, rid: verdict.ok ? verdict.claims.requestId : null }).toEqual({
          step: i,
          rid: step.expect.request_id,
        });
      });
    });
  }
});
