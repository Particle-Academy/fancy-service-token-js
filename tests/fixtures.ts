import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { MemoryReplayStore, Verifier, type Reason } from "../src/index";

export const FIXTURES_PATH = fileURLToPath(new URL("../conformance/service-token-v1.json", import.meta.url));

// Pinned in EVERY leg (PHP, Python, Node). A copy that drifts in one repository
// fails that repository's suite, so "byte-identical" is a test result.
export const FIXTURES_SHA256 = "767caf66f1fc2cba980dc493c10c18df21676720e8183565397bdeea80b328bd";

export interface VerifierSpec {
  audience: string;
  issuer: string;
  clock_skew: number;
  max_lifetime: number;
  max_token_bytes: number;
  require_nonce: boolean;
  keys: { kid: string; secret_hex: string; accept_until: number | null }[];
}

export interface Step {
  token: string | null;
  now: number;
  expect: { ok: boolean; reason: Reason | null; request_id: string | null };
}

export interface Case {
  name: string;
  why: string;
  verifier: VerifierSpec;
  steps: Step[];
}

export interface Fixtures {
  sign: { name: string; input: Record<string, string | number>; token: string }[];
  verify: Case[];
}

export const RAW = readFileSync(FIXTURES_PATH);
export const FX: Fixtures = JSON.parse(RAW.toString("utf8"));

export const sha256 = (data: Uint8Array): string => createHash("sha256").update(data).digest("hex");

export function build(v: VerifierSpec): Verifier {
  return new Verifier({
    keys: v.keys.map((k) => ({ kid: k.kid, secret: Buffer.from(k.secret_hex, "hex"), acceptUntil: k.accept_until })),
    audience: v.audience,
    issuer: v.issuer,
    clockSkew: v.clock_skew,
    maxLifetime: v.max_lifetime,
    maxTokenBytes: v.max_token_bytes,
    requireNonce: v.require_nonce,
    replayStore: new MemoryReplayStore(),
  });
}

export const VALID = FX.sign[0]!.token;
export const SECRET = Buffer.from(String(FX.sign[0]!.input.secret_hex), "hex");
export const NOW = 1793000005;
export const caseToken = (name: string): string => FX.verify.find((c) => c.name === name)!.steps[0]!.token!;
