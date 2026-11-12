/**
 * The verifier for `fst1` service tokens. node:crypto only: createHmac and
 * timingSafeEqual. No JWT library and no cryptography of our own.
 *
 * The format and the ORDER of the checks are defined in the README and pinned
 * by the shared fixtures; the order decides which reason a token that is wrong
 * in two ways is refused with, so the PHP and Python legs follow it exactly.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export const PREFIX = "fst1";
const SIGNATURE_CHARS = 43;

export const REASONS = [
  "missing",
  "malformed",
  "bad_signature",
  "expired",
  "not_yet_valid",
  "wrong_audience",
  "replayed",
] as const;
export type Reason = (typeof REASONS)[number];

export interface Key {
  kid: string;
  secret: Uint8Array;
  /** Unix seconds. Marks a PREVIOUS key, accepted until (and including) this second. */
  acceptUntil?: number | null;
}

/** The verified contents of a token. Never holds the token, the nonce or a secret. */
export interface Claims {
  kid: string;
  issuer: string;
  audience: string;
  issuedAt: number;
  expiresAt: number;
  requestId: string;
}

export type Verdict = { ok: true; claims: Claims } | { ok: false; reason: Reason };

export interface ReplayStore {
  /** Record `key` until `expiresAt`. True if it was new; false if already held (or refused). */
  add(key: string, expiresAt: number, now: number): boolean;
}

/**
 * Per-process nonce memory. Fails CLOSED when full: a nonce it cannot record is
 * refused. Several processes behind one port need a shared store.
 */
export class MemoryReplayStore implements ReplayStore {
  private seen = new Map<string, number>();

  constructor(readonly maxEntries = 100_000) {
    if (!Number.isInteger(maxEntries) || maxEntries < 1) throw new RangeError("maxEntries must be at least 1");
  }

  add(key: string, expiresAt: number, now: number): boolean {
    const held = this.seen.get(key);
    if (held !== undefined && held > now) return false;
    if (this.seen.size >= this.maxEntries) {
      for (const [k, v] of this.seen) if (v <= now) this.seen.delete(k);
      if (this.seen.size >= this.maxEntries) return false;
    }
    this.seen.set(key, expiresAt);
    return true;
  }
}

export interface VerifierOptions {
  keys: Key[];
  audience: string;
  issuer: string;
  clockSkew?: number;
  maxLifetime?: number;
  maxTokenBytes?: number;
  requireNonce?: boolean;
  minKeyBytes?: number;
  /** `null` turns replay checks off. Default: a new MemoryReplayStore. */
  replayStore?: ReplayStore | null;
  /** Milliseconds, like Date.now. */
  clock?: () => number;
}

const B64URL = /^[A-Za-z0-9_-]*$/;
const charset = (extra: string) => new Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" + extra);
const KID = charset("._-");
const NAME = charset("._:/-");
const RID = charset("._:-");
const NONCE = charset("_-");
const DIGITS = new Set("0123456789");

function only(value: string, chars: Set<string>, min: number, max: number): boolean {
  if (value.length < min || value.length > max) return false;
  for (const c of value) if (!chars.has(c)) return false;
  return true;
}

function time(value: string): number | null {
  if (!only(value, DIGITS, 1, 12) || value[0] === "0") return null;
  return Number(value);
}

/** Strict unpadded base64url: right alphabet, right length, and the ONE canonical spelling. */
function b64decode(text: string): Buffer | null {
  if (text.length === 0 || text.length % 4 === 1 || !B64URL.test(text)) return null;
  const raw = Buffer.from(text, "base64url");
  if (raw.toString("base64url") !== text) return null;
  return raw;
}

const no = (reason: Reason): Verdict => ({ ok: false, reason });

export class Verifier {
  readonly audience: string;
  readonly issuer: string;
  readonly clockSkew: number;
  readonly maxLifetime: number;
  readonly maxTokenBytes: number;
  readonly requireNonce: boolean;
  readonly replayStore: ReplayStore | null;
  private readonly keys: Map<string, Key>;
  private readonly clock: () => number;

  constructor(options: VerifierOptions) {
    const { clockSkew = 10, maxLifetime = 300, maxTokenBytes = 1024, minKeyBytes = 32 } = options;
    for (const [label, value] of [
      ["clockSkew", clockSkew],
      ["maxLifetime", maxLifetime],
      ["maxTokenBytes", maxTokenBytes],
    ] as const) {
      if (!Number.isInteger(value) || value < 0) throw new RangeError(`${label} must be a non-negative integer`);
    }
    if (!options.keys || options.keys.length === 0) throw new Error("at least one key is required");
    if (!only(options.audience, NAME, 1, 128) || !only(options.issuer, NAME, 1, 128)) {
      throw new Error("audience and issuer must be 1-128 chars of [A-Za-z0-9._:/-]");
    }
    this.keys = new Map();
    for (const key of options.keys) {
      if (!only(key.kid, KID, 1, 64)) throw new Error("a key id must be 1-64 chars of [A-Za-z0-9._-]");
      if (this.keys.has(key.kid)) throw new Error(`duplicate key id "${key.kid}"`);
      // Names the key, never its value.
      if (!(key.secret instanceof Uint8Array) || key.secret.length < minKeyBytes) {
        throw new Error(`key "${key.kid}" is shorter than ${minKeyBytes} bytes`);
      }
      this.keys.set(key.kid, key);
    }
    this.audience = options.audience;
    this.issuer = options.issuer;
    this.clockSkew = clockSkew;
    this.maxLifetime = maxLifetime;
    this.maxTokenBytes = maxTokenBytes;
    this.requireNonce = options.requireNonce ?? true;
    this.replayStore = options.replayStore === undefined ? new MemoryReplayStore() : options.replayStore;
    this.clock = options.clock ?? Date.now;
  }

  /** Never throws for any input: an unexpected failure is a `malformed` refusal. */
  verify(token: unknown, now?: number): Verdict {
    try {
      return this.check(token, now ?? Math.floor(this.clock() / 1000));
    } catch {
      return no("malformed");
    }
  }

  private check(input: unknown, now: number): Verdict {
    // 1. Missing.
    if (input === null || input === undefined || input === "") return no("missing");
    let token: string;
    if (typeof input === "string") token = input;
    else if (input instanceof Uint8Array) {
      if (input.length === 0) return no("missing");
      for (const b of input) if (b > 0x7f) return no("malformed");
      token = Buffer.from(input).toString("latin1");
    } else return no("malformed");

    // 2. Size, before any parsing.
    if (token.length > this.maxTokenBytes) return no("malformed");

    // 3. Structure: exactly prefix . payload . signature, each canonical.
    const parts = token.split(".");
    if (parts.length !== 3 || parts[0] !== PREFIX || parts[2]!.length !== SIGNATURE_CHARS) return no("malformed");
    const signature = b64decode(parts[2]!);
    const raw = b64decode(parts[1]!);
    if (!signature || !raw || signature.length !== 32) return no("malformed");

    // 4. Payload grammar: seven LF-separated ASCII fields.
    for (const b of raw) if (b > 0x7f) return no("malformed");
    const fields = raw.toString("latin1").split("\n");
    if (fields.length !== 7) return no("malformed");
    const [kid, iss, aud, iatS, expS, rid, nonce] = fields as [string, string, string, string, string, string, string];
    const iat = time(iatS);
    const exp = time(expS);
    if (
      !only(kid, KID, 1, 64) ||
      !only(iss, NAME, 1, 128) ||
      !only(aud, NAME, 1, 128) ||
      !only(rid, RID, 1, 128) ||
      iat === null ||
      exp === null ||
      exp <= iat ||
      exp - iat > this.maxLifetime
    ) {
      return no("malformed");
    }
    if (nonce !== "") {
      if (!only(nonce, NONCE, 16, 128)) return no("malformed");
    } else if (this.requireNonce) return no("malformed");

    // 5. Signature. An unknown kid, a retired key past its grace window and
    //    another issuer are all "not signed by a key we hold for this issuer".
    const key = this.keys.get(kid);
    const expected = createHmac("sha256", key ? key.secret : Buffer.alloc(32))
      .update(PREFIX + "." + parts[1]!, "latin1")
      .digest();
    if (!timingSafeEqual(expected, signature) || !key) return no("bad_signature");
    if (key.acceptUntil !== undefined && key.acceptUntil !== null && now > key.acceptUntil) return no("bad_signature");
    if (iss !== this.issuer) return no("bad_signature");

    // 6. Audience, 7. time window, 8. replay -- last, so only a token that is
    //    otherwise acceptable can spend a nonce.
    if (aud !== this.audience) return no("wrong_audience");
    if (now + this.clockSkew < iat) return no("not_yet_valid");
    if (now >= exp + this.clockSkew) return no("expired");
    if (nonce !== "" && this.replayStore && !this.replayStore.add(iss + "\n" + nonce, exp + this.clockSkew, now)) {
      return no("replayed");
    }

    return { ok: true, claims: { kid, issuer: iss, audience: aud, issuedAt: iat, expiresAt: exp, requestId: rid } };
  }
}
