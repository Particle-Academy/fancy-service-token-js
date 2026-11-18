// Break one clause of the verifier or middleware at a time; the suite must
// notice every one. A suite written alongside its implementation passes on its
// first run, and a check never seen to fail cannot be told apart from one that
// cannot. Each file is restored in a `finally`. Exits 1 if a mutation survives.
//
//   node tests/sabotage.mjs
import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const src = (name) => fileURLToPath(new URL(`../src/${name}`, import.meta.url));

const MUTATIONS = [
  ["signature unchecked", "verifier.ts", "if (!timingSafeEqual(expected, signature) || !key)", "if (!key)"],
  ["audience unchecked", "verifier.ts", "if (aud !== this.audience)", "if (false)"],
  ["issuer unchecked", "verifier.ts", "if (iss !== this.issuer)", "if (false)"],
  ["exp inclusive", "verifier.ts", "if (now >= exp + this.clockSkew)", "if (now > exp + this.clockSkew)"],
  ["iat off by one", "verifier.ts", "if (now + this.clockSkew < iat)", "if (now + this.clockSkew < iat - 1)"],
  ["grace window off by one", "verifier.ts", "now > key.acceptUntil", "now > key.acceptUntil + 1"],
  ["replay ignored", "verifier.ts", 'return no("replayed");', ";"],
  ["nonce not required", "verifier.ts", "} else if (this.requireNonce)", "} else if (false)"],
  ["lifetime unbounded", "verifier.ts", "exp - iat > this.maxLifetime", "false"],
  ["size unbounded", "verifier.ts", "if (token.length > this.maxTokenBytes)", "if (false)"],
  ["non-canonical base64 accepted", "verifier.ts", 'if (raw.toString("base64url") !== text) return null;', ""],
  ["middleware never refuses", "middleware.ts", "if (!claims) {", "if (false) {"],
  ["duplicate header tolerated", "middleware.ts", "if (distinct && distinct.length > 1)", "if (false)"],
  ["reason back in the body", "middleware.ts", "message: REFUSAL_MESSAGES[refused], requestId }", "message: REFUSAL_MESSAGES[refused], requestId, reason: refused }"],
  ["unsafe request id echoed", "middleware.ts", "safeRequestId(incomingId) ? incomingId", "incomingId ? incomingId"],
  ["request id header not echoed", "middleware.ts", "res.setHeader(requestIdHeader, requestId);", ""],
  ["sentence drifts", "middleware.ts", "The service token has expired.", "The token has expired."],
  ["exception text leaked","middleware.ts", 'errorClass: (err as Error)?.constructor?.name ?? "unknown"', "errorClass: String(err)"],
];

let survivors = 0;
for (const [label, file, from, to] of MUTATIONS) {
  const path = src(file);
  const original = readFileSync(path);
  const text = original.toString("utf8");
  if (!text.includes(from)) {
    console.log(`BROKEN SWEEP  ${label}: pattern not found in ${file}`);
    survivors++;
    continue;
  }
  let status;
  try {
    writeFileSync(path, text.replace(from, to));
    status = spawnSync(process.execPath, ["node_modules/vitest/vitest.mjs", "run", "--bail=1"], { cwd: root, stdio: "ignore" }).status;
  } finally {
    writeFileSync(path, original);
  }
  if (status === 0) {
    console.log(`SURVIVED      ${label}`);
    survivors++;
  } else {
    console.log(`killed        ${label}`);
  }
}
console.log(`${MUTATIONS.length - survivors}/${MUTATIONS.length} mutations killed`);
process.exit(survivors ? 1 : 0);
