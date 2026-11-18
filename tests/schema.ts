/**
 * A first-party validator for the keywords envelope.schema.json uses: type,
 * required, properties, enum, pattern, minLength, maxLength, items, minItems,
 * minimum, additionalProperties and a local $ref. Anything else in the schema
 * is an error rather than silently ignored, so a schema that grows a keyword
 * this does not understand fails the suite instead of passing everything.
 */
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const SCHEMA_PATH = fileURLToPath(new URL("./fixtures/envelope.schema.json", import.meta.url));
// Copied unchanged from fancy-http-errors/envelope.schema.json (identical to
// fancy-conformance suites/http/error-envelope/envelope.schema.json).
export const SCHEMA_SHA256 = "af4fc3e4bbd9dc29fa32cb3a6ea8d7285d84036a7b5e52daa47e29d8e6516509";

type Schema = Record<string, unknown>;

const KNOWN = new Set([
  "$schema",
  "$id",
  "$defs",
  "$ref",
  "title",
  "description",
  "type",
  "required",
  "properties",
  "enum",
  "pattern",
  "minLength",
  "maxLength",
  "items",
  "minItems",
  "minimum",
  "additionalProperties",
]);

export function schemaBytes(): Buffer {
  return readFileSync(SCHEMA_PATH);
}

export function sha256(data: Buffer | string): string {
  return createHash("sha256").update(data).digest("hex");
}

export function loadSchema(): Schema {
  return JSON.parse(schemaBytes().toString("utf8")) as Schema;
}

const typeOf = (v: unknown): string =>
  v === null ? "null" : Array.isArray(v) ? "array" : Number.isInteger(v) ? "integer" : typeof v;

/** Every violation as "path: problem". Empty means valid. */
export function validate(value: unknown, root: Schema = loadSchema()): string[] {
  const errors: string[] = [];
  const walk = (v: unknown, s: Schema, path: string): void => {
    for (const k of Object.keys(s)) if (!KNOWN.has(k)) errors.push(`${path}: schema keyword ${k} is not supported`);
    if (typeof s.$ref === "string") {
      const name = s.$ref.replace(/^#\/\$defs\//, "");
      const target = (root.$defs as Record<string, Schema> | undefined)?.[name];
      if (!target) errors.push(`${path}: unresolved $ref ${s.$ref}`);
      else walk(v, target, path);
      return;
    }
    if (typeof s.type === "string") {
      const t = typeOf(v);
      const ok = s.type === t || (s.type === "number" && (t === "number" || t === "integer"));
      if (!ok) {
        errors.push(`${path}: expected ${s.type}, got ${t}`);
        return;
      }
    }
    if (Array.isArray(s.enum) && !s.enum.includes(v)) errors.push(`${path}: not in enum`);
    if (typeof v === "string") {
      if (typeof s.pattern === "string" && !new RegExp(s.pattern, "u").test(v)) errors.push(`${path}: does not match ${s.pattern}`);
      const len = [...v].length;
      if (typeof s.minLength === "number" && len < s.minLength) errors.push(`${path}: shorter than ${s.minLength}`);
      if (typeof s.maxLength === "number" && len > s.maxLength) errors.push(`${path}: longer than ${s.maxLength}`);
    }
    if (typeof v === "number" && typeof s.minimum === "number" && v < s.minimum) errors.push(`${path}: below ${s.minimum}`);
    if (Array.isArray(v)) {
      if (typeof s.minItems === "number" && v.length < s.minItems) errors.push(`${path}: fewer than ${s.minItems} items`);
      if (s.items && typeof s.items === "object") v.forEach((item, i) => walk(item, s.items as Schema, `${path}[${i}]`));
    }
    if (v && typeof v === "object" && !Array.isArray(v)) {
      const obj = v as Record<string, unknown>;
      const props = (s.properties ?? {}) as Record<string, Schema>;
      for (const r of (s.required as string[] | undefined) ?? []) if (!(r in obj)) errors.push(`${path}: missing ${r}`);
      for (const [k, child] of Object.entries(obj)) {
        if (k in props) walk(child, props[k]!, `${path}.${k}`);
        else if (s.additionalProperties === false) errors.push(`${path}: unexpected member ${k}`);
      }
    }
  };
  walk(value, root, "$");
  return errors;
}
