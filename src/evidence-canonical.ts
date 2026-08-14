import { createHash } from "node:crypto";
import { AppError } from "./errors.js";

export const CANONICALIZATION_VERSION = "JCS-1";

function canonicalizeValue(value: unknown): unknown {
  if (value === null || typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new AppError("SCHEMA_ERROR", "schema_error: non-finite number");
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) return value.map(canonicalizeValue);
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return Object.fromEntries(
      // JCS-1 uses deterministic code-unit ordering. localeCompare is
      // locale-dependent and can produce different bytes across runtimes.
      Object.keys(record).sort((left, right) => left < right ? -1 : left > right ? 1 : 0).map((key) => [key, canonicalizeValue(record[key])]),
    );
  }
  throw new AppError("SCHEMA_ERROR", "schema_error: unsupported JSON value");
}

export function canonicalizeEvidence(value: unknown, version = CANONICALIZATION_VERSION): Buffer {
  if (version !== CANONICALIZATION_VERSION) throw new AppError("SCHEMA_ERROR", `Unsupported canonicalization version: ${version}`);
  return Buffer.from(JSON.stringify(canonicalizeValue(value)), "utf8");
}

export function sha256Hex(bytes: Uint8Array): string {
  return createHash("sha256").update(bytes).digest("hex");
}
