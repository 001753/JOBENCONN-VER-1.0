import { AppError } from "./errors.js";

export const REDACTION_MARKER = "[REDACTED]";

const sensitiveKeyPattern =
  /^(authorization|proxy-authorization|x-api-key|api[-_]?key|access[-_]?key|secret|secret[-_]?key|token|bearer|password|passphrase|private[-_]?key|credential|credentials|webhook[-_]?secret|session[-_]?secret|database[-_]?url|connection[-_]?string)$/i;
const sensitiveValuePatterns = [
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bASIA[0-9A-Z]{16}\b/g,
  /\bBearer\s+[A-Za-z0-9._~+/=-]+/gi,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g,
];

function redactString(value: string): string {
  return sensitiveValuePatterns.reduce((current, pattern) => current.replace(pattern, REDACTION_MARKER), value);
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Provider payloads are copied into a new tree. The input is never mutated.
 * Key based redaction is deliberately exact enough to keep ordinary fields
 * such as resource names and descriptions intact.
 */
export function redactEvidencePayload(value: unknown): unknown {
  if (typeof value === "string") return redactString(value);
  if (Array.isArray(value)) return value.map(redactEvidencePayload);
  if (isPlainObject(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [
        key,
        sensitiveKeyPattern.test(key) ? REDACTION_MARKER : redactEvidencePayload(nested),
      ]),
    );
  }
  if (typeof value === "number" && !Number.isFinite(value)) {
    throw new AppError("SCHEMA_ERROR", "schema_error");
  }
  return value;
}

export function assertNoSensitiveEvidencePayload(value: unknown, path = "payload"): void {
  if (typeof value === "string") {
    if (sensitiveValuePatterns.some((pattern) => {
      pattern.lastIndex = 0;
      return pattern.test(value);
    })) {
      throw new AppError("SCHEMA_ERROR", `schema_error: secret material remains at ${path}`);
    }
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((nested, index) => assertNoSensitiveEvidencePayload(nested, `${path}[${index}]`));
    return;
  }
  if (isPlainObject(value)) {
    for (const [key, nested] of Object.entries(value)) {
      if (sensitiveKeyPattern.test(key) && nested !== REDACTION_MARKER) {
        throw new AppError("SCHEMA_ERROR", `schema_error: secret material remains at ${path}.${key}`);
      }
      assertNoSensitiveEvidencePayload(nested, `${path}.${key}`);
    }
  }
}
