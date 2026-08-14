import { AppError } from "./errors.js";

export const TERMINAL_SCAN_STATES = ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "DEAD_LETTER"] as const;
export type ScanState = "QUEUED" | "RUNNING" | "CANCELLING" | (typeof TERMINAL_SCAN_STATES)[number];

const transitions: Record<ScanState, readonly ScanState[]> = {
  QUEUED: ["RUNNING", "CANCELLED", "DEAD_LETTER"],
  RUNNING: ["CANCELLING", "COMPLETED", "PARTIAL", "FAILED", "DEAD_LETTER"],
  CANCELLING: ["CANCELLED"],
  COMPLETED: [],
  PARTIAL: [],
  FAILED: [],
  CANCELLED: [],
  DEAD_LETTER: [],
};

export function transitionScanState(from: ScanState, to: ScanState): void {
  if (!transitions[from].includes(to)) {
    throw new AppError("CONFLICT", `Invalid scan state transition: ${from} -> ${to}.`);
  }
}

export function calculateProgress(input: { total: number | null; completed: number; failed: number; skipped: number; terminal: boolean }) {
  const processed = input.completed + input.failed + input.skipped;
  return {
    total: input.total,
    completed: input.completed,
    failed: input.failed,
    skipped: input.skipped,
    percentage: input.total && input.total > 0
      ? input.terminal ? 100 : Math.min(99, Math.floor((processed / input.total) * 100))
      : null,
  };
}

export function classifyRetry(error: unknown): { retryable: boolean; category: string } {
  const value = error as { code?: unknown; statusCode?: unknown; name?: unknown; message?: unknown } | null;
  const code = value && typeof value.code === "string" ? value.code.toUpperCase() : "";
  const status = value && typeof value.statusCode === "number" ? value.statusCode : undefined;
  const name = value && typeof value.name === "string" ? value.name.toLowerCase() : "";
  const message = value && typeof value.message === "string" ? value.message.toLowerCase() : "";
  if (status === 401 || status === 403 || ["AUTHORIZATION_ERROR", "FORBIDDEN", "ROLE_INSUFFICIENT"].includes(code)) {
    return { retryable: false, category: status === 401 ? "unauthorized" : "forbidden" };
  }
  if ((status !== undefined && [429, 500, 503].includes(status)) || ["TIMEOUT", "TIMEOUT_ERROR", "ETIMEDOUT", "ECONNRESET", "AWS_ERROR", "DEPENDENCY_ERROR"].includes(code) || name.includes("timeout") || message.includes("timeout")) {
    return { retryable: true, category: status ? `http_${status}` : "transient" };
  }
  if (["VALIDATION_ERROR", "CONFLICT"].includes(code)) return { retryable: false, category: code.toLowerCase() };
  return { retryable: false, category: code ? code.toLowerCase() : "unrecoverable" };
}

export function retryDelayMs(attempt: number, jitterMs = 0): number {
  const safeAttempt = Math.min(Math.max(Math.floor(attempt), 1), 30);
  const boundedJitter = Math.min(Math.max(Math.floor(jitterMs), 0), 250);
  return Math.min(60_000, 1_000 * (2 ** (safeAttempt - 1)) + boundedJitter);
}

export function durationMs(startedAt: Date, finishedAt: Date): number {
  return Math.max(0, finishedAt.getTime() - startedAt.getTime());
}