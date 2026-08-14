import { AppError } from "./errors.js";

export const TERMINAL_SCAN_STATES = ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "DEAD_LETTER"] as const;
export type ScanState = "QUEUED" | "RUNNING" | "CANCELLING" | (typeof TERMINAL_SCAN_STATES)[number];

const transitions: Record<ScanState, readonly ScanState[]> = {
  QUEUED: ["RUNNING", "CANCELLED", "DEAD_LETTER"],
  RUNNING: ["CANCELLING", "COMPLETED", "PARTIAL", "FAILED", "DEAD_LETTER"],
  CANCELLING: ["CANCELLED"],
  COMPLETED: [],
  PARTIAL: [],
  FAILED: ["QUEUED", "DEAD_LETTER"],
  CANCELLED: [],
  DEAD_LETTER: ["QUEUED"],
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
  const code = typeof error === "object" && error !== null && "code" in error ? String(error.code) : "";
  if (["AWS_ERROR", "DEPENDENCY_ERROR"].includes(code)) return { retryable: true, category: "transient" };
  if (["AUTHORIZATION_ERROR", "FORBIDDEN", "ROLE_INSUFFICIENT", "VALIDATION_ERROR", "CONFLICT"].includes(code)) {
    return { retryable: false, category: code.toLowerCase() };
  }
  return { retryable: true, category: "system" };
}

export function retryDelayMs(attempt: number): number {
  const safeAttempt = Math.min(Math.max(attempt, 1), 3);
  return Math.min(60_000, 1_000 * (2 ** (safeAttempt - 1)));
}

export function durationMs(startedAt: Date, finishedAt: Date): number {
  return Math.max(0, finishedAt.getTime() - startedAt.getTime());
}