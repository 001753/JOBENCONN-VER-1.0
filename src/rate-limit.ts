import { AppError } from "./errors.js";

interface Bucket {
  startedAt: number;
  count: number;
}

/**
 * Small deterministic process-local hook. It is intentionally not described
 * as distributed protection; a shared adapter can implement the same contract
 * when authentication traffic is horizontally scaled.
 */
export class FixedWindowRateLimiter {
  private readonly buckets = new Map<string, Bucket>();

  constructor(
    private readonly limit: number,
    private readonly windowMs: number,
  ) {}

  consume(key: string, now = Date.now()): void {
    const current = this.buckets.get(key);
    if (!current || now - current.startedAt >= this.windowMs) {
      this.buckets.set(key, { startedAt: now, count: 1 });
      return;
    }
    current.count += 1;
    if (current.count > this.limit) throw new AppError("AUTHENTICATION_ERROR", "Too many authentication attempts.");
  }

  clear(): void {
    this.buckets.clear();
  }
}