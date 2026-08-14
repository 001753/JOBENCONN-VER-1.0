import test from "node:test";
import assert from "node:assert/strict";
import { AppError } from "../src/errors.js";
import { calculateProgress, classifyRetry, retryDelayMs, transitionScanState } from "../src/scan-orchestration.js";

test("M-03 state machine rejects unsafe transitions", () => {
  transitionScanState("QUEUED", "RUNNING");
  transitionScanState("RUNNING", "CANCELLING");
  transitionScanState("CANCELLING", "CANCELLED");
  assert.throws(() => transitionScanState("COMPLETED", "RUNNING"), (error: unknown) => error instanceof AppError && error.code === "CONFLICT");
});

test("M-03 progress is server-derived and never reaches 100 before terminal", () => {
  assert.deepEqual(calculateProgress({ total: 10, completed: 9, failed: 0, skipped: 0, terminal: false }), {
    total: 10, completed: 9, failed: 0, skipped: 0, percentage: 90,
  });
  assert.equal(calculateProgress({ total: 10, completed: 10, failed: 0, skipped: 0, terminal: false }).percentage, 99);
  assert.equal(calculateProgress({ total: 10, completed: 10, failed: 0, skipped: 0, terminal: true }).percentage, 100);
});

test("M-03 retry policy is bounded and does not retry authorization failures", () => {
  assert.equal(classifyRetry({ code: "AWS_ERROR" }).retryable, true);
  assert.equal(classifyRetry({ code: "FORBIDDEN" }).retryable, false);
  assert.equal(retryDelayMs(1), 1_000);
  assert.equal(retryDelayMs(3), 4_000);
  assert.equal(retryDelayMs(99), 60_000);
});