import assert from "node:assert/strict";
import test from "node:test";
import { canonicalizeEvidence, sha256Hex } from "../src/evidence-canonical.js";
import { redactEvidencePayload, REDACTION_MARKER, assertNoSensitiveEvidencePayload } from "../src/evidence-redaction.js";
import { validateProviderEvidence } from "../src/evidence-schema.js";
import { InMemoryEvidenceObjectStorage } from "../src/evidence-storage.js";
import { AppError } from "../src/errors.js";

test("M-05 secret canary is recursively redacted before persistence", () => {
  const canary = {
    headers: { authorization: "Bearer fake-canary", "x-api-key": "fake-api-key" },
    token: "fake-token",
    privateKey: "-----BEGIN PRIVATE KEY-----fake-canary-----END PRIVATE KEY-----",
    nested: [{ webhookSecret: "fake-webhook-secret", credential: "fake-credential" }],
    description: "legitimate provider description remains",
  };
  const redacted = redactEvidencePayload(canary);
  assertNoSensitiveEvidencePayload(redacted);
  const serialized = JSON.stringify(redacted);
  assert.doesNotMatch(serialized, /fake-canary|fake-api-key|fake-token|fake-webhook-secret|fake-credential/);
  assert.match(serialized, /\[REDACTED\]/);
  assert.equal((redacted as { description: string }).description, "legitimate provider description remains");
  assert.equal((redacted as { headers: { authorization: string } }).headers.authorization, REDACTION_MARKER);
});

test("M-05 canonicalization is stable across object key order and preserves arrays", () => {
  const left = { z: 1, nested: { b: "é", a: null }, list: [3, 2, 1], whitespace: " a  b " };
  const right = { whitespace: " a  b ", list: [3, 2, 1], nested: { a: null, b: "é" }, z: 1 };
  const leftBytes = canonicalizeEvidence(left);
  const rightBytes = canonicalizeEvidence(right);
  assert.deepEqual(leftBytes, rightBytes);
  assert.equal(sha256Hex(leftBytes), sha256Hex(rightBytes));
  assert.notEqual(sha256Hex(leftBytes), sha256Hex(canonicalizeEvidence({ ...left, list: [1, 2, 3] })));
});

test("M-05 provider schema failure is deterministic and not silently accepted", () => {
  assert.throws(
    () => validateProviderEvidence("aws", "aws.v1", { credentials: "invalid" }),
    (error: unknown) => error instanceof AppError && error.code === "SCHEMA_ERROR" && error.message.startsWith("schema_error"),
  );
  assert.throws(() => validateProviderEvidence("unknown", "unknown.v1", { anything: true }), /schema_error/);
  assert.doesNotThrow(() => validateProviderEvidence("aws", "aws.v1", { service: "ec2", resourceId: "i-123" }));
});

test("M-05 test storage is versioned, content-addressed, and rejects overwrite", async () => {
  const storage = new InMemoryEvidenceObjectStorage();
  const retentionUntil = new Date("2030-01-01T00:00:00.000Z");
  const first = await storage.put({ key: "org/scan_check/hash", bytes: Buffer.from("canonical"), contentHash: "hash", retentionUntil });
  const same = await storage.put({ key: "org/scan_check/hash", bytes: Buffer.from("canonical"), contentHash: "hash", retentionUntil });
  assert.equal(same.versionId, first.versionId);
  await assert.rejects(
    storage.put({ key: "org/scan_check/hash", bytes: Buffer.from("different"), contentHash: "hash", retentionUntil }),
    (error: unknown) => error instanceof AppError && error.code === "CONFLICT",
  );
  assert.equal(storage.capabilities.versioning, true);
  assert.equal(storage.capabilities.objectLockCompatible, true);
  assert.equal(storage.capabilities.liveVerified, false);
});

test("M-05 integrity drill detects deliberate object corruption", async () => {
  const storage = new InMemoryEvidenceObjectStorage();
  const bytes = Buffer.from('{"fixture":"integrity-drill"}');
  const contentHash = sha256Hex(bytes);
  const stored = await storage.put({
    key: "org/provider_response/integrity-drill",
    bytes,
    contentHash,
    retentionUntil: new Date("2030-01-01T00:00:00.000Z"),
  });
  const original = await storage.get(stored.key, stored.versionId);
  assert.ok(original);
  assert.equal(sha256Hex(original), contentHash);
  storage.corrupt(stored.key, stored.versionId, Buffer.from("corrupted"));
  const corrupted = await storage.get(stored.key, stored.versionId);
  assert.ok(corrupted);
  assert.notEqual(sha256Hex(corrupted), contentHash);
});
