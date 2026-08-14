import assert from "node:assert/strict";
import test from "node:test";
import {
  ROOT_MFA_CHECK_ID,
  ROOT_MFA_CHECK_VERSION,
  ROOT_MFA_CONTROL_CONTRACT,
  ROOT_MFA_EVALUATOR_VERSION,
  ROOT_MFA_OPERATION,
  ROOT_MFA_PERMISSION,
  evaluateRootMfa,
  rootMfaResourceKey,
} from "../src/root-mfa-control.js";

const observedAt = new Date("2026-08-14T00:00:00.000Z");

test("M-06 Root MFA contract is stable and evaluator is deterministic", () => {
  assert.equal(ROOT_MFA_CONTROL_CONTRACT.checkId, ROOT_MFA_CHECK_ID);
  assert.equal(ROOT_MFA_CONTROL_CONTRACT.checkVersion, ROOT_MFA_CHECK_VERSION);
  assert.equal(ROOT_MFA_CONTROL_CONTRACT.evaluatorVersion, ROOT_MFA_EVALUATOR_VERSION);
  assert.equal(ROOT_MFA_CONTROL_CONTRACT.operation, ROOT_MFA_OPERATION);
  assert.deepEqual(ROOT_MFA_CONTROL_CONTRACT.requiredPermissions, [ROOT_MFA_PERMISSION]);
  assert.equal(rootMfaResourceKey("123456789012"), "aws-account:123456789012:root-mfa");

  const pass = evaluateRootMfa({ accountId: "123456789012", mfaEnabled: true, observedAt });
  const fail = evaluateRootMfa({ accountId: "123456789012", mfaEnabled: false, observedAt });
  assert.equal(pass.status, "PASS");
  assert.equal(pass.dataQuality, "AUTHORITATIVE");
  assert.equal(fail.status, "FAIL");
  assert.equal(fail.dataQuality, "AUTHORITATIVE");
  assert.ok(fail.remediation);
  assert.deepEqual(
    evaluateRootMfa({ accountId: "123456789012", mfaEnabled: true, observedAt }),
    pass,
  );
});

test("M-06 malformed observations fail closed as schema drift", () => {
  const malformed = evaluateRootMfa({
    accountId: "not-an-account",
    mfaEnabled: true,
    observedAt,
  });
  assert.equal(malformed.status, "ERROR");
  assert.equal(malformed.errorCode, "SCHEMA_DRIFT");
  assert.equal(malformed.dataQuality, "INVALID");
  assert.throws(() => rootMfaResourceKey("123"), /12-digit/);
});