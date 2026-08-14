import assert from "node:assert/strict";
import test from "node:test";
import { applicableSecurityRules, SECURITY_RULES, type SecurityResourceSnapshot } from "../src/security-rules.js";

function resource(input: Partial<SecurityResourceSnapshot> = {}): SecurityResourceSnapshot {
  return {
    id: "11111111-1111-4111-8111-111111111111",
    accountId: "22222222-2222-4222-8222-222222222222",
    awsAccountId: "123456789012",
    region: "us-east-1",
    service: "IAM",
    resourceType: "account-summary",
    resourceId: "123456789012",
    resourceArn: "arn:aws:iam::123456789012:root",
    resourceName: null,
    status: "ACTIVE",
    tags: {},
    metadata: { summaryMap: { AccountMFAEnabled: 0, AccountAccessKeysPresent: 1 } },
    ...input,
  };
}

test("security rule registry is trusted, versioned, and deterministic", () => {
  assert.ok(SECURITY_RULES.length >= 4);
  for (const rule of SECURITY_RULES) {
    assert.match(rule.ruleId, /^AWS-SEC-\d{3}$/);
    assert.equal(rule.version, "1");
    assert.ok(rule.resourceTypes.length > 0);
    const [service, resourceType] = rule.resourceTypes[0]!.split(":");
    assert.ok(service);
    assert.ok(resourceType);
    const input = resource({ service, resourceType });
    assert.deepEqual(rule.evaluate(input), rule.evaluate(input));
  }
});

test("IAM rules produce fail, pass, and insufficient evidence without inventing evidence", () => {
  const mfa = SECURITY_RULES.find((rule) => rule.ruleId === "AWS-SEC-002")!;
  const keys = SECURITY_RULES.find((rule) => rule.ruleId === "AWS-SEC-003")!;
  assert.equal(mfa.evaluate(resource()).status, "FAIL");
  assert.equal(keys.evaluate(resource()).status, "FAIL");
  assert.equal(
    mfa.evaluate(resource({ metadata: { summaryMap: { AccountMFAEnabled: 1 } } })).status,
    "PASS",
  );
  assert.equal(
    mfa.evaluate(resource({ metadata: { summaryMap: {} } })).status,
    "INSUFFICIENT_EVIDENCE",
  );
});

test("rules only apply to their declared inventory resource types", () => {
  const secure = resource({
    service: "EC2",
    resourceType: "instance",
    resourceId: "i-123",
    metadata: { publicIpAddress: false },
  });
  const rules = applicableSecurityRules(secure);
  assert.deepEqual(rules.map((rule) => rule.ruleId), ["AWS-SEC-004"]);
  assert.equal(rules[0]!.evaluate(secure).status, "PASS");
  assert.equal(applicableSecurityRules(resource({ service: "VPC", resourceType: "unknown" })).length, 0);
});

test("S3 encryption rule distinguishes explicit failure from missing evidence", () => {
  const rule = SECURITY_RULES.find((candidate) => candidate.ruleId === "AWS-SEC-001")!;
  const base = resource({ service: "S3", resourceType: "bucket", resourceId: "bucket-a", metadata: {} });
  assert.equal(rule.evaluate(base).status, "INSUFFICIENT_EVIDENCE");
  assert.equal(rule.evaluate({ ...base, metadata: { encrypted: false } }).status, "FAIL");
  assert.equal(rule.evaluate({ ...base, metadata: { encrypted: true } }).status, "PASS");
  assert.equal(rule.severity, "HIGH");
});