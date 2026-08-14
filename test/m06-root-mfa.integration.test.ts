import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { getPrismaClient, disconnectPrisma } from "../src/database.js";
import { type ExternalIdentity } from "../src/identity-provider.js";
import { IdentityService } from "../src/identity-service.js";
import { customerContext } from "../src/persistence.js";
import { SessionManager } from "../src/session.js";
import { type AwsReadOnlyDiscoveryClient, type AwsRootMfaObservation } from "../src/aws.js";
import { type AwsReadOnlyDiscoveryClientFactory } from "../src/aws-service.js";
import { AppError } from "../src/errors.js";
import { SecurityAnalysisService, customerSecurityAuthorization } from "../src/security-service.js";

const databaseConfigured = Boolean(process.env.DATABASE_URL);

test("M-06 Root MFA vertical slice persists evidence, result, provenance, audit, and tenant boundaries", { skip: !databaseConfigured }, async (t) => {
  const db = getPrismaClient();
  await db.$connect();
  const suffix = randomUUID().slice(0, 8);
  const identityA: ExternalIdentity = { provider: "test", subject: `m06-a-${suffix}`, verified: true, email: `m06-a-${suffix}@example.test` };
  const identityB: ExternalIdentity = { provider: "test", subject: `m06-b-${suffix}`, verified: true, email: `m06-b-${suffix}@example.test` };
  const sessions = new SessionManager(db, 3_600, false);
  const identity = new IdentityService(db, sessions);
  const loginA = await identity.login(identityA, `m06-login-a-${suffix}`);
  const loginB = await identity.login(identityB, `m06-login-b-${suffix}`);
  const authA = customerSecurityAuthorization({
    actorUserId: loginA.actor.userId,
    organizationId: loginA.organizationId,
    role: "OWNER",
    context: customerContext(loginA.organizationId, loginA.actor.userId),
  });
  const authB = customerSecurityAuthorization({
    actorUserId: loginB.actor.userId,
    organizationId: loginB.organizationId,
    role: "OWNER",
    context: customerContext(loginB.organizationId, loginB.actor.userId),
  });
  let mfaEnabled = true;
  const client: AwsReadOnlyDiscoveryClient = {
    async getCallerIdentity() {
      return { accountId: "123456789012", arn: "arn:aws:iam::123456789012:role/M06Test", userId: "AROAM06TEST" };
    },
    async getRootMfaObservation(accountId): Promise<AwsRootMfaObservation> {
      return { accountId, mfaEnabled, observedAt: new Date("2026-08-14T00:00:00.000Z"), requestId: `request-${suffix}` };
    },
    async listRegions() { return []; },
    async listEc2Resources() { return []; },
    async listS3Resources() { return []; },
    async listIamResources() { return []; },
  };
  const factory: AwsReadOnlyDiscoveryClientFactory = { create: () => client };
  const service = new SecurityAnalysisService(db, undefined, factory);
  const connection = await db.awsConnection.create({
    data: { organizationId: loginA.organizationId, name: `m06-${suffix}`, credentialSource: "default-chain", status: "ACTIVE", awsAccountId: "123456789012" },
  });
  const account = await db.awsAccount.create({
    data: { organizationId: loginA.organizationId, connectionId: connection.id, awsAccountId: "123456789012", status: "ACTIVE" },
  });

  t.after(async () => {
    const organizationIds = [loginA.organizationId, loginB.organizationId];
    await db.domainEvent.deleteMany({ where: { organizationId: { in: organizationIds } } });
    await db.auditEvent.deleteMany({ where: { organizationId: { in: organizationIds } } });
    await db.observedFact.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.controlResult.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.evidence.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.scanCheckOutcome.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.securityScanRun.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.awsAccount.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.awsConnection.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.session.deleteMany({ where: { userId: { in: [loginA.actor.userId, loginB.actor.userId] } } });
    await db.membership.deleteMany({ where: { userId: { in: [loginA.actor.userId, loginB.actor.userId] } } });
    await db.organization.deleteMany({ where: { id: { in: organizationIds } } });
    await db.user.deleteMany({ where: { id: { in: [loginA.actor.userId, loginB.actor.userId] } } });
    await disconnectPrisma();
  });

  const first = await service.runScan(authA, account.id, `m06-scan-pass-${suffix}`, `m06-pass-${suffix}`);
  assert.equal(first.status, "COMPLETED");
  const passResult = await db.controlResult.findFirstOrThrow({ where: { scanRunId: first.id } });
  assert.equal(passResult.status, "PASS");
  assert.equal(passResult.checkId, "AWS-IAM-ROOT-MFA");
  assert.equal(passResult.evidenceId !== null, true);
  assert.equal(passResult.evidenceHash?.length, 64);
  assert.equal((passResult.provenance as { evidenceId?: string }).evidenceId, passResult.evidenceId);
  assert.equal((await db.evidence.findUniqueOrThrow({ where: { id: passResult.evidenceId! } })).integrityStatus, "VALID");

  mfaEnabled = false;
  const second = await service.runScan(authA, account.id, `m06-scan-fail-${suffix}`, `m06-fail-${suffix}`);
  assert.equal(second.status, "COMPLETED");
  const failResult = await db.controlResult.findFirstOrThrow({ where: { scanRunId: second.id } });
  assert.equal(failResult.status, "FAIL");
  assert.ok(failResult.remediation);
  assert.equal(await db.auditEvent.count({
    where: { organizationId: loginA.organizationId, action: { in: ["CONTROL_EXECUTION_STARTED", "CONTROL_PROVIDER_REQUEST_COMPLETED", "CONTROL_EVALUATED"] } },
  }), 6);

  await assert.rejects(
    service.getControlResult(authB, passResult.id),
    (error: unknown) => error instanceof AppError && error.code === "NOT_FOUND",
  );
  const memberAuth = customerSecurityAuthorization({
    actorUserId: loginA.actor.userId,
    organizationId: loginA.organizationId,
    role: "MEMBER",
    context: customerContext(loginA.organizationId, loginA.actor.userId),
  });
  assert.equal((await service.listControlResults(memberAuth)).length, 2);
});