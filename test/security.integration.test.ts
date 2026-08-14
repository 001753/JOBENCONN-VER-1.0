import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { getPrismaClient, disconnectPrisma } from "../src/database.js";
import { IdentityService } from "../src/identity-service.js";
import { type ExternalIdentity } from "../src/identity-provider.js";
import { SessionManager } from "../src/session.js";
import { customerContext } from "../src/persistence.js";
import { AppError } from "../src/errors.js";
import { SecurityAnalysisService, customerSecurityAuthorization } from "../src/security-service.js";

const databaseConfigured = Boolean(process.env.DATABASE_URL);

test("Prompt 05 scan persistence, deduplication, lifecycle, tenant isolation, and RBAC", { skip: !databaseConfigured }, async () => {
  const db = getPrismaClient();
  await db.$connect();
  const suffix = randomUUID().slice(0, 8);
  const identityA: ExternalIdentity = { provider: "test", subject: `security-a-${suffix}`, verified: true, email: `security-a-${suffix}@example.test` };
  const identityB: ExternalIdentity = { provider: "test", subject: `security-b-${suffix}`, verified: true, email: `security-b-${suffix}@example.test` };
  const sessions = new SessionManager(db, 3_600, false);
  const identity = new IdentityService(db, sessions);
  const loginA = await identity.login(identityA, `security-login-a-${suffix}`);
  const loginB = await identity.login(identityB, `security-login-b-${suffix}`);
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
  const service = new SecurityAnalysisService(db);
  const connection = await db.awsConnection.create({
    data: { organizationId: loginA.organizationId, name: `security-${suffix}`, credentialSource: "default-chain", status: "ACTIVE", awsAccountId: "123456789012" },
  });
  const account = await db.awsAccount.create({
    data: { organizationId: loginA.organizationId, connectionId: connection.id, awsAccountId: "123456789012", status: "ACTIVE" },
  });
  const iamResource = await db.awsResource.create({
    data: {
      organizationId: loginA.organizationId,
      accountId: account.id,
      connectionId: connection.id,
      region: "global",
      service: "IAM",
      resourceType: "account-summary",
      resourceId: `summary-${suffix}`,
      resourceArn: "arn:aws:iam::123456789012:root",
      status: "ACTIVE",
      metadata: { summaryMap: { AccountMFAEnabled: 0, AccountAccessKeysPresent: 1 } },
    },
  });
  const incompleteResource = await db.awsResource.create({
    data: {
      organizationId: loginA.organizationId,
      accountId: account.id,
      connectionId: connection.id,
      region: "us-east-1",
      service: "S3",
      resourceType: "bucket",
      resourceId: `bucket-${suffix}`,
      status: "ACTIVE",
      metadata: {},
    },
  });

  try {
    const first = await service.runScan(authA, account.id, `security-scan-1-${suffix}`, `security-key-${suffix}`);
    assert.equal(first.status, "PARTIAL");
    assert.equal(first.totalResources, 2);
    assert.equal(first.insufficientEvidence, 1);
    assert.equal(first.findingsCreated, 2);
    assert.equal(await db.securityFinding.count({ where: { organizationId: loginA.organizationId } }), 2);

    const replay = await service.runScan(authA, account.id, `security-scan-replay-${suffix}`, `security-key-${suffix}`);
    assert.equal(replay.id, first.id);
    assert.equal(await db.securityFinding.count({ where: { organizationId: loginA.organizationId } }), 2);

    const page = await service.listFindings(authA, { page: 1, pageSize: 1 });
    assert.equal(page.total, 2);
    assert.equal(page.findings.length, 1);
    assert.equal(page.findings[0]!.severity, "CRITICAL");

    const tenantBPage = await service.listFindings(authB, { page: 1, pageSize: 10 });
    assert.equal(tenantBPage.total, 0);
    const memberAuth = customerSecurityAuthorization({
      actorUserId: loginA.actor.userId,
      organizationId: loginA.organizationId,
      role: "MEMBER",
      context: customerContext(loginA.organizationId, loginA.actor.userId),
    });
    await assert.rejects(
      service.runScan(memberAuth, account.id, `security-member-${suffix}`),
      (error: unknown) => error instanceof AppError && error.code === "ROLE_INSUFFICIENT",
    );

    await db.awsResource.update({ where: { id: iamResource.id }, data: { metadata: { summaryMap: { AccountMFAEnabled: 1, AccountAccessKeysPresent: 0 } } } });
    const resolved = await service.runScan(authA, account.id, `security-scan-fixed-${suffix}`, `security-fixed-${suffix}`);
    assert.equal(resolved.findingsResolved, 2);
    assert.equal(await db.securityFinding.count({ where: { organizationId: loginA.organizationId, status: "RESOLVED" } }), 2);

    await db.awsResource.update({ where: { id: iamResource.id }, data: { metadata: { summaryMap: { AccountMFAEnabled: 0, AccountAccessKeysPresent: 1 } } } });
    const reopened = await service.runScan(authA, account.id, `security-scan-reopen-${suffix}`, `security-reopen-${suffix}`);
    assert.equal(reopened.findingsCreated, 0);
    assert.equal(await db.securityFinding.count({ where: { organizationId: loginA.organizationId, status: "OPEN" } }), 2);

    const finding = (await db.securityFinding.findFirst({ where: { organizationId: loginA.organizationId, ruleId: "AWS-SEC-003" } }))!;
    const acknowledged = await service.acknowledgeFinding(authA, finding.id, `security-ack-${suffix}`);
    assert.equal(acknowledged.status, "ACKNOWLEDGED");
    const stillOpen = await service.runScan(authA, account.id, `security-scan-ack-${suffix}`, `security-ack-scan-${suffix}`);
    assert.equal(stillOpen.findingsResolved, 0);
    assert.equal((await db.securityFinding.findUnique({ where: { id: finding.id } }))?.status, "ACKNOWLEDGED");
    const audits = await db.auditEvent.count({ where: { organizationId: loginA.organizationId, action: { in: ["SCAN_STARTED", "SCAN_COMPLETED", "FINDING_CREATED", "FINDING_REOPENED", "FINDING_ACKNOWLEDGED"] } } });
    assert.ok(audits >= 7);
    assert.equal(JSON.stringify(await service.getFinding(authA, finding.id)).includes("secret"), false);
  } finally {
    await db.securityFinding.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.securityScanRun.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.awsResource.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.awsAccount.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.awsConnection.deleteMany({ where: { organizationId: loginA.organizationId } });
    await db.auditEvent.deleteMany({ where: { organizationId: { in: [loginA.organizationId, loginB.organizationId] } } });
    await db.session.deleteMany({ where: { userId: { in: [loginA.actor.userId, loginB.actor.userId] } } });
    await db.membership.deleteMany({ where: { userId: { in: [loginA.actor.userId, loginB.actor.userId] } } });
    await db.organization.deleteMany({ where: { id: { in: [loginA.organizationId, loginB.organizationId] } } });
    await db.user.deleteMany({ where: { id: { in: [loginA.actor.userId, loginB.actor.userId] } } });
    await disconnectPrisma();
  }
});