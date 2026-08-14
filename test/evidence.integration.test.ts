import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { EvidenceService } from "../src/evidence-service.js";
import { InMemoryEvidenceObjectStorage } from "../src/evidence-storage.js";
import { customerAuthorizationContext } from "../src/authorization.js";
import { disconnectPrisma, getPrismaClient } from "../src/database.js";
import { AppError } from "../src/errors.js";

const databaseConfigured = Boolean(process.env.DATABASE_URL);

test("M-05 PostgreSQL evidence vault, tenant, lifecycle, and integrity gates", { skip: !databaseConfigured }, async (t) => {
  const db = getPrismaClient();
  await db.$connect();
  const suffix = randomUUID().slice(0, 8);
  const organization = await db.organization.create({ data: { name: `M05 ${suffix}`, slug: `m05-${suffix}` } });
  const otherOrganization = await db.organization.create({ data: { name: `M05 Other ${suffix}`, slug: `m05-other-${suffix}` } });
  const user = await db.user.create({ data: { externalIdentityRef: `m05-user-${suffix}` } });
  const otherUser = await db.user.create({ data: { externalIdentityRef: `m05-other-user-${suffix}` } });
  await db.membership.create({ data: { organizationId: organization.id, userId: user.id, role: "OWNER" } });
  await db.membership.create({ data: { organizationId: otherOrganization.id, userId: otherUser.id, role: "OWNER" } });
  const connection = await db.awsConnection.create({
    data: { organizationId: organization.id, name: `m05-connection-${suffix}`, credentialSource: "test", status: "ACTIVE", awsAccountId: "123456789012" },
  });
  const account = await db.awsAccount.create({
    data: { organizationId: organization.id, connectionId: connection.id, awsAccountId: "123456789012", status: "ACTIVE" },
  });
  const scan = await db.securityScanRun.create({
    data: {
      organizationId: organization.id,
      accountId: account.id,
      connectionId: connection.id,
      requestedByUserId: user.id,
      idempotencyKey: `m05-scan-${suffix}`,
      snapshotFingerprint: `m05-fingerprint-${suffix}`,
      correlationId: `m05-correlation-${suffix}`,
      status: "RUNNING",
    },
  });
  const outcome = await db.scanCheckOutcome.create({
    data: {
      organizationId: organization.id,
      scanRunId: scan.id,
      checkId: "M05-CANARY",
      checkVersion: "1",
      resourceIdentity: "resource:m05",
      status: "COMPLETED",
      startedAt: new Date("2026-08-14T00:00:00.000Z"),
      finishedAt: new Date("2026-08-14T00:00:01.000Z"),
      durationMs: 1000,
      correlationId: scan.correlationId,
    },
  });
  const storage = new InMemoryEvidenceObjectStorage();
  const service = new EvidenceService(db, storage);
  const auth = customerAuthorizationContext(user.id, organization.id, "OWNER");
  const otherAuth = customerAuthorizationContext(otherUser.id, otherOrganization.id, "OWNER");
  const collectedAt = new Date("2026-08-14T00:00:00.000Z");
  const retentionUntil = new Date("2030-08-14T00:00:00.000Z");

  t.after(async () => {
    await db.evidenceLegalHold.deleteMany({ where: { organizationId: { in: [organization.id, otherOrganization.id] } } });
    await db.observedFact.deleteMany({ where: { organizationId: { in: [organization.id, otherOrganization.id] } } });
    await db.domainEvent.deleteMany({ where: { organizationId: { in: [organization.id, otherOrganization.id] } } });
    await db.evidence.deleteMany({ where: { organizationId: { in: [organization.id, otherOrganization.id] } } });
    await db.scanCheckOutcome.deleteMany({ where: { organizationId: organization.id } });
    await db.securityScanRun.deleteMany({ where: { organizationId: organization.id } });
    await db.awsAccount.deleteMany({ where: { organizationId: organization.id } });
    await db.awsConnection.deleteMany({ where: { organizationId: organization.id } });
    await db.auditEvent.deleteMany({ where: { organizationId: { in: [organization.id, otherOrganization.id] } } });
    await db.membership.deleteMany({ where: { organizationId: { in: [organization.id, otherOrganization.id] } } });
    await db.user.deleteMany({ where: { id: { in: [user.id, otherUser.id] } } });
    await db.organization.deleteMany({ where: { id: { in: [organization.id, otherOrganization.id] } } });
    await disconnectPrisma();
  });

  await t.test("commit redacts, stores only metadata, links M-03 outcome, and emits proof", async () => {
    const evidence = await service.commit(auth, {
      sourceIntegrationId: connection.id,
      scanRunId: scan.id,
      scanCheckOutcomeId: outcome.id,
      type: "PROVIDER_RESPONSE",
      provider: "aws",
      schemaVersion: "aws.v1",
      providerRequestId: "request-m05",
      sourceEndpoint: "ec2:DescribeInstances",
      collectedAt,
      retentionUntil,
      payload: {
        accountId: "123456789012",
        service: "ec2",
        resourceId: "i-m05",
        headers: { authorization: "Bearer fake-m05-secret" },
        nested: { privateKey: "fake-private-key" },
      },
      observedFacts: [{
        provider: "aws",
        resourceKey: "i-m05",
        observedAt: collectedAt,
        payloadSchema: "aws.v1",
        extractedFields: { service: "ec2", resourceId: "i-m05" },
      }],
      correlationId: scan.correlationId,
    });
    assert.equal(evidence.scanRunId, scan.id);
    assert.equal(evidence.scanCheckOutcomeId, outcome.id);
    assert.equal(evidence.integrityStatus, "VALID");
    const bytes = await storage.get(evidence.storageRef, evidence.storageVersionId ?? undefined);
    assert.ok(bytes);
    assert.doesNotMatch(Buffer.from(bytes).toString("utf8"), /fake-m05-secret|fake-private-key/);
    assert.equal(await db.observedFact.count({ where: { evidenceId: evidence.id } }), 1);
    assert.equal(await db.domainEvent.count({ where: { entityId: evidence.id, eventType: "EvidenceCommitted" } }), 1);
    const audit = await db.auditEvent.findMany({ where: { targetId: evidence.id } });
    assert.equal(audit.some((item) => JSON.stringify(item.metadata).includes("fake-m05-secret")), false);
  });

  await t.test("cross-tenant read and member mutation are denied", async () => {
    const evidence = await db.evidence.findFirstOrThrow({ where: { organizationId: organization.id } });
    await assert.rejects(
      service.getMetadata({ auth: otherAuth, correlationId: "m05-cross-tenant" }, evidence.id),
      (error: unknown) => error instanceof AppError && error.code === "NOT_FOUND",
    );
    const member = await db.user.create({ data: { externalIdentityRef: `m05-member-${suffix}` } });
    await db.membership.create({ data: { organizationId: organization.id, userId: member.id, role: "MEMBER" } });
    const memberAuth = customerAuthorizationContext(member.id, organization.id, "MEMBER");
    await assert.rejects(
      service.verify({ auth: memberAuth, correlationId: "m05-member-verify" }, evidence.id),
      (error: unknown) => error instanceof AppError && error.code === "ROLE_INSUFFICIENT",
    );
    await db.membership.deleteMany({ where: { userId: member.id } });
    await db.user.delete({ where: { id: member.id } });
  });

  await t.test("verification detects corruption and blocks downstream eligibility", async () => {
    const evidence = await db.evidence.findFirstOrThrow({ where: { organizationId: organization.id } });
    storage.corrupt(evidence.storageRef, evidence.storageVersionId ?? "", Buffer.from("corrupted-m05-object"));
    const failed = await service.verify({ auth, correlationId: "m05-integrity-failure" }, evidence.id);
    assert.equal(failed.integrityStatus, "INTEGRITY_FAILED");
    await assert.rejects(service.assertEligible(evidence.id, organization.id), /integrity-failed/);
    assert.equal(await db.domainEvent.count({ where: { entityId: evidence.id, eventType: "EvidenceIntegrityFailed" } }), 1);
    assert.equal(await db.auditEvent.count({ where: { targetId: evidence.id, action: "EvidenceIntegrityFailed" } }), 1);
  });

  await t.test("superseding preserves original and legal hold blocks deletion", async () => {
    const original = await service.commit(auth, {
      type: "SCAN_CHECK",
      provider: "test",
      schemaVersion: "test.v1",
      collectedAt: new Date("2026-08-12T00:00:00.000Z"),
      retentionUntil: new Date("2026-08-13T00:00:00.000Z"),
      payload: { fixture: "supersede-original" },
      correlationId: "m05-supersede-original",
    });
    const replacement = await service.supersede({ auth, correlationId: "m05-supersede" }, original.id, {
      type: "SCAN_CHECK",
      provider: "test",
      schemaVersion: "test.v1",
      collectedAt,
      retentionUntil,
      payload: { fixture: "supersede-replacement" },
      correlationId: "m05-supersede-replacement",
    });
    assert.equal(replacement.supersedesEvidenceId, original.id);
    const hold = await service.createLegalHold({ auth, correlationId: "m05-hold" }, original.id, "preserve correction lineage");
    await assert.rejects(
      service.deleteExpired({ auth, correlationId: "m05-delete-held" }, original.id, new Date("2031-01-01T00:00:00.000Z")),
      (error: unknown) => error instanceof AppError && error.code === "LEGAL_HOLD_CONFLICT",
    );
    await service.releaseLegalHold({ auth, correlationId: "m05-release" }, hold.id);
    await service.deleteExpired({ auth, correlationId: "m05-delete-expired" }, original.id, new Date("2031-01-01T00:00:00.000Z"));
    assert.equal(await db.evidence.findUnique({ where: { id: original.id } }), null);
    assert.equal(await db.evidence.findUnique({ where: { id: replacement.id } }) !== null, true);
  });
});
