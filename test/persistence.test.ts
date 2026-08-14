import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { getPrismaClient, disconnectPrisma } from "../src/database.js";
import { AppError } from "../src/errors.js";
import {
  AuditEventRepository,
  CapabilityRepository,
  customerContext,
  IdempotencyRepository,
  InvitationRepository,
  MembershipRepository,
  OrganizationRepository,
  systemContext,
  UserRepository,
  withTransaction,
} from "../src/persistence.js";

const databaseConfigured = Boolean(process.env.DATABASE_URL);

test("Prompt 02 persistence foundation passes database integration gates", { skip: !databaseConfigured }, async (t) => {
  const db = getPrismaClient();
  await db.$connect();
  const suffix = randomUUID().slice(0, 8);
  const userRepo = new UserRepository(db);
  const organizationRepo = new OrganizationRepository(db);
  const membershipRepo = new MembershipRepository(db);
  const invitationRepo = new InvitationRepository(db);
  const auditRepo = new AuditEventRepository(db);
  const capabilityRepo = new CapabilityRepository(db);
  const idempotencyRepo = new IdempotencyRepository(db);
  const orgA = await organizationRepo.create(systemContext(), { name: `Test A ${suffix}`, slug: `test-a-${suffix}` });
  const orgB = await organizationRepo.create(systemContext(), { name: `Test B ${suffix}`, slug: `test-b-${suffix}` });
  const userA = await userRepo.create({ externalIdentityRef: `test-a-${suffix}` });
  const userB = await userRepo.create({ externalIdentityRef: `test-b-${suffix}` });
  const contextA = customerContext(orgA.id, userA.id);
  const contextB = customerContext(orgB.id, userB.id);

  t.after(async () => {
    await db.idempotencyRecord.deleteMany({ where: { scopeKey: `organization:${orgA.id}` } });
    await db.capabilityRecord.deleteMany({ where: { organizationId: orgA.id } });
    await db.auditEvent.deleteMany({ where: { organizationId: { in: [orgA.id, orgB.id] } } });
    await db.invitation.deleteMany({ where: { organizationId: { in: [orgA.id, orgB.id] } } });
    await db.membership.deleteMany({ where: { organizationId: { in: [orgA.id, orgB.id] } } });
    await db.user.deleteMany({ where: { id: { in: [userA.id, userB.id] } } });
    await db.organization.deleteMany({ where: { id: { in: [orgA.id, orgB.id] } } });
    await disconnectPrisma();
  });

  await t.test("user, organization, membership, and foreign keys", async () => {
    const membershipA = await membershipRepo.create(contextA, { organizationId: orgA.id, userId: userA.id, role: "OWNER" });
    assert.equal(membershipA.version, 1);
    await assert.rejects(
      membershipRepo.create(contextA, { organizationId: orgA.id, userId: userA.id, role: "OWNER" }),
      (error: unknown) => error instanceof AppError && error.code === "CONFLICT",
    );
    await assert.rejects(
      membershipRepo.create(contextA, { organizationId: orgA.id, userId: randomUUID(), role: "MEMBER" }),
      (error: unknown) => error instanceof AppError && error.code === "VALIDATION_ERROR",
    );
  });

  await t.test("customer scope prevents cross-organization reads", async () => {
    await membershipRepo.create(contextB, { organizationId: orgB.id, userId: userB.id, role: "OWNER" });
    const membershipsA = await membershipRepo.list(contextA);
    assert.equal(membershipsA.length, 1);
    assert.equal(membershipsA[0]?.organizationId, orgA.id);
    assert.equal(await organizationRepo.getById(contextA, orgB.id), null);
    assert.throws(() => customerContext(""), (error: unknown) => error instanceof AppError && error.code === "AUTHORIZATION_ERROR");
  });

  await t.test("invitation lifecycle and optimistic concurrency", async () => {
    const invitation = await invitationRepo.create(contextA, {
      organizationId: orgA.id,
      invitedEmail: `invite-${suffix}@example.test`,
      role: "MEMBER",
      tokenDigest: `digest-${suffix}`,
      expiresAt: new Date(Date.now() + 60_000),
    });
    const accepted = await invitationRepo.updateStatus(contextA, invitation.id, "ACCEPTED", invitation.version);
    assert.equal(accepted.status, "ACCEPTED");
    await assert.rejects(
      invitationRepo.updateStatus(contextA, invitation.id, "REVOKED", invitation.version),
      (error: unknown) => error instanceof AppError && error.code === "CONFLICT",
    );
  });

  await t.test("audit is append-oriented and metadata is redacted by contract", async () => {
    const event = await auditRepo.append(contextA, {
      action: "test.created",
      purpose: "persistence verification",
      result: "SUCCESS",
      correlationId: `corr-${suffix}`,
      metadata: { reference: `test:${suffix}` },
    });
    assert.equal(event.organizationId, orgA.id);
    assert.match(event.createdAt.toISOString(), /Z$/);
    const timezoneRows = await db.$queryRaw<Array<{ timezone: string }>>`SELECT current_setting('TIMEZONE') AS timezone`;
    assert.ok(timezoneRows[0]?.timezone === "UTC" || timezoneRows[0]?.timezone === "GMT");
    await assert.rejects(
      auditRepo.append(contextA, {
        action: "test.invalid",
        purpose: "security verification",
        result: "SUCCESS",
        correlationId: `corr-invalid-${suffix}`,
        metadata: { access_token: "must-not-persist" },
      }),
      (error: unknown) => error instanceof AppError && error.code === "VALIDATION_ERROR",
    );
  });

  await t.test("capability and idempotency records persist without fake live promotion", async () => {
    const capability = await capabilityRepo.upsert(contextA, {
      organizationId: orgA.id,
      capabilityId: `TEST_CAPABILITY_${suffix}`,
      module: "test",
      version: "1",
      state: "VERIFICATION_REQUIRED",
      sourceOfTruth: "integration-test",
      verificationStatus: "not_verified",
    });
    assert.equal(capability.state, "VERIFICATION_REQUIRED");
    const claimed = await idempotencyRepo.claim(contextA, {
      key: `mutation-${suffix}`,
      operationName: "test.mutation",
      requestFingerprint: "fingerprint-a",
      expiresAt: new Date(Date.now() + 60_000),
    });
    const replay = await idempotencyRepo.claim(contextA, {
      key: `mutation-${suffix}`,
      operationName: "test.mutation",
      requestFingerprint: "fingerprint-a",
      expiresAt: new Date(Date.now() + 60_000),
    });
    assert.equal(replay.id, claimed.id);
    await assert.rejects(
      idempotencyRepo.claim(contextA, {
        key: `mutation-${suffix}`,
        operationName: "test.mutation",
        requestFingerprint: "fingerprint-b",
        expiresAt: new Date(Date.now() + 60_000),
      }),
      (error: unknown) => error instanceof AppError && error.code === "CONFLICT",
    );
    const completed = await idempotencyRepo.complete(contextA, claimed.key, `result:${suffix}`, claimed.version);
    assert.equal(completed.status, "COMPLETED");
  });

  await t.test("required mutation and audit share a rollback boundary", async () => {
    const rollbackUserRef = `rollback-${suffix}`;
    await assert.rejects(
      withTransaction(db, async (transaction) => {
        const txUserRepo = new UserRepository(transaction);
        const txAuditRepo = new AuditEventRepository(transaction);
        await txUserRepo.create({ externalIdentityRef: rollbackUserRef });
        await txAuditRepo.append(systemContext(), {
          organizationId: randomUUID(),
          action: "test.rollback",
          purpose: "transaction verification",
          result: "SUCCESS",
          correlationId: `corr-rollback-${suffix}`,
          metadata: { reference: "invalid organization" },
        });
      }),
      (error: unknown) => error instanceof AppError && error.code === "VALIDATION_ERROR",
    );
    assert.equal(await db.user.count({ where: { externalIdentityRef: rollbackUserRef } }), 0);
  });
});