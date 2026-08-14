import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { disconnectPrisma, getPrismaClient } from "../src/database.js";
import { AppError } from "../src/errors.js";
import { customerContext } from "../src/persistence.js";
import { ScanWorker } from "../src/scan-worker.js";
import { SecurityAnalysisService, customerSecurityAuthorization } from "../src/security-service.js";

const databaseConfigured = Boolean(process.env.DATABASE_URL);

test("M-03 PostgreSQL orchestration gates", { skip: !databaseConfigured }, async (t) => {
  const db = getPrismaClient();
  await db.$connect();
  const suffix = randomUUID().slice(0, 8);
  const organization = await db.organization.create({ data: { name: `M03 ${suffix}`, slug: `m03-${suffix}` } });
  const user = await db.user.create({ data: { externalIdentityRef: `m03-user-${suffix}` } });
  await db.membership.create({ data: { organizationId: organization.id, userId: user.id, role: "OWNER" } });
  const connection = await db.awsConnection.create({
    data: { organizationId: organization.id, name: `m03-connection-${suffix}`, credentialSource: "test", status: "ACTIVE", awsAccountId: "123456789012" },
  });
  const account = await db.awsAccount.create({
    data: { organizationId: organization.id, connectionId: connection.id, awsAccountId: "123456789012", status: "ACTIVE" },
  });
  const auth = customerSecurityAuthorization({
    actorUserId: user.id,
    organizationId: organization.id,
    role: "OWNER",
    context: customerContext(organization.id, user.id),
  });
  const service = new SecurityAnalysisService(db);

  async function createQueuedRun(key: string) {
    const scan = await db.securityScanRun.create({
      data: {
        organizationId: organization.id,
        accountId: account.id,
        connectionId: connection.id,
        requestedByUserId: user.id,
        idempotencyKey: `${organization.id}:${account.id}:${key}`,
        snapshotFingerprint: key,
        correlationId: `m03-correlation-${key}`,
        status: "QUEUED",
      },
    });
    await db.scanJob.create({
      data: {
        scanRunId: scan.id,
        organizationId: organization.id,
        accountId: account.id,
        correlationId: scan.correlationId,
      },
    });
    return scan;
  }

  t.after(async () => {
    await db.scanCheckOutcome.deleteMany({ where: { organizationId: organization.id } });
    await db.scanEvent.deleteMany({ where: { organizationId: organization.id } });
    await db.scanJob.deleteMany({ where: { organizationId: organization.id } });
    await db.securityFinding.deleteMany({ where: { organizationId: organization.id } });
    await db.scanSchedule.deleteMany({ where: { organizationId: organization.id } });
    await db.securityScanRun.deleteMany({ where: { organizationId: organization.id } });
    await db.awsResource.deleteMany({ where: { organizationId: organization.id } });
    await db.awsAccount.deleteMany({ where: { organizationId: organization.id } });
    await db.awsConnection.deleteMany({ where: { organizationId: organization.id } });
    await db.auditEvent.deleteMany({ where: { organizationId: organization.id } });
    await db.membership.deleteMany({ where: { organizationId: organization.id } });
    await db.user.delete({ where: { id: user.id } });
    await db.organization.delete({ where: { id: organization.id } });
    await disconnectPrisma();
  });

  await t.test("retry classification, bounded attempts, and dead letter", async () => {
    const scan = await createQueuedRun(`retry-${suffix}`);
    const failures: unknown[] = [
      { statusCode: 429 },
      { statusCode: 500 },
      { statusCode: 503 },
      Object.assign(new Error("provider timeout"), { code: "TIMEOUT" }),
    ];
    const worker = new ScanWorker(db, {
      execute: async () => {
        throw failures.shift();
      },
    }, `m03-retry-worker-${suffix}`);

    for (let attempt = 0; attempt < 4; attempt += 1) {
      assert.equal(await worker.runOnce(new Date(Date.now() + 1_000)), true);
      const job = await db.scanJob.findUniqueOrThrow({ where: { scanRunId: scan.id } });
      if (job.status === "QUEUED") {
        await db.scanJob.update({ where: { id: job.id }, data: { availableAt: new Date(0) } });
      }
    }

    const result = await db.securityScanRun.findUniqueOrThrow({ where: { id: scan.id } });
    const job = await db.scanJob.findUniqueOrThrow({ where: { scanRunId: scan.id } });
    assert.equal(result.status, "DEAD_LETTER");
    assert.equal(job.status, "DEAD_LETTER");
    assert.equal(job.attempt, 4);
    assert.equal(result.retryCount, 3);
    assert.equal(await db.securityScanRun.count({ where: { id: scan.id } }), 1);
    assert.equal(await db.auditEvent.count({ where: { organizationId: organization.id, action: "RETRY_SCHEDULED", targetId: scan.id } }), 3);
    assert.equal(await db.scanEvent.count({ where: { scanRunId: scan.id, eventType: "ScanDeadLettered" } }), 1);
    assert.equal((await service.replayDeadLetter(auth, scan.id, `m03-replay-${suffix}`)).status, "QUEUED");
    assert.equal(await db.scanEvent.count({ where: { scanRunId: scan.id, eventType: "ScanDeadLettered" } }), 1);
    assert.equal(await db.auditEvent.count({ where: { organizationId: organization.id, action: "SCAN_DEAD_LETTER_REPLAYED", targetId: scan.id } }), 1);
    await db.scanJob.updateMany({ where: { scanRunId: scan.id, status: "QUEUED" }, data: { status: "CANCELLED" } });
    await db.securityScanRun.update({ where: { id: scan.id }, data: { status: "CANCELLED", activeKey: null, finishedAt: new Date(), terminalReason: "test_fixture_cleanup" } });
  });

  await t.test("authorization failures do not retry", async () => {
    for (const [label, error] of [["401", { statusCode: 401 }], ["403", { statusCode: 403 }]] as const) {
      const scan = await createQueuedRun(`auth-${label}-${suffix}`);
      const worker = new ScanWorker(db, { execute: async () => { throw error; } }, `m03-auth-${label}-${suffix}`);
      await worker.runOnce(new Date(Date.now() + 1_000));
      const result = await db.securityScanRun.findUniqueOrThrow({ where: { id: scan.id } });
      const job = await db.scanJob.findUniqueOrThrow({ where: { scanRunId: scan.id } });
      assert.equal(result.status, "FAILED");
      assert.equal(result.retryCount, 0);
      assert.equal(job.status, "COMPLETED");
      assert.equal(job.attempt, 1);
    }
  });

  await t.test("two workers have one atomic claim and expired leases recover", async () => {
    const scan = await createQueuedRun(`claim-${suffix}`);
    let executions = 0;
    const executor = async (_job: unknown, claimedScan: { id: string }) => {
      executions += 1;
      await db.securityScanRun.update({ where: { id: claimedScan.id }, data: { status: "COMPLETED", finishedAt: new Date() } });
    };
    const [first, second] = await Promise.all([
      new ScanWorker(db, { execute: executor }, `m03-claim-a-${suffix}`).runOnce(),
      new ScanWorker(db, { execute: executor }, `m03-claim-b-${suffix}`).runOnce(),
    ]);
    assert.deepEqual([first, second].sort(), [false, true]);
    assert.equal(executions, 1);
    assert.equal((await db.securityScanRun.findUniqueOrThrow({ where: { id: scan.id } })).status, "COMPLETED");

    const recoveredScan = await createQueuedRun(`recovery-${suffix}`);
    const recoveredJob = await db.scanJob.findUniqueOrThrow({ where: { scanRunId: recoveredScan.id } });
    const expired = new Date(Date.now() - 1_000);
    await db.scanJob.update({ where: { id: recoveredJob.id }, data: { status: "RUNNING", workerId: "dead-worker", leasedAt: expired, leaseExpiresAt: expired } });
    await db.securityScanRun.update({ where: { id: recoveredScan.id }, data: { status: "RUNNING", leaseOwner: "dead-worker", leaseAcquiredAt: expired, leaseExpiresAt: expired } });
    const recoveryWorker = new ScanWorker(db, {
      execute: async (_job, claimedScan) => {
        await db.securityScanRun.update({ where: { id: claimedScan.id }, data: { status: "COMPLETED", finishedAt: new Date() } });
      },
    }, `m03-recovery-${suffix}`);
    assert.equal(await recoveryWorker.runOnce(new Date()), true);
    assert.equal((await db.securityScanRun.findUniqueOrThrow({ where: { id: recoveredScan.id } })).status, "COMPLETED");
    assert.equal((await db.securityScanRun.findUniqueOrThrow({ where: { id: recoveredScan.id } })).retryCount, 1);
    assert.equal(await db.auditEvent.count({ where: { organizationId: organization.id, action: "LEASE_RECOVERED", targetId: recoveredJob.id } }), 1);
  });

  await t.test("circuit breaker opens at the configured failure threshold", async () => {
    await db.awsConnection.update({ where: { id: connection.id }, data: { scanFailureStreak: 4, status: "ACTIVE" } });
    const scan = await createQueuedRun(`circuit-${suffix}`);
    const worker = new ScanWorker(db, { execute: async () => { throw { statusCode: 400 }; } }, `m03-circuit-${suffix}`);
    await worker.runOnce(new Date(Date.now() + 1_000));
    const opened = await db.awsConnection.findUniqueOrThrow({ where: { id: connection.id } });
    assert.equal(opened.status, "ERROR");
    assert.equal(opened.scanFailureStreak, 5);
    assert.equal(await db.auditEvent.count({ where: { organizationId: organization.id, action: "CIRCUIT_BREAKER_OPENED", targetId: connection.id } }), 1);
    assert.equal((await db.securityScanRun.findUniqueOrThrow({ where: { id: scan.id } })).status, "FAILED");
    await db.awsConnection.update({ where: { id: connection.id }, data: { scanFailureStreak: 0, status: "ACTIVE" } });
  });

  await t.test("queued and running cancellation have one terminal state", async () => {
    const queued = await service.enqueueScan(auth, account.id, `m03-cancel-queued-${suffix}`, `cancel-queued-${suffix}`);
    const cancelled = await service.cancelScan(auth, queued.id, `m03-cancel-queued-${suffix}`);
    assert.equal(cancelled.status, "CANCELLED");
    assert.equal(await db.scanJob.count({ where: { scanRunId: queued.id, status: "CANCELLED" } }), 1);

    const running = await service.enqueueScan(auth, account.id, `m03-cancel-running-${suffix}`, `cancel-running-${suffix}`);
    let started!: () => void;
    const startedPromise = new Promise<void>((resolve) => { started = resolve; });
    let release!: () => void;
    const releasePromise = new Promise<void>((resolve) => { release = resolve; });
    const worker = new ScanWorker(db, {
      execute: async () => {
        started();
        await releasePromise;
      },
    }, `m03-cancel-worker-${suffix}`);
    const workerPromise = worker.runOnce();
    await startedPromise;
    assert.equal((await service.cancelScan(auth, running.id, `m03-cancel-running-${suffix}`)).status, "CANCELLING");
    release();
    await workerPromise;
    const final = await service.getScan(auth, running.id);
    assert.equal(final.status, "CANCELLED");
    assert.equal(await db.auditEvent.count({ where: { organizationId: organization.id, action: "SCAN_COMPLETED", targetId: running.id } }), 0);
    assert.ok((await db.auditEvent.count({ where: { organizationId: organization.id, action: "SCAN_CANCELLED", targetId: running.id } })) >= 1);
  });

  await t.test("cursor pagination starts from the first page without duplicates", async () => {
    for (let index = 0; index < 3; index += 1) {
      await db.securityScanRun.create({
        data: {
          organizationId: organization.id,
          accountId: account.id,
          connectionId: connection.id,
          requestedByUserId: user.id,
          idempotencyKey: `${organization.id}:${account.id}:page-${suffix}-${index}`,
          snapshotFingerprint: `page-${index}`,
          correlationId: `page-correlation-${suffix}-${index}`,
          status: "COMPLETED",
          startedAt: new Date(Date.now() - (index + 1) * 1_000),
          finishedAt: new Date(Date.now() - (index + 1) * 1_000),
          createdAt: new Date(Date.now() - (index + 1) * 1_000),
        },
      });
    }
    const first = await service.listScans(auth, account.id, { pageSize: 2 });
    assert.equal(first.scans.length, 2);
    assert.ok(first.nextCursor);
    const second = await service.listScans(auth, account.id, { pageSize: 2, cursor: first.nextCursor! });
    assert.ok(second.scans.length > 0);
    const firstIds = new Set(first.scans.map((scan) => scan.id));
    assert.equal(second.scans.some((scan) => firstIds.has(scan.id)), false);
  });

  await t.test("schedule persists, triggers a queued scan, and paused schedules do nothing", async () => {
    const schedule = await service.createSchedule(auth, {
      accountId: account.id,
      name: `schedule-${suffix}`,
      frequency: "DAILY",
      localTime: "03:00",
      timezone: "Asia/Jakarta",
    }, `m03-schedule-${suffix}`);
    await db.scanSchedule.update({ where: { id: schedule.id }, data: { nextRunAt: new Date(Date.now() - 1_000) } });
    assert.equal(await service.processDueSchedules(new Date()), 1);
    const triggered = await db.securityScanRun.findUniqueOrThrow({ where: { id: (await db.scanSchedule.findUniqueOrThrow({ where: { id: schedule.id } })).lastRunId! } });
    assert.equal(triggered.triggerType, "SCHEDULE");
    assert.equal(triggered.status, "QUEUED");

    await service.pauseSchedule(auth, schedule.id, true, `m03-schedule-pause-${suffix}`);
    await db.scanSchedule.update({ where: { id: schedule.id }, data: { nextRunAt: new Date(Date.now() - 1_000) } });
    assert.equal(await service.processDueSchedules(new Date()), 0);
  });

  await t.test("MEMBER cannot create, cancel, or replay scans", async () => {
    const memberAuth = customerSecurityAuthorization({
      actorUserId: user.id,
      organizationId: organization.id,
      role: "MEMBER",
      context: customerContext(organization.id, user.id),
    });
    await assert.rejects(service.enqueueScan(memberAuth, account.id, `m03-member-create-${suffix}`, `member-create-${suffix}`), (error: unknown) => error instanceof AppError && error.code === "ROLE_INSUFFICIENT");
    await assert.rejects(service.cancelScan(memberAuth, randomUUID(), `m03-member-cancel-${suffix}`), (error: unknown) => error instanceof AppError && error.code === "ROLE_INSUFFICIENT");
    await assert.rejects(service.replayDeadLetter(memberAuth, randomUUID(), `m03-member-replay-${suffix}`), (error: unknown) => error instanceof AppError && error.code === "ROLE_INSUFFICIENT");
  });
});