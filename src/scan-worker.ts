import type { Prisma, PrismaClient } from "@prisma/client";
import { AuditEventRepository, systemContext } from "./persistence.js";
import { classifyRetry, retryDelayMs, TERMINAL_SCAN_STATES } from "./scan-orchestration.js";

const LEASE_MS = 30_000;
const MAX_RETRIES = 3;
const HEARTBEAT_MS = 10_000;

type Job = Prisma.ScanJobGetPayload<object>;
type Scan = Prisma.SecurityScanRunGetPayload<object>;

export interface ScanJobExecutor {
  execute(job: Job, scan: Scan): Promise<void>;
}

export class ScanWorker {
  constructor(
    private readonly db: PrismaClient,
    private readonly executor: ScanJobExecutor,
    private readonly workerId: string,
  ) {}

  async runOnce(now = new Date()): Promise<boolean> {
    await this.recoverExpiredLeases(now);
    const claimed = await this.claim(now);
    if (!claimed) return false;
    const { job, scan } = claimed;
    const heartbeat = setInterval(() => {
      void this.heartbeat(job.id, scan.id).catch(() => undefined);
    }, HEARTBEAT_MS);
    heartbeat.unref();
    try {
      await this.executor.execute(job, scan);
      await this.db.$transaction(async (tx) => {
        const current = await tx.securityScanRun.findUniqueOrThrow({ where: { id: scan.id } });
        const terminal = TERMINAL_SCAN_STATES.includes(current.status as (typeof TERMINAL_SCAN_STATES)[number]);
        if (!terminal) throw new Error("Scan executor returned without a terminal state.");
        await tx.scanJob.updateMany({
          where: { id: job.id, workerId: this.workerId, status: "RUNNING" },
          data: { status: current.status === "CANCELLED" ? "CANCELLED" : "COMPLETED", leasedAt: null, leaseExpiresAt: null, workerId: null },
        });
        await tx.securityScanRun.updateMany({
          where: { id: scan.id, leaseOwner: this.workerId },
          data: { leaseOwner: null, leaseAcquiredAt: null, leaseExpiresAt: null, activeKey: null },
        });
        if (current.status === "COMPLETED" || current.status === "PARTIAL") {
          await tx.awsConnection.update({ where: { id: scan.connectionId }, data: { scanFailureStreak: 0 } });
        } else if (current.status === "FAILED") {
          const connection = await tx.awsConnection.findUniqueOrThrow({ where: { id: scan.connectionId } });
          const nextStreak = connection.scanFailureStreak + 1;
          await tx.awsConnection.update({
            where: { id: scan.connectionId },
            data: { scanFailureStreak: nextStreak, ...(nextStreak >= 5 ? { status: "ERROR" } : {}) },
          });
          if (nextStreak === 5) {
            await new AuditEventRepository(tx).append(systemContext(), {
              organizationId: scan.organizationId,
              action: "CIRCUIT_BREAKER_OPENED",
              purpose: "stop automatic scans after five consecutive total failures",
              targetType: "aws_connection",
              targetId: scan.connectionId,
              result: "FAILURE",
              reason: "Five consecutive total scan failures.",
              correlationId: scan.correlationId,
              metadata: { failureStreak: nextStreak },
            });
          }
        }
      });
    } catch (error) {
      await this.handleFailure(job, scan, error);
    } finally {
      clearInterval(heartbeat);
    }
    return true;
  }

  private async claim(now: Date): Promise<{ job: Job; scan: Scan } | null> {
    return this.db.$transaction(async (tx) => {
      const candidate = await tx.scanJob.findFirst({
        where: { status: "QUEUED", availableAt: { lte: now } },
        orderBy: [{ availableAt: "asc" }, { createdAt: "asc" }],
        include: { scanRun: true },
      });
      if (!candidate) return null;
      const leaseExpiresAt = new Date(now.getTime() + LEASE_MS);
      const updated = await tx.scanJob.updateMany({
        where: { id: candidate.id, status: "QUEUED", availableAt: { lte: now } },
        data: { status: "RUNNING", attempt: { increment: 1 }, leasedAt: now, leaseExpiresAt, workerId: this.workerId },
      });
      if (updated.count !== 1) return null;
      const scanUpdated = await tx.securityScanRun.updateMany({
        where: { id: candidate.scanRunId, status: "QUEUED" },
        data: { status: "RUNNING", leaseOwner: this.workerId, leaseAcquiredAt: now, leaseExpiresAt, startedAt: now },
      });
      if (scanUpdated.count !== 1) {
        await tx.scanJob.updateMany({
          where: { id: candidate.id, workerId: this.workerId, status: "RUNNING" },
          data: { status: "QUEUED", leasedAt: null, leaseExpiresAt: null, workerId: null },
        });
        return null;
      }
      return { job: { ...candidate, status: "RUNNING", attempt: candidate.attempt + 1, leasedAt: now, leaseExpiresAt, workerId: this.workerId }, scan: candidate.scanRun };
    });
  }

  private async recoverExpiredLeases(now: Date): Promise<void> {
    const expired = await this.db.scanJob.findMany({
      where: { status: "RUNNING", leaseExpiresAt: { lt: now } },
      select: { id: true, scanRunId: true },
      take: 100,
    });
    for (const job of expired) {
      await this.db.$transaction(async (tx) => {
        const changed = await tx.scanJob.updateMany({
          where: { id: job.id, status: "RUNNING", leaseExpiresAt: { lt: now } },
          data: { status: "QUEUED", availableAt: now, leasedAt: null, leaseExpiresAt: null, workerId: null, lastError: "Lease expired; job recovered." },
        });
        if (changed.count === 1) {
          await tx.securityScanRun.updateMany({
            where: { id: job.scanRunId, status: "RUNNING", leaseExpiresAt: { lt: now } },
            data: { status: "QUEUED", leaseOwner: null, leaseAcquiredAt: null, leaseExpiresAt: null, lastError: "Lease expired; job recovered.", retryCount: { increment: 1 } },
          });
          await new AuditEventRepository(tx).append(systemContext(), {
            organizationId: job.organizationId,
            action: "LEASE_RECOVERED",
            purpose: "recover a scan job whose worker lease expired",
            targetType: "scan_job",
            targetId: job.id,
            result: "FAILURE",
            reason: "Worker lease expired before execution completed.",
            correlationId: job.correlationId,
            metadata: { scanRunId: job.scanRunId },
          });
        }
      });
    }
  }

  private async handleFailure(job: Job, scan: Scan, error: unknown): Promise<void> {
    const classification = classifyRetry(error);
    const message = error instanceof Error ? error.message.slice(0, 500) : "Unknown scan execution failure.";
    await this.db.$transaction(async (tx) => {
      const current = await tx.scanJob.findUniqueOrThrow({ where: { id: job.id } });
      const retry = classification.retryable && current.attempt <= MAX_RETRIES;
      if (retry) {
        const next = new Date(Date.now() + retryDelayMs(current.attempt, Math.floor(Math.random() * 251)));
        await tx.scanJob.updateMany({ where: { id: job.id, workerId: this.workerId, status: "RUNNING" }, data: { status: "QUEUED", availableAt: next, leasedAt: null, leaseExpiresAt: null, workerId: null, lastError: message } });
        await tx.securityScanRun.updateMany({ where: { id: scan.id, leaseOwner: this.workerId, status: "RUNNING" }, data: { status: "QUEUED", finishedAt: null, terminalReason: null, leaseOwner: null, leaseAcquiredAt: null, leaseExpiresAt: null, retryCount: { increment: 1 }, lastErrorCategory: classification.category, lastError: message } });
        await new AuditEventRepository(tx).append(systemContext(), {
          organizationId: scan.organizationId,
          action: "RETRY_SCHEDULED",
          purpose: "retry a transient scan execution failure",
          targetType: "security_scan",
          targetId: scan.id,
          result: "FAILURE",
          reason: message,
          correlationId: scan.correlationId,
          metadata: { attempt: current.attempt, nextAttemptAt: next.toISOString(), category: classification.category },
        });
        return;
      }
      const terminalStatus = classification.retryable ? "DEAD_LETTER" as const : "FAILED" as const;
      await tx.scanJob.updateMany({ where: { id: job.id, workerId: this.workerId, status: "RUNNING" }, data: { status: terminalStatus === "DEAD_LETTER" ? "DEAD_LETTER" : "COMPLETED", leasedAt: null, leaseExpiresAt: null, workerId: null, lastError: message } });
      await tx.securityScanRun.updateMany({ where: { id: scan.id, leaseOwner: this.workerId, status: "RUNNING" }, data: { status: terminalStatus, finishedAt: new Date(), leaseOwner: null, leaseAcquiredAt: null, leaseExpiresAt: null, activeKey: null, lastErrorCategory: classification.category, lastError: message, terminalReason: terminalStatus === "DEAD_LETTER" ? "retry_exhausted" : "unrecoverable_execution_failure" } });
      await new AuditEventRepository(tx).append(systemContext(), {
        organizationId: scan.organizationId,
        action: "SCAN_DEAD_LETTERED",
        purpose: "retain an unsafe or exhausted scan job for operator recovery",
        targetType: "security_scan",
        targetId: scan.id,
        result: "FAILURE",
        reason: terminalStatus === "DEAD_LETTER" ? "Scan execution retry policy exhausted." : message,
        correlationId: scan.correlationId,
        metadata: { attempt: current.attempt, category: classification.category, terminalStatus },
      });
      await tx.scanEvent.upsert({
        where: { scanRunId_eventType: { scanRunId: scan.id, eventType: terminalStatus === "DEAD_LETTER" ? "ScanFailed" : "ScanFailed" } },
        create: { organizationId: scan.organizationId, scanRunId: scan.id, eventType: "ScanFailed", correlationId: scan.correlationId, payload: { status: terminalStatus, reason: classification.category } },
        update: {},
      });
    });
  }

  private async heartbeat(jobId: string, scanId: string): Promise<void> {
    const now = new Date();
    const leaseExpiresAt = new Date(now.getTime() + LEASE_MS);
    await this.db.$transaction([
      this.db.scanJob.updateMany({
        where: { id: jobId, workerId: this.workerId, status: "RUNNING" },
        data: { leasedAt: now, leaseExpiresAt },
      }),
      this.db.securityScanRun.updateMany({
        where: { id: scanId, leaseOwner: this.workerId, status: "RUNNING" },
        data: { leaseAcquiredAt: now, leaseExpiresAt },
      }),
    ]);
  }
}