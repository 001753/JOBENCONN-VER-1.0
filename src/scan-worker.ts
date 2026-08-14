import type { Prisma, PrismaClient } from "@prisma/client";
import { AuditEventRepository, systemContext } from "./persistence.js";
import { classifyRetry, retryDelayMs, TERMINAL_SCAN_STATES } from "./scan-orchestration.js";

const LEASE_MS = 30_000;
const MAX_ATTEMPTS = 3;

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
      await tx.securityScanRun.updateMany({
        where: { id: candidate.scanRunId, status: "QUEUED" },
        data: { status: "RUNNING", leaseOwner: this.workerId, leaseAcquiredAt: now, leaseExpiresAt, startedAt: now },
      });
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
        }
      });
    }
  }

  private async handleFailure(job: Job, scan: Scan, error: unknown): Promise<void> {
    const classification = classifyRetry(error);
    const message = error instanceof Error ? error.message.slice(0, 500) : "Unknown scan execution failure.";
    await this.db.$transaction(async (tx) => {
      const current = await tx.scanJob.findUniqueOrThrow({ where: { id: job.id } });
      const retry = classification.retryable && current.attempt < MAX_ATTEMPTS;
      if (retry) {
        const next = new Date(Date.now() + retryDelayMs(current.attempt));
        await tx.scanJob.update({ where: { id: job.id }, data: { status: "QUEUED", availableAt: next, leasedAt: null, leaseExpiresAt: null, workerId: null, lastError: message } });
        await tx.securityScanRun.update({ where: { id: scan.id }, data: { status: "QUEUED", finishedAt: null, terminalReason: null, leaseOwner: null, leaseAcquiredAt: null, leaseExpiresAt: null, retryCount: { increment: 1 }, lastErrorCategory: classification.category, lastError: message } });
        return;
      }
      await tx.scanJob.update({ where: { id: job.id }, data: { status: "DEAD_LETTER", leasedAt: null, leaseExpiresAt: null, workerId: null, lastError: message } });
      await tx.securityScanRun.update({ where: { id: scan.id }, data: { status: "DEAD_LETTER", finishedAt: new Date(), leaseOwner: null, leaseAcquiredAt: null, leaseExpiresAt: null, activeKey: null, lastErrorCategory: classification.category, lastError: message, terminalReason: "retry_exhausted" } });
      await new AuditEventRepository(tx).append(systemContext(), {
        organizationId: scan.organizationId,
        action: "SCAN_DEAD_LETTERED",
        purpose: "retain an unsafe or exhausted scan job for operator recovery",
        targetType: "security_scan",
        targetId: scan.id,
        result: "FAILURE",
        reason: "Scan execution retry policy exhausted.",
        correlationId: scan.correlationId,
        metadata: { attempt: current.attempt, category: classification.category },
      });
    });
  }
}