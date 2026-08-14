import { createHash } from "node:crypto";
import { Prisma, type PrismaClient } from "@prisma/client";
import { AppError } from "./errors.js";
import { requirePermission, type Permission } from "./authorization.js";
import { AuditEventRepository, systemContext, type OrganizationContext } from "./persistence.js";
import {
  applicableSecurityRules,
  SECURITY_RULES,
  type SecurityEvaluation,
  type SecurityResourceSnapshot,
  type SecurityRule,
} from "./security-rules.js";
import { calculateProgress } from "./scan-orchestration.js";

type Db = PrismaClient | Prisma.TransactionClient;
type SecurityFindingRecord = Prisma.SecurityFindingGetPayload<object>;
type SecurityScanRunRecord = Prisma.SecurityScanRunGetPayload<object>;

export interface SecurityAuthorization {
  readonly actorUserId: string;
  readonly organizationId: string;
  readonly role: string;
  readonly context: OrganizationContext;
}

export interface FindingFilters {
  readonly severity?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  readonly status?: "OPEN" | "ACKNOWLEDGED" | "RESOLVED";
  readonly ruleId?: string;
  readonly resourceType?: string;
  readonly awsAccountId?: string;
  readonly region?: string;
  readonly page: number;
  readonly pageSize: number;
}

export interface ScanFilters {
  readonly page: number;
  readonly pageSize: number;
  readonly status?: "QUEUED" | "RUNNING" | "CANCELLING" | "COMPLETED" | "PARTIAL" | "FAILED" | "CANCELLED" | "DEAD_LETTER";
  readonly from?: Date;
  readonly to?: Date;
}

function requireSecurityPermission(auth: SecurityAuthorization, permission: Permission): void {
  requirePermission({
    actor: { userId: auth.actorUserId, membership: { organizationId: auth.organizationId, role: auth.role, status: "ACTIVE" } },
    organizationId: auth.organizationId,
    permission,
  });
}

function safeUuid(value: string, field: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new AppError("VALIDATION_ERROR", `${field} must be a valid UUID.`);
  }
  return value;
}

function safeKey(value: string): string {
  const key = value.trim();
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{7,179}$/.test(key)) {
    throw new AppError("VALIDATION_ERROR", "idempotencyKey contains invalid characters or has an unsafe length.");
  }
  return key;
}

function jsonValue(value: unknown): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).sort(([left], [right]) => left.localeCompare(right)).map(([key, nested]) => [key, canonicalize(nested)]));
  }
  return value;
}

function snapshotFingerprint(resources: readonly SecurityResourceSnapshot[], rules: readonly SecurityRule[]): string {
  const content = JSON.stringify(canonicalize({
    rules: rules.map((rule) => ({ ruleId: rule.ruleId, version: rule.version })),
    resources: resources.map((resource) => ({
      id: resource.id,
      accountId: resource.accountId,
      awsAccountId: resource.awsAccountId,
      region: resource.region,
      service: resource.service,
      resourceType: resource.resourceType,
      resourceId: resource.resourceId,
      status: resource.status,
      tags: resource.tags,
      metadata: resource.metadata,
    })),
  }));
  return createHash("sha256").update(content, "utf8").digest("hex");
}

function toResourceSnapshot(resource: {
  id: string;
  accountId: string;
  region: string;
  service: string;
  resourceType: string;
  resourceId: string;
  resourceArn: string | null;
  resourceName: string | null;
  status: string;
  tags: Prisma.JsonValue;
  metadata: Prisma.JsonValue;
  account: { awsAccountId: string };
}): SecurityResourceSnapshot {
  return { ...resource, awsAccountId: resource.account.awsAccountId };
}

export function toPublicScan(run: SecurityScanRunRecord) {
  const durationMs = run.durationMs ?? (run.finishedAt && run.startedAt ? run.finishedAt.getTime() - run.startedAt.getTime() : null);
  const total = run.totalChecks ?? run.totalResources;
  const completed = run.completedChecks || run.evaluatedResources;
  const failed = run.failedChecks || run.failedResources;
  const progress = calculateProgress({
    total: total > 0 ? total : null,
    completed,
    failed,
    skipped: run.skippedChecks,
    terminal: ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "DEAD_LETTER"].includes(run.status),
  });
  return {
    id: run.id,
    organizationId: run.organizationId,
    accountId: run.accountId,
    discoveryRunId: run.discoveryRunId,
    status: run.status,
    triggerType: run.triggerType,
    requestedByUserId: run.requestedByUserId,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    durationMs,
    progress,
    totalResources: run.totalResources,
    evaluatedResources: run.evaluatedResources,
    insufficientEvidence: run.insufficientEvidence,
    failedResources: run.failedResources,
    totalChecks: run.totalChecks,
    completedChecks: run.completedChecks,
    failedChecks: run.failedChecks,
    skippedChecks: run.skippedChecks,
    retryCount: run.retryCount,
    lastErrorCategory: run.lastErrorCategory,
    lastError: run.lastError,
    cancelRequestedAt: run.cancelRequestedAt,
    terminalReason: run.terminalReason,
    rulesEvaluated: run.rulesEvaluated,
    findingsCreated: run.findingsCreated,
    findingsResolved: run.findingsResolved,
    ruleErrors: run.ruleErrors,
    correlationId: run.correlationId,
    createdAt: run.createdAt,
    updatedAt: run.updatedAt,
  };
}

function toPublicFinding(finding: SecurityFindingRecord) {
  return {
    id: finding.id,
    organizationId: finding.organizationId,
    ruleId: finding.ruleId,
    ruleVersion: finding.ruleVersion,
    resourceId: finding.resourceId,
    resourceType: finding.resourceType,
    awsAccountId: finding.awsAccountId,
    region: finding.region,
    severity: finding.severity,
    status: finding.status,
    title: finding.title,
    description: finding.description,
    evidence: finding.evidence,
    recommendation: finding.recommendation,
    firstDetectedAt: finding.firstDetectedAt,
    lastDetectedAt: finding.lastDetectedAt,
    acknowledgedAt: finding.acknowledgedAt,
    resolvedAt: finding.resolvedAt,
    resolutionReason: finding.resolutionReason,
    discoveryRunId: finding.discoveryRunId,
    scanRunId: finding.scanRunId,
    createdAt: finding.createdAt,
    updatedAt: finding.updatedAt,
  };
}

function findingIdentity(finding: { ruleId: string; ruleVersion: string; awsAccountId: string; region: string; resourceId: string }): string {
  return [finding.ruleId, finding.ruleVersion, finding.awsAccountId, finding.region, finding.resourceId].join("|");
}

export class SecurityAnalysisService {
  constructor(
    private readonly db: PrismaClient,
    private readonly rules: readonly SecurityRule[] = SECURITY_RULES,
  ) {}

  async enqueueScan(auth: SecurityAuthorization, accountId: string, correlationId: string, requestedKey: string | undefined, triggerType = "MANUAL") {
    requireSecurityPermission(auth, "scan.create");
    safeUuid(accountId, "accountId");
    const account = await this.db.awsAccount.findFirst({
      where: { id: accountId, organizationId: auth.organizationId },
      include: { connection: true },
    });
    if (!account) throw new AppError("NOT_FOUND", "AWS account not found.");
    if (account.status !== "ACTIVE" || account.connection.status !== "ACTIVE") {
      throw new AppError("CONFLICT", "The AWS integration must be verified and active before a scan can run.");
    }
    const resources = await this.db.awsResource.findMany({
      where: { organizationId: auth.organizationId, accountId },
      select: { resourceId: true, resourceType: true, region: true, status: true },
      orderBy: [{ resourceId: "asc" }, { region: "asc" }],
    });
    const fingerprint = createHash("sha256").update(JSON.stringify(resources), "utf8").digest("hex");
    const key = requestedKey ? safeKey(requestedKey) : `snapshot-${fingerprint}`;
    const canonicalKey = `${auth.organizationId}:${accountId}:${key}`;
    const activeKey = `${auth.organizationId}:${accountId}`;
    const existing = await this.db.securityScanRun.findUnique({ where: { idempotencyKey: canonicalKey } });
    if (existing) {
      if (existing.snapshotFingerprint !== fingerprint) throw new AppError("CONFLICT", "The idempotency key was reused for a different inventory snapshot.");
      return toPublicScan(existing);
    }
    const active = await this.db.securityScanRun.findUnique({ where: { activeKey } });
    if (active) throw new AppError("CONFLICT", "An active scan already exists for this AWS integration.");
    const createdAt = new Date();
    try {
      const scan = await this.db.$transaction(async (tx) => {
        const created = await tx.securityScanRun.create({
          data: {
            organizationId: auth.organizationId,
            accountId,
            connectionId: account.connectionId,
            requestedByUserId: auth.actorUserId,
            status: "QUEUED",
            triggerType,
            idempotencyKey: canonicalKey,
            activeKey,
            snapshotFingerprint: fingerprint,
            correlationId,
            startedAt: null,
          },
        });
        await tx.scanJob.create({
          data: {
            scanRunId: created.id,
            organizationId: auth.organizationId,
            accountId,
            correlationId,
          },
        });
        const audit = new AuditEventRepository(tx);
        await audit.append(auth.context, {
          actorUserId: auth.actorUserId,
          action: "SCAN_REQUESTED",
          purpose: "request a durable tenant-scoped scan",
          targetType: "security_scan",
          targetId: created.id,
          result: "SUCCESS",
          correlationId,
          metadata: { accountId, triggerType },
        });
        await audit.append(auth.context, {
          actorUserId: auth.actorUserId,
          action: "SCAN_QUEUED",
          purpose: "place scan work in the PostgreSQL-backed queue",
          targetType: "security_scan",
          targetId: created.id,
          result: "SUCCESS",
          correlationId,
          metadata: {},
        });
        return created;
      });
      return toPublicScan(scan);
    } catch (error) {
      if (this.persistenceCode(error) === "P2002") {
        const raced = await this.db.securityScanRun.findUnique({ where: { idempotencyKey: canonicalKey } });
        if (raced) return toPublicScan(raced);
        throw new AppError("CONFLICT", "An active scan already exists for this AWS integration.");
      }
      throw error;
    }
  }

  async cancelScan(auth: SecurityAuthorization, scanId: string, correlationId: string) {
    requireSecurityPermission(auth, "scan.cancel");
    safeUuid(scanId, "scanId");
    const current = await this.db.securityScanRun.findFirst({ where: { id: scanId, organizationId: auth.organizationId } });
    if (!current) throw new AppError("NOT_FOUND", "Security scan not found.");
    if (["COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "DEAD_LETTER"].includes(current.status)) return toPublicScan(current);
    const cancelled = await this.db.$transaction(async (tx) => {
      const status = current.status === "QUEUED" ? "CANCELLED" as const : "CANCELLING" as const;
      const updated = await tx.securityScanRun.updateMany({
        where: { id: scanId, organizationId: auth.organizationId, status: current.status },
        data: { status, cancelRequestedAt: new Date(), ...(status === "CANCELLED" ? { finishedAt: new Date(), activeKey: null, terminalReason: "client_requested" } : {}) },
      });
      if (updated.count !== 1) throw new AppError("CONFLICT", "The scan changed before cancellation could be applied.");
      if (status === "CANCELLED") await tx.scanJob.updateMany({ where: { scanRunId: scanId, status: "QUEUED" }, data: { status: "CANCELLED" } });
      await new AuditEventRepository(tx).append(auth.context, {
        actorUserId: auth.actorUserId,
        action: "SCAN_CANCELLED",
        purpose: "request safe cancellation of scan execution",
        targetType: "security_scan",
        targetId: scanId,
        result: "SUCCESS",
        correlationId,
        metadata: { priorStatus: current.status },
      });
      return tx.securityScanRun.findUniqueOrThrow({ where: { id: scanId } });
    });
    return toPublicScan(cancelled);
  }

  async getScanProgress(auth: SecurityAuthorization, scanId: string) {
    requireSecurityPermission(auth, "scan.read");
    return this.getScan(auth, scanId);
  }

  async executeQueuedRun(scanId: string): Promise<void> {
    const scan = await this.db.securityScanRun.findUnique({ where: { id: scanId } });
    if (!scan) throw new AppError("NOT_FOUND", "Queued security scan not found.");
    const auth: SecurityAuthorization = {
      actorUserId: scan.requestedByUserId ?? "",
      organizationId: scan.organizationId,
      role: "OWNER",
      context: systemContext(scan.requestedByUserId ?? undefined),
    };
    await this.runScan(auth, scan.accountId, scan.correlationId, undefined, scan.id);
  }

  async runScan(auth: SecurityAuthorization, accountId: string, correlationId: string, requestedKey?: string, existingRunId?: string) {
    requireSecurityPermission(auth, "findings.run");
    safeUuid(accountId, "accountId");
    const account = await this.db.awsAccount.findFirst({ where: { id: accountId, organizationId: auth.organizationId } });
    if (!account) throw new AppError("NOT_FOUND", "AWS account not found.");

    const allResources = await this.db.awsResource.findMany({
      where: { organizationId: auth.organizationId, accountId },
      include: { account: { select: { awsAccountId: true } } },
      orderBy: [{ status: "asc" }, { resourceId: "asc" }],
    });
    const activeResources = allResources.filter((resource) => resource.status === "ACTIVE").map(toResourceSnapshot);
    const activeRules = this.rules.filter((rule) => rule.enabled !== false);
    const fingerprint = snapshotFingerprint(allResources.map(toResourceSnapshot), activeRules);
    const suppliedKey = requestedKey ? safeKey(requestedKey) : undefined;
    const canonicalKey = `${auth.organizationId}:${accountId}:${suppliedKey ?? `snapshot-${fingerprint}`}`;
    const existing = existingRunId
      ? await this.db.securityScanRun.findFirst({ where: { id: existingRunId, organizationId: auth.organizationId, accountId } })
      : await this.db.securityScanRun.findUnique({ where: { idempotencyKey: canonicalKey } });
    if (existing && !existingRunId) {
      if (existing.snapshotFingerprint !== fingerprint) throw new AppError("CONFLICT", "The idempotency key was reused for a different inventory snapshot.");
      return toPublicScan(existing);
    }

    const latestDiscovery = await this.db.discoveryRun.findFirst({
      where: { organizationId: auth.organizationId, accountId, status: { in: ["COMPLETED", "PARTIAL"] } },
      orderBy: { createdAt: "desc" },
      select: { id: true },
    });
    let scan: SecurityScanRunRecord;
    if (existingRunId) {
      if (!existing) throw new AppError("NOT_FOUND", "Queued security scan not found.");
      scan = existing;
    } else {
      try {
        scan = await this.db.securityScanRun.create({
          data: {
            organizationId: auth.organizationId,
            accountId,
            connectionId: account.connectionId,
            ...(latestDiscovery ? { discoveryRunId: latestDiscovery.id } : {}),
            idempotencyKey: canonicalKey,
            snapshotFingerprint: fingerprint,
            correlationId,
            status: "RUNNING",
            startedAt: new Date(),
          },
        });
      } catch (error) {
        if (this.persistenceCode(error) === "P2002") {
          const raced = await this.db.securityScanRun.findUnique({ where: { idempotencyKey: canonicalKey } });
          if (raced) return toPublicScan(raced);
        }
        throw error;
      }
    }

    try {
      if (existingRunId && scan.status === "QUEUED") {
        const transitioned = await this.db.securityScanRun.updateMany({
          where: { id: scan.id, status: "QUEUED" },
          data: { status: "RUNNING", startedAt: new Date() },
        });
        if (transitioned.count !== 1) {
          const current = await this.db.securityScanRun.findUniqueOrThrow({ where: { id: scan.id } });
          if (["COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "DEAD_LETTER"].includes(current.status)) return toPublicScan(current);
          throw new AppError("CONFLICT", "The queued scan is already being processed.");
        }
      }
      await new AuditEventRepository(this.db).append(auth.context, {
        actorUserId: auth.actorUserId,
        action: "SCAN_STARTED",
        purpose: "run deterministic AWS security analysis",
        targetType: "security_scan",
        targetId: scan.id,
        result: "SUCCESS",
        correlationId,
        metadata: { accountId: account.awsAccountId, ruleCount: activeRules.length, resourceCount: activeResources.length },
      });

      const violations: Array<{ resource: SecurityResourceSnapshot; rule: SecurityRule; evaluation: SecurityEvaluation }> = [];
      const errors: Array<{ resourceId: string; ruleId: string; category: string }> = [];
      const resolvable = new Set<string>();
      let evaluatedResources = 0;
      let insufficientEvidence = 0;
      let failedResources = 0;
      let rulesEvaluated = 0;
      let completedChecks = 0;
      let failedChecks = 0;

      for (const resource of activeResources) {
        const cancellation = await this.db.securityScanRun.findUnique({ where: { id: scan.id }, select: { status: true } });
        if (cancellation?.status === "CANCELLING") break;
        const applicable = applicableSecurityRules(resource, activeRules);
        let resourceEvaluated = false;
        let resourceInsufficient = false;
        let resourceFailed = false;
        for (const rule of applicable) {
          rulesEvaluated += 1;
          const checkStartedAt = new Date();
          try {
            const evaluation = rule.evaluate(resource);
            const checkFinishedAt = new Date();
            if (evaluation.status === "FAIL") {
              violations.push({ resource, rule, evaluation });
              resourceEvaluated = true;
              resourceFailed = true;
              failedChecks += 1;
            } else if (evaluation.status === "PASS" || evaluation.status === "NOT_APPLICABLE") {
              resourceEvaluated = true;
              resolvable.add(findingIdentity({ ruleId: rule.ruleId, ruleVersion: rule.version, awsAccountId: resource.awsAccountId, region: resource.region, resourceId: resource.resourceId }));
              completedChecks += 1;
            } else {
              resourceInsufficient = true;
              completedChecks += 1;
            }
            try {
              await this.db.scanCheckOutcome.create({
                data: {
                  organizationId: auth.organizationId,
                  scanRunId: scan.id,
                  checkId: rule.ruleId,
                  checkVersion: rule.version,
                  resourceIdentity: `${resource.awsAccountId}:${resource.region}:${resource.resourceId}`,
                  status: evaluation.status,
                  startedAt: checkStartedAt,
                  finishedAt: checkFinishedAt,
                  durationMs: Math.max(0, checkFinishedAt.getTime() - checkStartedAt.getTime()),
                  correlationId,
                  attempt: 1,
                },
              });
            } catch (outcomeError) {
              if (this.persistenceCode(outcomeError) !== "P2002") throw outcomeError;
            }
          } catch {
            resourceFailed = true;
            errors.push({ resourceId: resource.resourceId, ruleId: rule.ruleId, category: "RULE_EXECUTION_ERROR" });
            failedChecks += 1;
            try {
              await this.db.scanCheckOutcome.create({
                data: {
                  organizationId: auth.organizationId,
                  scanRunId: scan.id,
                  checkId: rule.ruleId,
                  checkVersion: rule.version,
                  resourceIdentity: `${resource.awsAccountId}:${resource.region}:${resource.resourceId}`,
                  status: "ERROR",
                  startedAt: checkStartedAt,
                  finishedAt: new Date(),
                  durationMs: Math.max(0, Date.now() - checkStartedAt.getTime()),
                  errorClass: "RULE_EXECUTION_ERROR",
                  errorMessage: "Rule execution failed.",
                  correlationId,
                  attempt: 1,
                },
              });
            } catch (outcomeError) {
              if (this.persistenceCode(outcomeError) !== "P2002") throw outcomeError;
            }
          }
        }
        if (resourceEvaluated) evaluatedResources += 1;
        if (resourceInsufficient) insufficientEvidence += 1;
        if (resourceFailed) failedResources += 1;
      }

      const existingFindings = await this.db.securityFinding.findMany({ where: { organizationId: auth.organizationId, accountId } });
      const activeResourceIds = new Set(activeResources.map((resource) => resource.resourceId));
      const result = await this.db.$transaction(async (tx) => {
        let findingsCreated = 0;
        let findingsResolved = 0;
        const audit = new AuditEventRepository(tx);
        for (const violation of violations) {
          const identity = {
            organizationId: auth.organizationId,
            ruleId: violation.rule.ruleId,
            ruleVersion: violation.rule.version,
            awsAccountId: violation.resource.awsAccountId,
            region: violation.resource.region,
            resourceId: violation.resource.resourceId,
          };
          const previous = existingFindings.find((finding) => findingIdentity(finding) === findingIdentity(identity));
          const reopened = previous?.status === "RESOLVED";
          const data = {
            awsResourceId: violation.resource.id,
            accountId: violation.resource.accountId,
            resourceType: violation.resource.resourceType,
            severity: violation.rule.severity,
            title: violation.evaluation.title,
            description: violation.evaluation.description,
            evidence: jsonValue(violation.evaluation.evidence),
            recommendation: violation.evaluation.recommendation,
            status: reopened ? "OPEN" as const : previous?.status ?? "OPEN" as const,
            ...(reopened ? { resolvedAt: null, resolutionReason: null } : {}),
            lastDetectedAt: new Date(),
            ...(latestDiscovery ? { discoveryRunId: latestDiscovery.id } : {}),
            scanRunId: scan.id,
          };
          await tx.securityFinding.upsert({
            where: { organizationId_ruleId_ruleVersion_awsAccountId_region_resourceId: identity },
            create: { ...identity, ...data },
            update: data,
          });
          if (!previous) {
            findingsCreated += 1;
            await audit.append(auth.context, {
              actorUserId: auth.actorUserId,
              action: "FINDING_CREATED",
              purpose: "persist security finding",
              targetType: "security_finding",
              result: "SUCCESS",
              correlationId,
              metadata: { ruleId: violation.rule.ruleId, resourceId: violation.resource.resourceId, severity: violation.rule.severity },
            });
          } else if (reopened) {
            await audit.append(auth.context, {
              actorUserId: auth.actorUserId,
              action: "FINDING_REOPENED",
              purpose: "reopen security finding after a new violation",
              targetType: "security_finding",
              targetId: previous.id,
              result: "SUCCESS",
              correlationId,
              metadata: { ruleId: violation.rule.ruleId, resourceId: violation.resource.resourceId },
            });
          }
        }

        for (const previous of existingFindings) {
          if (previous.status === "RESOLVED") continue;
          const identity = findingIdentity(previous);
          const safeToResolve = resolvable.has(identity) || (!activeResourceIds.has(previous.resourceId) && allResources.some((resource) => resource.resourceId === previous.resourceId && resource.status !== "ACTIVE"));
          if (!safeToResolve) continue;
          await tx.securityFinding.update({
            where: { id: previous.id },
            data: { status: "RESOLVED", resolvedAt: new Date(), resolutionReason: "No violation was present in the analyzed inventory snapshot.", scanRunId: scan.id },
          });
          findingsResolved += 1;
          await audit.append(auth.context, {
            actorUserId: auth.actorUserId,
            action: "FINDING_RESOLVED",
            purpose: "automatically resolve remediated security finding",
            targetType: "security_finding",
            targetId: previous.id,
            result: "SUCCESS",
            correlationId,
            metadata: { ruleId: previous.ruleId, resourceId: previous.resourceId },
          });
        }

        const cancellation = await tx.securityScanRun.findUnique({ where: { id: scan.id }, select: { status: true } });
        const status = cancellation?.status === "CANCELLING"
          ? "CANCELLED" as const
          : errors.length > 0 || insufficientEvidence > 0 || failedResources > 0 ? "PARTIAL" as const : "COMPLETED" as const;
        const finishedAt = new Date();
        const completed = await tx.securityScanRun.update({
          where: { id: scan.id },
          data: {
            status,
            finishedAt,
            durationMs: scan.startedAt ? Math.max(0, finishedAt.getTime() - scan.startedAt.getTime()) : null,
            ...(status === "CANCELLED" ? { terminalReason: "client_requested" } : {}),
            totalResources: allResources.length,
            totalChecks: activeResources.reduce((total, resource) => total + applicableSecurityRules(resource, activeRules).length, 0),
            completedChecks,
            failedChecks,
            evaluatedResources,
            insufficientEvidence,
            failedResources,
            rulesEvaluated,
            findingsCreated,
            findingsResolved,
            ruleErrors: jsonValue(errors),
          },
        });
        await audit.append(auth.context, {
          actorUserId: auth.actorUserId,
          action: status === "PARTIAL" ? "SCAN_PARTIAL" : "SCAN_COMPLETED",
          purpose: "complete deterministic AWS security analysis",
          targetType: "security_scan",
          targetId: scan.id,
          result: "SUCCESS",
          ...(errors.length ? { reason: `${errors.length} rule execution error(s)` } : {}),
          correlationId,
          metadata: { status, findingsCreated, findingsResolved, insufficientEvidence },
        });
        const eventType = status === "COMPLETED"
          ? "ScanCompleted"
          : status === "PARTIAL" ? "ScanPartial" : status === "CANCELLED" ? "ScanCancelled" : "ScanFailed";
        await tx.scanEvent.upsert({
          where: { scanRunId_eventType: { scanRunId: scan.id, eventType } },
          create: {
            organizationId: auth.organizationId,
            scanRunId: scan.id,
            eventType,
            correlationId,
            payload: jsonValue({ status, findingsCreated, findingsResolved, completedChecks, failedChecks }),
          },
          update: {},
        });
        return { completed, findingsCreated, findingsResolved };
      });

      return toPublicScan(result.completed);
    } catch (error) {
      try {
        await this.db.securityScanRun.update({
          where: { id: scan.id },
          data: { status: "FAILED", finishedAt: new Date() },
        });
        await new AuditEventRepository(this.db).append(auth.context, {
          actorUserId: auth.actorUserId,
          action: "SCAN_FAILED",
          purpose: "record failed AWS security analysis",
          targetType: "security_scan",
          targetId: scan.id,
          result: "FAILURE",
          reason: "Security scan persistence or execution failed.",
          correlationId,
        });
      } catch {
        // Preserve the original failure if failure-state persistence also fails.
      }
      throw error;
    }
  }

  async listScans(auth: SecurityAuthorization, accountId: string, filters: ScanFilters = { page: 1, pageSize: 50 }) {
    requireSecurityPermission(auth, "findings.read");
    safeUuid(accountId, "accountId");
    await this.findAccount(auth, accountId);
    const where: Prisma.SecurityScanRunWhereInput = {
      organizationId: auth.organizationId,
      accountId,
      ...(filters.status ? { status: filters.status } : {}),
      ...(filters.from || filters.to ? { createdAt: { ...(filters.from ? { gte: filters.from } : {}), ...(filters.to ? { lte: filters.to } : {}) } } : {}),
    };
    const [runs, total] = await this.db.$transaction([
      this.db.securityScanRun.findMany({
        where,
        orderBy: [{ createdAt: "desc" }, { id: "desc" }],
        skip: (filters.page - 1) * filters.pageSize,
        take: filters.pageSize,
      }),
      this.db.securityScanRun.count({ where }),
    ]);
    return { scans: runs.map(toPublicScan), page: filters.page, pageSize: filters.pageSize, total, hasNextPage: filters.page * filters.pageSize < total };
  }

  async queueBacklog(auth: SecurityAuthorization) {
    requireSecurityPermission(auth, "scan.read");
    const where = { organizationId: auth.organizationId };
    const [queued, running, failed, deadLetter, oldest] = await Promise.all([
      this.db.scanJob.count({ where: { ...where, status: "QUEUED" } }),
      this.db.scanJob.count({ where: { ...where, status: "RUNNING" } }),
      this.db.securityScanRun.count({ where: { ...where, status: "FAILED" } }),
      this.db.scanJob.count({ where: { ...where, status: "DEAD_LETTER" } }),
      this.db.scanJob.findFirst({ where: { ...where, status: "QUEUED" }, orderBy: { createdAt: "asc" }, select: { createdAt: true } }),
    ]);
    return {
      queuedCount: queued,
      runningCount: running,
      failedCount: failed,
      deadLetterCount: deadLetter,
      oldestQueuedAgeMs: oldest ? Math.max(0, Date.now() - oldest.createdAt.getTime()) : null,
    };
  }

  async getScan(auth: SecurityAuthorization, scanId: string) {
    requireSecurityPermission(auth, "findings.read");
    safeUuid(scanId, "scanId");
    const scan = await this.db.securityScanRun.findFirst({ where: { id: scanId, organizationId: auth.organizationId } });
    if (!scan) throw new AppError("NOT_FOUND", "Security scan not found.");
    return toPublicScan(scan);
  }

  async listFindings(auth: SecurityAuthorization, filters: FindingFilters) {
    requireSecurityPermission(auth, "findings.read");
    const where: Prisma.SecurityFindingWhereInput = {
      organizationId: auth.organizationId,
      ...(filters.severity ? { severity: filters.severity } : {}),
      ...(filters.status ? { status: filters.status } : {}),
      ...(filters.ruleId ? { ruleId: filters.ruleId } : {}),
      ...(filters.resourceType ? { resourceType: filters.resourceType } : {}),
      ...(filters.awsAccountId ? { awsAccountId: filters.awsAccountId } : {}),
      ...(filters.region ? { region: filters.region } : {}),
    };
    const [findings, total] = await this.db.$transaction([
      this.db.securityFinding.findMany({
        where,
        orderBy: [{ severity: "asc" }, { lastDetectedAt: "desc" }, { id: "asc" }],
        skip: (filters.page - 1) * filters.pageSize,
        take: filters.pageSize,
      }),
      this.db.securityFinding.count({ where }),
    ]);
    return { findings: findings.map(toPublicFinding), page: filters.page, pageSize: filters.pageSize, total, hasNextPage: filters.page * filters.pageSize < total };
  }

  async getFinding(auth: SecurityAuthorization, findingId: string) {
    requireSecurityPermission(auth, "findings.read");
    safeUuid(findingId, "findingId");
    const finding = await this.db.securityFinding.findFirst({
      where: { id: findingId, organizationId: auth.organizationId },
      include: { resource: true, account: true, discoveryRun: true, scanRun: true },
    });
    if (!finding) throw new AppError("NOT_FOUND", "Security finding not found.");
    const rule = this.rules.find((candidate) => candidate.ruleId === finding.ruleId && candidate.version === finding.ruleVersion);
    return {
      ...toPublicFinding(finding),
      rule: rule ? { ruleId: rule.ruleId, version: rule.version, name: rule.name, description: rule.description, severity: rule.severity, resourceTypes: rule.resourceTypes } : null,
      resource: { id: finding.resource.id, resourceId: finding.resource.resourceId, resourceType: finding.resource.resourceType, service: finding.resource.service, name: finding.resource.resourceName, arn: finding.resource.resourceArn, region: finding.resource.region, status: finding.resource.status },
      account: { id: finding.account.id, awsAccountId: finding.account.awsAccountId },
      provenance: { discoveryRunId: finding.discoveryRunId, scanRunId: finding.scanRunId, discoveryStatus: finding.discoveryRun?.status ?? null },
    };
  }

  async acknowledgeFinding(auth: SecurityAuthorization, findingId: string, correlationId: string) {
    requireSecurityPermission(auth, "findings.acknowledge");
    const finding = await this.findFinding(auth, findingId);
    if (finding.status === "RESOLVED") throw new AppError("CONFLICT", "A resolved finding cannot be acknowledged.");
    const updated = await this.db.$transaction(async (tx) => {
      const result = await tx.securityFinding.updateMany({
        where: { id: finding.id, organizationId: auth.organizationId, status: { in: ["OPEN", "ACKNOWLEDGED"] } },
        data: { status: "ACKNOWLEDGED", acknowledgedAt: finding.acknowledgedAt ?? new Date() },
      });
      if (result.count !== 1) throw new AppError("CONFLICT", "The finding changed before it could be acknowledged.");
      await new AuditEventRepository(tx).append(auth.context, {
        actorUserId: auth.actorUserId,
        action: "FINDING_ACKNOWLEDGED",
        purpose: "acknowledge security finding",
        targetType: "security_finding",
        targetId: finding.id,
        result: "SUCCESS",
        correlationId,
        metadata: { ruleId: finding.ruleId, resourceId: finding.resourceId },
      });
      return tx.securityFinding.findUniqueOrThrow({ where: { id: finding.id } });
    });
    return toPublicFinding(updated);
  }

  async resolveFinding(auth: SecurityAuthorization, findingId: string, reason: string, correlationId: string) {
    requireSecurityPermission(auth, "findings.resolve");
    const normalizedReason = reason.trim();
    if (!normalizedReason || normalizedReason.length > 500) throw new AppError("VALIDATION_ERROR", "A resolution reason between 1 and 500 characters is required.");
    const finding = await this.findFinding(auth, findingId);
    if (finding.status === "RESOLVED") return toPublicFinding(finding);
    const updated = await this.db.$transaction(async (tx) => {
      const result = await tx.securityFinding.update({
        where: { id: finding.id },
        data: { status: "RESOLVED", resolvedAt: new Date(), resolutionReason: normalizedReason },
      });
      await new AuditEventRepository(tx).append(auth.context, {
        actorUserId: auth.actorUserId,
        action: "FINDING_RESOLVED",
        purpose: "manually resolve security finding",
        targetType: "security_finding",
        targetId: finding.id,
        result: "SUCCESS",
        correlationId,
        metadata: { ruleId: finding.ruleId, resourceId: finding.resourceId },
      });
      return result;
    });
    return toPublicFinding(updated);
  }

  private async findFinding(auth: SecurityAuthorization, findingId: string): Promise<SecurityFindingRecord> {
    safeUuid(findingId, "findingId");
    const finding = await this.db.securityFinding.findFirst({ where: { id: findingId, organizationId: auth.organizationId } });
    if (!finding) throw new AppError("NOT_FOUND", "Security finding not found.");
    return finding;
  }

  private async findAccount(auth: SecurityAuthorization, accountId: string) {
    const account = await this.db.awsAccount.findFirst({ where: { id: accountId, organizationId: auth.organizationId } });
    if (!account) throw new AppError("NOT_FOUND", "AWS account not found.");
    return account;
  }

  private persistenceCode(error: unknown): string | undefined {
    return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : undefined;
  }
}

export function customerSecurityAuthorization(input: { actorUserId: string; organizationId: string; role: string; context: OrganizationContext }): SecurityAuthorization {
  return input;
}