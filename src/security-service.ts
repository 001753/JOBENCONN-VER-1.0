import { createHash } from "node:crypto";
import { Prisma, type PrismaClient } from "@prisma/client";
import { AppError } from "./errors.js";
import { requirePermission, type Permission } from "./authorization.js";
import { AuditEventRepository, type OrganizationContext } from "./persistence.js";
import {
  applicableSecurityRules,
  SECURITY_RULES,
  type SecurityEvaluation,
  type SecurityResourceSnapshot,
  type SecurityRule,
} from "./security-rules.js";

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

function toPublicScan(run: SecurityScanRunRecord) {
  return {
    id: run.id,
    organizationId: run.organizationId,
    accountId: run.accountId,
    discoveryRunId: run.discoveryRunId,
    status: run.status,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    totalResources: run.totalResources,
    evaluatedResources: run.evaluatedResources,
    insufficientEvidence: run.insufficientEvidence,
    failedResources: run.failedResources,
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

  async runScan(auth: SecurityAuthorization, accountId: string, correlationId: string, requestedKey?: string) {
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
    const existing = await this.db.securityScanRun.findUnique({ where: { idempotencyKey: canonicalKey } });
    if (existing) {
      if (existing.snapshotFingerprint !== fingerprint) throw new AppError("CONFLICT", "The idempotency key was reused for a different inventory snapshot.");
      return toPublicScan(existing);
    }

    const latestDiscovery = await this.db.discoveryRun.findFirst({
      where: { organizationId: auth.organizationId, accountId, status: { in: ["COMPLETED", "PARTIAL"] } },
      orderBy: { createdAt: "desc" },
      select: { id: true },
    });
    let scan: SecurityScanRunRecord;
    try {
      scan = await this.db.securityScanRun.create({
        data: {
          organizationId: auth.organizationId,
          accountId,
          ...(latestDiscovery ? { discoveryRunId: latestDiscovery.id } : {}),
          idempotencyKey: canonicalKey,
          snapshotFingerprint: fingerprint,
          correlationId,
        },
      });
    } catch (error) {
      if (this.persistenceCode(error) === "P2002") {
        const raced = await this.db.securityScanRun.findUnique({ where: { idempotencyKey: canonicalKey } });
        if (raced) return toPublicScan(raced);
      }
      throw error;
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

    for (const resource of activeResources) {
      const applicable = applicableSecurityRules(resource, activeRules);
      let resourceEvaluated = false;
      let resourceInsufficient = false;
      let resourceFailed = false;
      for (const rule of applicable) {
        rulesEvaluated += 1;
        try {
          const evaluation = rule.evaluate(resource);
          if (evaluation.status === "FAIL") {
            violations.push({ resource, rule, evaluation });
            resourceEvaluated = true;
            resourceFailed = true;
          } else if (evaluation.status === "PASS" || evaluation.status === "NOT_APPLICABLE") {
            resourceEvaluated = true;
            resolvable.add(findingIdentity({ ruleId: rule.ruleId, ruleVersion: rule.version, awsAccountId: resource.awsAccountId, region: resource.region, resourceId: resource.resourceId }));
          } else {
            resourceInsufficient = true;
          }
        } catch {
          resourceFailed = true;
          errors.push({ resourceId: resource.resourceId, ruleId: rule.ruleId, category: "RULE_EXECUTION_ERROR" });
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

      const status = errors.length > 0 || insufficientEvidence > 0 || failedResources > 0 ? "PARTIAL" as const : "COMPLETED" as const;
      const completed = await tx.securityScanRun.update({
        where: { id: scan.id },
        data: {
          status,
          finishedAt: new Date(),
          totalResources: allResources.length,
          evaluatedResources,
          insufficientEvidence,
          failedResources,
          rulesEvaluated,
          findingsCreated,
          findingsResolved,
          ruleErrors: jsonValue(errors),
        },
      });
      return { completed, findingsCreated, findingsResolved };
    });

    await new AuditEventRepository(this.db).append(auth.context, {
      actorUserId: auth.actorUserId,
      action: "SCAN_COMPLETED",
      purpose: "complete deterministic AWS security analysis",
      targetType: "security_scan",
      targetId: scan.id,
      result: "SUCCESS",
      ...(errors.length ? { reason: `${errors.length} rule execution error(s)` } : {}),
      correlationId,
      metadata: { status: result.completed.status, findingsCreated: result.findingsCreated, findingsResolved: result.findingsResolved, insufficientEvidence },
    });
    return toPublicScan(result.completed);
  }

  async listScans(auth: SecurityAuthorization, accountId: string) {
    requireSecurityPermission(auth, "findings.read");
    safeUuid(accountId, "accountId");
    await this.findAccount(auth, accountId);
    const runs = await this.db.securityScanRun.findMany({ where: { organizationId: auth.organizationId, accountId }, orderBy: { createdAt: "desc" }, take: 100 });
    return runs.map(toPublicScan);
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
        orderBy: [{ severity: "asc" }, { lastDetectedAt: "desc" }],
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
    const updated = await this.db.securityFinding.update({ where: { id: finding.id }, data: { status: "ACKNOWLEDGED", acknowledgedAt: new Date() } });
    await new AuditEventRepository(this.db).append(auth.context, {
      actorUserId: auth.actorUserId,
      action: "FINDING_ACKNOWLEDGED",
      purpose: "acknowledge security finding",
      targetType: "security_finding",
      targetId: finding.id,
      result: "SUCCESS",
      correlationId,
      metadata: { ruleId: finding.ruleId, resourceId: finding.resourceId },
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