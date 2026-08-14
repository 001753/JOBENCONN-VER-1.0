import { Prisma, type EvidenceType, type PrismaClient } from "@prisma/client";
import { AppError } from "./errors.js";
import { requirePermission, type AuthorizationContext, type Permission } from "./authorization.js";
import { AuditEventRepository, customerContext, systemContext, type DatabaseClient, type OrganizationContext } from "./persistence.js";
import { assertNoSensitiveEvidencePayload, redactEvidencePayload } from "./evidence-redaction.js";
import { CANONICALIZATION_VERSION, canonicalizeEvidence, sha256Hex } from "./evidence-canonical.js";
import { validateProviderEvidence } from "./evidence-schema.js";
import { InMemoryEvidenceObjectStorage, type EvidenceObjectStorage } from "./evidence-storage.js";

export const EVIDENCE_EVENT_VERSION = 1;

export interface ObservedFactInput {
  readonly provider: string;
  readonly resourceKey: string;
  readonly observedAt: Date;
  readonly payloadSchema: string;
  readonly extractedFields: unknown;
}

export interface EvidenceCommitInput {
  readonly sourceIntegrationId?: string;
  readonly scanRunId?: string;
  readonly scanCheckOutcomeId?: string;
  readonly findingId?: string;
  readonly controlStatusId?: string;
  readonly supersedesEvidenceId?: string;
  readonly type: EvidenceType;
  readonly provider: string;
  readonly schemaVersion: string;
  readonly providerRequestId?: string;
  readonly sourceEndpoint?: string;
  readonly collectedAt: Date;
  readonly retentionUntil: Date;
  readonly payload: unknown;
  readonly observedFacts?: readonly ObservedFactInput[];
  readonly correlationId: string;
}

export interface EvidenceReadContext {
  readonly auth: AuthorizationContext;
  readonly correlationId: string;
}

function organizationContext(auth: AuthorizationContext): OrganizationContext {
  return auth.kind === "customer"
    ? customerContext(auth.organizationId, auth.actorUserId)
    : systemContext(auth.actorUserId);
}

function requireEvidencePermission(auth: AuthorizationContext, organizationId: string, permission: Permission): void {
  if (auth.kind === "system") return;
  requirePermission({
    actor: {
      userId: auth.actorUserId,
      membership: { organizationId: auth.organizationId, role: auth.role, status: "ACTIVE" },
    },
    organizationId,
    permission,
  });
}

function toPrismaJson(value: unknown, path = "payload"): Prisma.InputJsonValue | typeof Prisma.JsonNull {
  if (value === null) return Prisma.JsonNull;
  if (typeof value === "string" || typeof value === "boolean") return value;
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (Array.isArray(value)) return value.map((item, index) => toPrismaJson(item, `${path}[${index}]`)) as Prisma.InputJsonValue;
  if (typeof value === "object") {
    return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, nested]) => [key, toPrismaJson(nested, `${path}.${key}`)])) as Prisma.InputJsonValue;
  }
  throw new AppError("SCHEMA_ERROR", `schema_error: unsupported value at ${path}`);
}

function isSameEvidenceMetadata(existing: Prisma.EvidenceGetPayload<object>, input: EvidenceCommitInput, hash: string): boolean {
  return existing.contentHash === hash
    && existing.organizationId !== ""
    && existing.type === input.type
    && existing.provider === input.provider
    && existing.schemaVersion === input.schemaVersion
    && existing.canonicalizationVersion === CANONICALIZATION_VERSION
    && existing.sourceIntegrationId === (input.sourceIntegrationId ?? null)
    && existing.retentionUntil.getTime() === input.retentionUntil.getTime()
    && existing.collectedAt.getTime() === input.collectedAt.getTime()
    && existing.providerRequestId === (input.providerRequestId ?? null)
    && existing.sourceEndpoint === (input.sourceEndpoint ?? null)
    && existing.scanRunId === (input.scanRunId ?? null)
    && existing.scanCheckOutcomeId === (input.scanCheckOutcomeId ?? null);
}

export class EvidenceService {
  constructor(
    private readonly db: PrismaClient,
    private readonly storage: EvidenceObjectStorage = new InMemoryEvidenceObjectStorage(),
  ) {}

  get storageCapabilities(): EvidenceObjectStorage["capabilities"] {
    return this.storage.capabilities;
  }

  async commit(auth: AuthorizationContext, input: EvidenceCommitInput): Promise<Prisma.EvidenceGetPayload<object>> {
    const organizationId = auth.kind === "customer"
      ? auth.organizationId
      : await this.resolveSystemOrganization(input);
    requireEvidencePermission(auth, organizationId, "evidence.commit");
    this.validateInput(input);

    const redactedPayload = redactEvidencePayload(input.payload);
    assertNoSensitiveEvidencePayload(redactedPayload);
    validateProviderEvidence(input.provider, input.schemaVersion, redactedPayload);
    const canonicalBytes = canonicalizeEvidence(redactedPayload);
    const contentHash = sha256Hex(canonicalBytes);
    const storageRef = `${organizationId}/${input.type.toLowerCase()}/${contentHash}`;

    const stored = await this.storage.put({
      key: storageRef,
      bytes: canonicalBytes,
      contentHash,
      retentionUntil: input.retentionUntil,
    });
    const persistedBytes = await this.storage.get(storageRef, stored.versionId);
    if (!persistedBytes || sha256Hex(persistedBytes) !== contentHash) {
      throw new AppError("INTEGRITY_ERROR", "Evidence object failed commit verification.");
    }

    try {
      return await this.db.$transaction(async (tx) => {
        await this.assertReferences(tx, organizationId, input);
        const existing = await tx.evidence.findUnique({ where: { storageRef } });
        if (existing) {
          if (isSameEvidenceMetadata(existing, input, contentHash)) return existing;
          throw new AppError("CONFLICT", "Content-addressed evidence already exists with conflicting metadata.");
        }

        const created = await tx.evidence.create({
          data: {
            organizationId,
            ...(input.sourceIntegrationId ? { sourceIntegrationId: input.sourceIntegrationId } : {}),
            ...(input.scanRunId ? { scanRunId: input.scanRunId } : {}),
            ...(input.scanCheckOutcomeId ? { scanCheckOutcomeId: input.scanCheckOutcomeId } : {}),
            ...(input.findingId ? { findingId: input.findingId } : {}),
            ...(input.controlStatusId ? { controlStatusId: input.controlStatusId } : {}),
            ...(input.supersedesEvidenceId ? { supersedesEvidenceId: input.supersedesEvidenceId } : {}),
            type: input.type,
            provider: input.provider,
            storageRef,
            storageVersionId: stored.versionId,
            contentHash,
            canonicalizationVersion: CANONICALIZATION_VERSION,
            schemaVersion: input.schemaVersion,
            ...(input.providerRequestId ? { providerRequestId: input.providerRequestId } : {}),
            ...(input.sourceEndpoint ? { sourceEndpoint: input.sourceEndpoint } : {}),
            collectedAt: input.collectedAt,
            retentionUntil: input.retentionUntil,
            immutable: true,
          } as Prisma.EvidenceUncheckedCreateInput,
        });

        for (const fact of input.observedFacts ?? []) {
          await tx.observedFact.create({
            data: {
              organizationId,
              evidenceId: created.id,
              provider: fact.provider,
              resourceKey: fact.resourceKey,
              observedAt: fact.observedAt,
              payloadSchema: fact.payloadSchema,
              extractedFields: toPrismaJson(fact.extractedFields, "observedFacts"),
            },
          });
        }

        await tx.domainEvent.create({
          data: {
            eventType: "EvidenceCommitted",
            eventVersion: EVIDENCE_EVENT_VERSION,
            ...(auth.kind === "customer" ? { actorUserId: auth.actorUserId } : auth.actorUserId ? { actorUserId: auth.actorUserId } : {}),
            organizationId,
            entityId: created.id,
            entityVersion: 1,
            correlationId: input.correlationId,
            dataRef: storageRef,
          },
        });
        await new AuditEventRepository(tx).append(organizationContext(auth), {
          ...(auth.kind === "customer" ? { actorUserId: auth.actorUserId } : auth.actorUserId ? { actorUserId: auth.actorUserId } : {}),
          organizationId,
          action: "EvidenceCommitted",
          purpose: "commit redacted provider evidence",
          targetType: "evidence",
          targetId: created.id,
          result: "SUCCESS",
          correlationId: input.correlationId,
          metadata: { contentHash, storageRef, canonicalizationVersion: CANONICALIZATION_VERSION, schemaVersion: input.schemaVersion, redacted: true },
        });
        return created;
      });
    } catch (error) {
      if (error instanceof AppError) throw error;
      const existing = await this.db.evidence.findUnique({ where: { storageRef } });
      if (existing && isSameEvidenceMetadata(existing, input, contentHash)) return existing;
      throw error;
    }
  }

  async commitForScan(auth: AuthorizationContext, input: EvidenceCommitInput): Promise<Prisma.EvidenceGetPayload<object>> {
    try {
      return await this.commit(auth, input);
    } catch (error) {
      if (input.scanCheckOutcomeId) {
        await this.db.scanCheckOutcome.updateMany({
          where: {
            id: input.scanCheckOutcomeId,
            ...(auth.kind === "customer" ? { organizationId: auth.organizationId } : {}),
          },
          data: {
            status: "FAILED",
            errorClass: "EVIDENCE_COMMIT_FAILED",
            errorMessage: error instanceof AppError ? error.message.slice(0, 500) : "Evidence commit failed.",
            finishedAt: new Date(),
          },
        });
      }
      throw error;
    }
  }

  async getMetadata(context: EvidenceReadContext, evidenceId: string): Promise<Prisma.EvidenceGetPayload<object>> {
    const organizationId = await this.resolveReadOrganization(context.auth, evidenceId);
    requireEvidencePermission(context.auth, organizationId, "evidence.read");
    const evidence = await this.db.evidence.findFirst({ where: { id: evidenceId, organizationId } });
    if (!evidence) {
      await this.auditDenied(context, evidenceId, "evidence.read");
      throw new AppError("NOT_FOUND", "Evidence not found.");
    }
    await new AuditEventRepository(this.db).append(organizationContext(context.auth), {
      ...(context.auth.kind === "customer" ? { actorUserId: context.auth.actorUserId } : {}),
      organizationId,
      action: "EvidenceRead",
      purpose: "inspect evidence metadata",
      targetType: "evidence",
      targetId: evidence.id,
      result: "SUCCESS",
      correlationId: context.correlationId,
      metadata: { contentHash: evidence.contentHash, storageRef: evidence.storageRef, metadataOnly: true },
    });
    return evidence;
  }

  async retrieve(context: EvidenceReadContext, evidenceId: string): Promise<{ metadata: Prisma.EvidenceGetPayload<object>; bytes: Uint8Array }> {
    const metadata = await this.verify(context, evidenceId);
    const bytes = await this.storage.get(metadata.storageRef, metadata.storageVersionId ?? undefined);
    if (!bytes) {
      await this.markIntegrityFailure(context.auth, metadata, context.correlationId, "object_missing");
      throw new AppError("INTEGRITY_ERROR", "Evidence object is missing.");
    }
    await new AuditEventRepository(this.db).append(organizationContext(context.auth), {
      ...(context.auth.kind === "customer" ? { actorUserId: context.auth.actorUserId } : {}),
      organizationId: metadata.organizationId,
      action: "EvidenceRead",
      purpose: "retrieve authorized evidence bytes",
      targetType: "evidence",
      targetId: metadata.id,
      result: "SUCCESS",
      correlationId: context.correlationId,
      metadata: { contentHash: metadata.contentHash, storageRef: metadata.storageRef, metadataOnly: false },
    });
    return { metadata, bytes };
  }

  async verify(context: EvidenceReadContext, evidenceId: string): Promise<Prisma.EvidenceGetPayload<object>> {
    const organizationId = await this.resolveReadOrganization(context.auth, evidenceId);
    requireEvidencePermission(context.auth, organizationId, "evidence.verify");
    const evidence = await this.db.evidence.findFirst({ where: { id: evidenceId, organizationId } });
    if (!evidence) {
      await this.auditDenied(context, evidenceId, "evidence.verify");
      throw new AppError("NOT_FOUND", "Evidence not found.");
    }
    const object = await this.storage.head(evidence.storageRef, evidence.storageVersionId ?? undefined);
    const bytes = object ? await this.storage.get(evidence.storageRef, evidence.storageVersionId ?? undefined) : null;
    const reason = !object ? "object_missing" : !bytes ? "object_unreadable" : sha256Hex(bytes) !== evidence.contentHash ? "hash_mismatch" : object.contentHash !== evidence.contentHash ? "metadata_mismatch" : null;
    if (reason) return this.markIntegrityFailure(context.auth, evidence, context.correlationId, reason);

    const valid = await this.db.evidence.updateMany({
      where: { id: evidence.id, organizationId },
      data: { integrityStatus: "VALID", integrityVerifiedAt: new Date(), integrityFailureReason: null },
    });
    if (valid.count !== 1) throw new AppError("CONCURRENCY_CONFLICT", "Evidence changed during verification.");
    await new AuditEventRepository(this.db).append(organizationContext(context.auth), {
      ...(context.auth.kind === "customer" ? { actorUserId: context.auth.actorUserId } : {}),
      organizationId,
      action: "EvidenceVerified",
      purpose: "verify evidence object integrity",
      targetType: "evidence",
      targetId: evidence.id,
      result: "SUCCESS",
      correlationId: context.correlationId,
      metadata: { contentHash: evidence.contentHash, integrityStatus: "VALID" },
    });
    return (await this.db.evidence.findUniqueOrThrow({ where: { id: evidence.id } }));
  }

  async createLegalHold(context: EvidenceReadContext, evidenceId: string, reason: string): Promise<Prisma.EvidenceLegalHoldGetPayload<object>> {
    const organizationId = this.requireCustomerOrganization(context.auth);
    requireEvidencePermission(context.auth, organizationId, "evidence.legal_hold");
    const actorUserId = this.requireActor(context.auth);
    if (!reason.trim()) throw new AppError("VALIDATION_ERROR", "Legal hold reason is required.");
    const evidence = await this.scopedEvidence(evidenceId, organizationId, context, "evidence.legal_hold");
    if (evidence.legalHoldStatus === "ACTIVE") throw new AppError("LEGAL_HOLD_CONFLICT", "Evidence already has an active legal hold.");
    return this.db.$transaction(async (tx) => {
      const hold = await tx.evidenceLegalHold.create({
        data: { organizationId, evidenceId, reason: reason.trim(), createdByUserId: actorUserId, status: "ACTIVE" },
      });
      await tx.evidence.update({ where: { id: evidenceId }, data: { legalHoldStatus: "ACTIVE" } });
      await new AuditEventRepository(tx).append(customerContext(organizationId, actorUserId), {
        actorUserId,
        organizationId,
        action: "LegalHoldCreated",
        purpose: "preserve evidence from retention deletion",
        targetType: "evidence",
        targetId: evidenceId,
        result: "SUCCESS",
        correlationId: context.correlationId,
        metadata: { holdId: hold.id, reason: hold.reason },
      });
      return hold;
    });
  }

  async releaseLegalHold(context: EvidenceReadContext, holdId: string): Promise<Prisma.EvidenceLegalHoldGetPayload<object>> {
    const organizationId = this.requireCustomerOrganization(context.auth);
    requireEvidencePermission(context.auth, organizationId, "evidence.legal_hold");
    const actorUserId = this.requireActor(context.auth);
    const hold = await this.db.evidenceLegalHold.findFirst({ where: { id: holdId, organizationId } });
    if (!hold) throw new AppError("NOT_FOUND", "Legal hold not found.");
    if (hold.status !== "ACTIVE") throw new AppError("LEGAL_HOLD_CONFLICT", "Legal hold is already released.");
    return this.db.$transaction(async (tx) => {
      const released = await tx.evidenceLegalHold.update({
        where: { id: hold.id },
        data: { status: "RELEASED", releasedByUserId: actorUserId, releasedAt: new Date() },
      });
      const active = await tx.evidenceLegalHold.count({ where: { evidenceId: hold.evidenceId, organizationId, status: "ACTIVE" } });
      await tx.evidence.update({ where: { id: hold.evidenceId }, data: { legalHoldStatus: active > 0 ? "ACTIVE" : "RELEASED" } });
      await new AuditEventRepository(tx).append(customerContext(organizationId, actorUserId), {
        actorUserId,
        organizationId,
        action: "LegalHoldReleased",
        purpose: "release evidence retention hold",
        targetType: "evidence",
        targetId: hold.evidenceId,
        result: "SUCCESS",
        correlationId: context.correlationId,
        metadata: { holdId: hold.id },
      });
      return released;
    });
  }

  async supersede(context: EvidenceReadContext, evidenceId: string, input: Omit<EvidenceCommitInput, "supersedesEvidenceId">): Promise<Prisma.EvidenceGetPayload<object>> {
    const organizationId = this.requireCustomerOrganization(context.auth);
    requireEvidencePermission(context.auth, organizationId, "evidence.supersede");
    const original = await this.scopedEvidence(evidenceId, organizationId, context, "evidence.supersede");
    const scanRunId = input.scanRunId ?? original.scanRunId ?? undefined;
    const replacement = await this.commit(context.auth, { ...input, ...(scanRunId ? { scanRunId } : {}), supersedesEvidenceId: original.id });
    await new AuditEventRepository(this.db).append(organizationContext(context.auth), {
      ...(context.auth.kind === "customer" ? { actorUserId: context.auth.actorUserId } : {}),
      organizationId,
      action: "EvidenceSuperseded",
      purpose: "correct evidence through an immutable successor",
      targetType: "evidence",
      targetId: original.id,
      result: "SUCCESS",
      correlationId: context.correlationId,
      metadata: { replacementEvidenceId: replacement.id, originalHash: original.contentHash, replacementHash: replacement.contentHash },
    });
    return replacement;
  }

  async deleteExpired(context: EvidenceReadContext, evidenceId: string, now = new Date()): Promise<void> {
    const organizationId = this.requireCustomerOrganization(context.auth);
    requireEvidencePermission(context.auth, organizationId, "evidence.delete");
    const evidence = await this.scopedEvidence(evidenceId, organizationId, context, "evidence.delete");
    // Retention deletion is only safe after a fresh integrity check. A missing
    // or corrupted object must become an integrity failure, never a successful
    // metadata deletion.
    const verifiedEvidence = await this.verify(context, evidenceId);
    if (verifiedEvidence.retentionUntil > now) throw new AppError("RETENTION_CONFLICT", "Evidence retention has not expired.");
    if (verifiedEvidence.legalHoldStatus === "ACTIVE") throw new AppError("LEGAL_HOLD_CONFLICT", "Legal hold blocks evidence deletion.");
    if (verifiedEvidence.integrityStatus !== "VALID") throw new AppError("INTEGRITY_ERROR", "Integrity failure blocks evidence deletion.");
    await this.storage.delete(verifiedEvidence.storageRef, verifiedEvidence.storageVersionId ?? "", now);
    await this.db.$transaction(async (tx) => {
      await tx.evidenceLegalHold.deleteMany({ where: { evidenceId, organizationId } });
      await tx.observedFact.deleteMany({ where: { evidenceId, organizationId } });
      await tx.evidence.delete({ where: { id: evidenceId } });
      await new AuditEventRepository(tx).append(organizationContext(context.auth), {
        ...(context.auth.kind === "customer" ? { actorUserId: context.auth.actorUserId } : {}),
        organizationId,
        action: "EvidenceDeleted",
        purpose: "execute documented expired-retention deletion",
        targetType: "evidence",
        targetId: evidenceId,
        result: "SUCCESS",
        correlationId: context.correlationId,
        metadata: { contentHash: verifiedEvidence.contentHash },
      });
    });
  }

  async assertEligible(evidenceId: string, organizationId: string): Promise<Prisma.EvidenceGetPayload<object>> {
    const evidence = await this.db.evidence.findFirst({ where: { id: evidenceId, organizationId } });
    if (!evidence) throw new AppError("NOT_FOUND", "Evidence not found.");
    if (evidence.integrityStatus !== "VALID") throw new AppError("INTEGRITY_ERROR", "integrity-failed evidence is not eligible.");
    return evidence;
  }

  private validateInput(input: EvidenceCommitInput): void {
    if (!input.correlationId.trim() || !input.provider.trim() || !input.schemaVersion.trim()) throw new AppError("VALIDATION_ERROR", "Evidence provenance fields are required.");
    if (!(input.collectedAt instanceof Date) || Number.isNaN(input.collectedAt.getTime())) throw new AppError("VALIDATION_ERROR", "collectedAt must be a valid timestamp.");
    if (!(input.retentionUntil instanceof Date) || Number.isNaN(input.retentionUntil.getTime())) throw new AppError("VALIDATION_ERROR", "retentionUntil must be a valid timestamp.");
    if (input.retentionUntil < input.collectedAt) throw new AppError("VALIDATION_ERROR", "retentionUntil cannot precede collectedAt.");
  }

  private async assertReferences(tx: DatabaseClient, organizationId: string, input: EvidenceCommitInput): Promise<void> {
    if (input.sourceIntegrationId && !(await tx.awsConnection.findFirst({ where: { id: input.sourceIntegrationId, organizationId }, select: { id: true } }))) {
      throw new AppError("NOT_FOUND", "Source integration not found.");
    }
    if (input.scanRunId && !(await tx.securityScanRun.findFirst({ where: { id: input.scanRunId, organizationId }, select: { id: true } }))) {
      throw new AppError("NOT_FOUND", "Scan run not found.");
    }
    if (input.scanCheckOutcomeId && !(await tx.scanCheckOutcome.findFirst({ where: { id: input.scanCheckOutcomeId, organizationId, ...(input.scanRunId ? { scanRunId: input.scanRunId } : {}) }, select: { id: true } }))) {
      throw new AppError("NOT_FOUND", "Scan check outcome not found.");
    }
    if (input.supersedesEvidenceId && !(await tx.evidence.findFirst({ where: { id: input.supersedesEvidenceId, organizationId }, select: { id: true } }))) {
      throw new AppError("NOT_FOUND", "Superseded evidence not found.");
    }
  }

  private requireCustomerOrganization(auth: AuthorizationContext): string {
    if (auth.kind !== "customer") throw new AppError("AUTHORIZATION_ERROR", "A tenant organization context is required.");
    return auth.organizationId;
  }

  private async resolveReadOrganization(auth: AuthorizationContext, evidenceId: string): Promise<string> {
    if (auth.kind === "customer") return auth.organizationId;
    const evidence = await this.db.evidence.findUnique({ where: { id: evidenceId }, select: { organizationId: true } });
    if (!evidence) throw new AppError("NOT_FOUND", "Evidence not found.");
    return evidence.organizationId;
  }

  private requireActor(auth: AuthorizationContext): string {
    if (!auth.actorUserId) throw new AppError("AUTHORIZATION_ERROR", "An authenticated actor is required.");
    return auth.actorUserId;
  }

  private async resolveSystemOrganization(input: EvidenceCommitInput): Promise<string> {
    if (input.sourceIntegrationId) {
      const connection = await this.db.awsConnection.findUnique({ where: { id: input.sourceIntegrationId }, select: { organizationId: true } });
      if (connection) return connection.organizationId;
    }
    if (input.scanRunId) {
      const scan = await this.db.securityScanRun.findUnique({ where: { id: input.scanRunId }, select: { organizationId: true } });
      if (scan) return scan.organizationId;
    }
    throw new AppError("AUTHORIZATION_ERROR", "System evidence commits require a tenant-bound source reference.");
  }

  private async scopedEvidence(evidenceId: string, organizationId: string, context: EvidenceReadContext, permission: Permission): Promise<Prisma.EvidenceGetPayload<object>> {
    const evidence = await this.db.evidence.findFirst({ where: { id: evidenceId, organizationId } });
    if (!evidence) {
      await this.auditDenied(context, evidenceId, permission);
      throw new AppError("NOT_FOUND", "Evidence not found.");
    }
    return evidence;
  }

  private async markIntegrityFailure(auth: AuthorizationContext, evidence: Prisma.EvidenceGetPayload<object>, correlationId: string, reason: string): Promise<Prisma.EvidenceGetPayload<object>> {
    const updated = await this.db.evidence.update({
      where: { id: evidence.id },
      data: { integrityStatus: "INTEGRITY_FAILED", integrityVerifiedAt: new Date(), integrityFailureReason: reason },
    });
    await this.db.$transaction(async (tx) => {
      await tx.domainEvent.create({
        data: {
          eventType: "EvidenceIntegrityFailed",
          eventVersion: EVIDENCE_EVENT_VERSION,
          ...(auth.kind === "customer" ? { actorUserId: auth.actorUserId } : auth.actorUserId ? { actorUserId: auth.actorUserId } : {}),
          organizationId: evidence.organizationId,
          entityId: evidence.id,
          entityVersion: 1,
          correlationId,
          dataRef: evidence.storageRef,
        },
      }).catch((error: unknown) => {
        if (!(typeof error === "object" && error !== null && "code" in error && error.code === "P2002")) throw error;
      });
      await new AuditEventRepository(tx).append(organizationContext(auth), {
        ...(auth.kind === "customer" ? { actorUserId: auth.actorUserId } : auth.actorUserId ? { actorUserId: auth.actorUserId } : {}),
        organizationId: evidence.organizationId,
        action: "EvidenceIntegrityFailed",
        purpose: "record an evidence integrity incident",
        targetType: "evidence",
        targetId: evidence.id,
        result: "FAILURE",
        reason,
        correlationId,
        metadata: { contentHash: evidence.contentHash, storageRef: evidence.storageRef, integrityStatus: "INTEGRITY_FAILED" },
      });
    });
    return updated;
  }

  private async auditDenied(context: EvidenceReadContext, evidenceId: string, permission: Permission): Promise<void> {
    try {
      await new AuditEventRepository(this.db).append(organizationContext(context.auth), {
        ...(context.auth.kind === "customer" ? { actorUserId: context.auth.actorUserId } : {}),
        ...(context.auth.kind === "customer" ? { organizationId: context.auth.organizationId } : {}),
        action: "EvidenceAccessDenied",
        purpose: `deny unauthorized ${permission} access`,
        targetType: "evidence",
        targetId: evidenceId,
        result: "FAILURE",
        reason: "tenant_scope_or_permission",
        correlationId: context.correlationId,
        metadata: { permission },
      });
    } catch {
      // An access denial must never reveal persistence details or mask the denial.
    }
  }
}
