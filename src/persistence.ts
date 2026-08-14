import type { Prisma, PrismaClient } from "@prisma/client";
import { AppError } from "./errors.js";

export type DatabaseClient = PrismaClient | Prisma.TransactionClient;

export type OrganizationContext =
  | { readonly kind: "customer"; readonly organizationId: string; readonly actorUserId?: string }
  | { readonly kind: "system"; readonly actorUserId?: string };

export function customerContext(organizationId: string, actorUserId?: string): OrganizationContext {
  if (!organizationId.trim()) throw new AppError("AUTHORIZATION_ERROR", "Organization context is required.");
  return actorUserId ? { kind: "customer", organizationId, actorUserId } : { kind: "customer", organizationId };
}

export function systemContext(actorUserId?: string): OrganizationContext {
  return actorUserId ? { kind: "system", actorUserId } : { kind: "system" };
}

function requireCustomerContext(context: OrganizationContext, organizationId: string): void {
  if (context.kind !== "customer" || context.organizationId !== organizationId) {
    throw new AppError("AUTHORIZATION_ERROR", "A matching organization context is required.");
  }
}

function requireSystemContext(context: OrganizationContext): void {
  if (context.kind !== "system") throw new AppError("AUTHORIZATION_ERROR", "System-level context is required.");
}

function mapPersistenceError(error: unknown): never {
  const code = typeof error === "object" && error !== null && "code" in error ? error.code : undefined;
  if (code === "P2002") throw new AppError("CONFLICT", "The requested record already exists.", { cause: error });
  if (code === "P2003") throw new AppError("VALIDATION_ERROR", "The referenced record does not exist.", { cause: error });
  throw error;
}

const forbiddenAuditKeys = new Set([
  "password",
  "sessionsecret",
  "accesstoken",
  "refreshtoken",
  "awscredential",
  "apisecret",
  "privatekey",
]);

function assertSafeAuditMetadata(value: Prisma.InputJsonValue, path = "metadata"): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => assertSafeAuditMetadata(item, `${path}[${index}]`));
    return;
  }
  if (typeof value === "object" && value !== null) {
    for (const [key, nested] of Object.entries(value)) {
      if (forbiddenAuditKeys.has(key.replace(/[_-]/g, "").toLowerCase())) {
        throw new AppError("VALIDATION_ERROR", `Sensitive audit metadata is not allowed at ${path}.`);
      }
      assertSafeAuditMetadata(nested as Prisma.InputJsonValue, `${path}.${key}`);
    }
  }
}

export class OrganizationRepository {
  constructor(private readonly db: DatabaseClient) {}

  async create(context: OrganizationContext, data: { name: string; slug: string; homeRegion?: string }): Promise<Prisma.OrganizationGetPayload<object>> {
    requireSystemContext(context);
    try {
      return await this.db.organization.create({ data });
    } catch (error) {
      return mapPersistenceError(error);
    }
  }

  async getById(context: OrganizationContext, id: string): Promise<Prisma.OrganizationGetPayload<object> | null> {
    if (context.kind === "customer" && context.organizationId !== id) return null;
    return this.db.organization.findUnique({ where: { id } });
  }

  async list(context: OrganizationContext): Promise<Prisma.OrganizationGetPayload<object>[]> {
    if (context.kind === "customer") return this.db.organization.findMany({ where: { id: context.organizationId } });
    return this.db.organization.findMany();
  }
}

export class UserRepository {
  constructor(private readonly db: DatabaseClient) {}

  async create(data: { externalIdentityRef?: string; status?: "ACTIVE" | "SUSPENDED" | "DELETED" }): Promise<Prisma.UserGetPayload<object>> {
    try {
      return await this.db.user.create({ data });
    } catch (error) {
      return mapPersistenceError(error);
    }
  }

  async getById(id: string): Promise<Prisma.UserGetPayload<object> | null> {
    return this.db.user.findUnique({ where: { id } });
  }
}

export class MembershipRepository {
  constructor(private readonly db: DatabaseClient) {}

  async create(context: OrganizationContext, data: { organizationId: string; userId: string; role: string; status?: "ACTIVE" | "INVITED" | "SUSPENDED" | "REMOVED" }): Promise<Prisma.MembershipGetPayload<object>> {
    requireCustomerContext(context, data.organizationId);
    try {
      return await this.db.membership.create({ data });
    } catch (error) {
      return mapPersistenceError(error);
    }
  }

  async list(context: OrganizationContext): Promise<Prisma.MembershipGetPayload<object>[]> {
    if (context.kind === "customer") return this.db.membership.findMany({ where: { organizationId: context.organizationId } });
    return this.db.membership.findMany();
  }

  async updateRole(context: OrganizationContext, id: string, role: string, expectedVersion: number): Promise<Prisma.MembershipGetPayload<object>> {
    const where = context.kind === "customer" ? { id, organizationId: context.organizationId, version: expectedVersion } : { id, version: expectedVersion };
    const result = await this.db.membership.updateMany({ where, data: { role, version: { increment: 1 } } });
    if (result.count !== 1) throw new AppError("CONFLICT", "The membership was changed or is not accessible.");
    return (await this.db.membership.findUnique({ where: { id } })) as Prisma.MembershipGetPayload<object>;
  }
}

export class InvitationRepository {
  constructor(private readonly db: DatabaseClient) {}

  async create(context: OrganizationContext, data: { organizationId: string; invitedEmail: string; role: string; tokenDigest: string; expiresAt: Date }): Promise<Prisma.InvitationGetPayload<object>> {
    requireCustomerContext(context, data.organizationId);
    try {
      return await this.db.invitation.create({ data });
    } catch (error) {
      return mapPersistenceError(error);
    }
  }

  async getByTokenDigest(context: OrganizationContext, tokenDigest: string): Promise<Prisma.InvitationGetPayload<object> | null> {
    const invitation = await this.db.invitation.findUnique({ where: { tokenDigest } });
    if (invitation && context.kind === "customer" && invitation.organizationId !== context.organizationId) return null;
    return invitation;
  }

  async updateStatus(context: OrganizationContext, id: string, status: "PENDING" | "ACCEPTED" | "REVOKED" | "EXPIRED", expectedVersion: number): Promise<Prisma.InvitationGetPayload<object>> {
    const where = context.kind === "customer" ? { id, organizationId: context.organizationId, version: expectedVersion } : { id, version: expectedVersion };
    const result = await this.db.invitation.updateMany({
      where,
      data: {
        status,
        version: { increment: 1 },
        ...(status === "ACCEPTED" ? { acceptedAt: new Date() } : {}),
        ...(status === "REVOKED" ? { revokedAt: new Date() } : {}),
      },
    });
    if (result.count !== 1) throw new AppError("CONFLICT", "The invitation was changed or is not accessible.");
    return (await this.db.invitation.findUnique({ where: { id } })) as Prisma.InvitationGetPayload<object>;
  }
}

export class AuditEventRepository {
  constructor(private readonly db: DatabaseClient) {}

  async append(context: OrganizationContext, data: { organizationId?: string; actorUserId?: string; action: string; purpose: string; targetType?: string; targetId?: string; result: "SUCCESS" | "FAILURE"; reason?: string; correlationId: string; metadata?: Prisma.InputJsonValue; schemaVersion?: number }): Promise<Prisma.AuditEventGetPayload<object>> {
    if (context.kind === "customer") {
      if (!data.organizationId) data = { ...data, organizationId: context.organizationId };
      requireCustomerContext(context, data.organizationId ?? "");
    }
    const metadata = data.metadata ?? {};
    assertSafeAuditMetadata(metadata);
    try {
      const { actorUserId, ...auditData } = data;
      return await this.db.auditEvent.create({
        data: { ...auditData, ...(actorUserId ? { actorUserId } : {}), metadata },
      });
    } catch (error) {
      return mapPersistenceError(error);
    }
  }

  async list(context: OrganizationContext, limit = 100): Promise<Prisma.AuditEventGetPayload<object>[]> {
    const safeLimit = Math.min(Math.max(limit, 1), 1000);
    return context.kind === "customer"
      ? this.db.auditEvent.findMany({ where: { organizationId: context.organizationId }, orderBy: { createdAt: "desc" }, take: safeLimit })
      : this.db.auditEvent.findMany({ orderBy: { createdAt: "desc" }, take: safeLimit });
  }
}

export class CapabilityRepository {
  constructor(private readonly db: DatabaseClient) {}

  async upsert(context: OrganizationContext, data: { organizationId?: string; capabilityId: string; module: string; version: string; state: "PLANNED" | "NOT_IMPLEMENTED" | "VERIFICATION_REQUIRED" | "DEGRADED" | "LIVE_VERIFIED" | "DEPRECATED"; sourceOfTruth: string; verificationStatus: string; proofReference?: string; dependencyReference?: string; reviewer?: string; verifiedAt?: Date; expiresAt?: Date }): Promise<Prisma.CapabilityRecordGetPayload<object>> {
    if (context.kind === "customer") requireCustomerContext(context, data.organizationId ?? "");
    try {
      return await this.db.capabilityRecord.upsert({ where: { capabilityId: data.capabilityId }, create: data, update: data });
    } catch (error) {
      return mapPersistenceError(error);
    }
  }
}

export class IdempotencyRepository {
  constructor(private readonly db: DatabaseClient) {}

  async claim(context: OrganizationContext, data: { key: string; operationName: string; requestFingerprint: string; expiresAt: Date; actorUserId?: string }): Promise<Prisma.IdempotencyRecordGetPayload<object>> {
    const scopeKey = context.kind === "customer" ? `organization:${context.organizationId}` : "system";
    const organizationId = context.kind === "customer" ? context.organizationId : undefined;
    const existing = await this.db.idempotencyRecord.findUnique({ where: { scopeKey_key: { scopeKey, key: data.key } } });
    if (existing) {
      if (existing.requestFingerprint !== data.requestFingerprint) throw new AppError("CONFLICT", "The idempotency key was reused for a different request.");
      return existing;
    }
    try {
      const createData = {
        key: data.key,
        operationName: data.operationName,
        requestFingerprint: data.requestFingerprint,
        expiresAt: data.expiresAt,
        scopeKey,
        ...(data.actorUserId ? { actorUserId: data.actorUserId } : {}),
        ...(organizationId ? { organizationId } : {}),
      };
      return await this.db.idempotencyRecord.create({ data: createData });
    } catch (error) {
      return mapPersistenceError(error);
    }
  }

  async complete(context: OrganizationContext, key: string, resultReference: string, expectedVersion: number): Promise<Prisma.IdempotencyRecordGetPayload<object>> {
    const scopeKey = context.kind === "customer" ? `organization:${context.organizationId}` : "system";
    const result = await this.db.idempotencyRecord.updateMany({ where: { scopeKey, key, version: expectedVersion }, data: { status: "COMPLETED", resultReference, version: { increment: 1 } } });
    if (result.count !== 1) throw new AppError("CONFLICT", "The idempotency record was changed or is not accessible.");
    return (await this.db.idempotencyRecord.findUnique({ where: { scopeKey_key: { scopeKey, key } } })) as Prisma.IdempotencyRecordGetPayload<object>;
  }
}

export async function withTransaction<T>(db: PrismaClient, operation: (transaction: Prisma.TransactionClient) => Promise<T>): Promise<T> {
  return db.$transaction(operation);
}