import { Prisma, type PrismaClient } from "@prisma/client";
import { AppError } from "./errors.js";
import { requirePermission, type Permission } from "./authorization.js";
import { AuditEventRepository, customerContext, type OrganizationContext } from "./persistence.js";
import {
  AwsSdkReadOnlyDiscoveryClient,
  classifyAwsError,
  DefaultAwsCredentialProviderFactory,
  type AwsReadOnlyDiscoveryClient,
  type AwsCredentialProviderFactory,
  type NormalizedAwsResource,
  validateAwsAccountId,
  validateRoleArn,
} from "./aws.js";

type Db = PrismaClient | Prisma.TransactionClient;

export interface AwsReadOnlyDiscoveryClientFactory {
  create(config: { credentialSource: string; roleArn?: string | null }): AwsReadOnlyDiscoveryClient;
}

export class DefaultAwsReadOnlyDiscoveryClientFactory implements AwsReadOnlyDiscoveryClientFactory {
  constructor(private readonly credentials: AwsCredentialProviderFactory = new DefaultAwsCredentialProviderFactory()) {}

  create(config: { credentialSource: string; roleArn?: string | null }): AwsReadOnlyDiscoveryClient {
    return new AwsSdkReadOnlyDiscoveryClient(this.credentials.create(config));
  }
}

export interface AwsAuthorization {
  readonly actorUserId: string;
  readonly organizationId: string;
  readonly role: string;
  readonly context: OrganizationContext;
}

function requireAwsPermission(auth: AwsAuthorization, permission: Permission): void {
  requirePermission({
    actor: {
      userId: auth.actorUserId,
      membership: { organizationId: auth.organizationId, role: auth.role, status: "ACTIVE" },
    },
    organizationId: auth.organizationId,
    permission,
  });
}

function safeName(value: string): string {
  const name = value.trim();
  if (!name || name.length > 160) throw new AppError("VALIDATION_ERROR", "AWS connection name is invalid.");
  return name;
}

function safeCredentialSource(value: string): string {
  if (value !== "default-chain") throw new AppError("VALIDATION_ERROR", "credentialSource must be the explicit default-chain.");
  return value;
}

function toPublicConnection(connection: Prisma.AwsConnectionGetPayload<object>) {
  return {
    id: connection.id,
    organizationId: connection.organizationId,
    name: connection.name,
    credentialSource: connection.credentialSource,
    roleArn: connection.roleArn,
    status: connection.status,
    awsAccountId: connection.awsAccountId,
    callerArn: connection.callerArn,
    callerUserId: connection.callerUserId,
    lastErrorCategory: connection.lastErrorCategory,
    lastVerifiedAt: connection.lastVerifiedAt,
    createdAt: connection.createdAt,
    updatedAt: connection.updatedAt,
  };
}

function toPublicRun(run: Prisma.DiscoveryRunGetPayload<object>) {
  return {
    id: run.id,
    organizationId: run.organizationId,
    accountId: run.accountId,
    connectionId: run.connectionId,
    status: run.status,
    idempotencyKey: run.idempotencyKey,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    regionsAttempted: run.regionsAttempted,
    regionsSucceeded: run.regionsSucceeded,
    regionsFailed: run.regionsFailed,
    resourcesDiscovered: run.resourcesDiscovered,
    resourcesUpdated: run.resourcesUpdated,
    resourcesStale: run.resourcesStale,
    errorCount: run.errorCount,
    errors: run.errors,
    correlationId: run.correlationId,
    createdAt: run.createdAt,
    updatedAt: run.updatedAt,
  };
}

function resourceKey(resource: NormalizedAwsResource, organizationId: string, accountId: string) {
  return {
    organizationId_accountId_region_service_resourceType_resourceId: {
      organizationId,
      accountId,
      region: resource.region,
      service: resource.service,
      resourceType: resource.resourceType,
      resourceId: resource.resourceId,
    },
  };
}

function jsonValue(value: Record<string, unknown>): Prisma.InputJsonValue {
  return JSON.parse(JSON.stringify(value)) as Prisma.InputJsonValue;
}

export class AwsService {
  private readonly audit: AuditEventRepository;

  constructor(
    private readonly db: PrismaClient,
    private readonly clients: AwsReadOnlyDiscoveryClientFactory = new DefaultAwsReadOnlyDiscoveryClientFactory(),
  ) {
    this.audit = new AuditEventRepository(db);
  }

  async listConnections(auth: AwsAuthorization): Promise<ReturnType<typeof toPublicConnection>[]> {
    requireAwsPermission(auth, "aws.connection.read");
    const connections = await this.db.awsConnection.findMany({
      where: { organizationId: auth.organizationId },
      orderBy: { createdAt: "asc" },
    });
    return connections.map(toPublicConnection);
  }

  async getConnection(auth: AwsAuthorization, connectionId: string) {
    requireAwsPermission(auth, "aws.connection.read");
    const connection = await this.db.awsConnection.findFirst({ where: { id: connectionId, organizationId: auth.organizationId } });
    if (!connection) throw new AppError("NOT_FOUND", "AWS connection not found.");
    return toPublicConnection(connection);
  }

  async createConnection(auth: AwsAuthorization, input: { name: string; credentialSource: string; roleArn?: string }, correlationId: string) {
    requireAwsPermission(auth, "aws.connection.create");
    const name = safeName(input.name);
    const credentialSource = safeCredentialSource(input.credentialSource);
    if (input.roleArn) validateRoleArn(input.roleArn);
    let connection: Prisma.AwsConnectionGetPayload<object>;
    try {
      connection = await this.db.awsConnection.create({
        data: {
          organizationId: auth.organizationId,
          name,
          credentialSource,
          ...(input.roleArn ? { roleArn: input.roleArn } : {}),
        },
      });
    } catch (error) {
      if (this.persistenceCode(error) === "P2002") throw new AppError("CONFLICT", "An AWS connection with this name already exists.");
      throw error;
    }
    await this.audit.append(auth.context, {
      actorUserId: auth.actorUserId,
      action: "aws.connection.created",
      purpose: "create AWS connection",
      targetType: "aws_connection",
      targetId: connection.id,
      result: "SUCCESS",
      correlationId,
      metadata: { credentialSource, roleConfigured: Boolean(input.roleArn) },
    });
    try {
      return await this.verifyConnection(auth, connection.id, correlationId);
    } catch (error) {
      const category = classifyAwsError(error);
      await this.db.awsConnection.update({ where: { id: connection.id }, data: { status: "ERROR", lastErrorCategory: category } });
      await this.audit.append(auth.context, {
        actorUserId: auth.actorUserId,
        action: "aws.connection.failed",
        purpose: "verify AWS connection",
        targetType: "aws_connection",
        targetId: connection.id,
        result: "FAILURE",
        reason: category,
        correlationId,
        metadata: {},
      });
      throw error;
    }
  }

  async verifyConnection(auth: AwsAuthorization, connectionId: string, correlationId: string) {
    requireAwsPermission(auth, "aws.connection.update");
    const connection = await this.db.awsConnection.findFirst({ where: { id: connectionId, organizationId: auth.organizationId } });
    if (!connection) throw new AppError("NOT_FOUND", "AWS connection not found.");
    if (connection.status === "REVOKED") throw new AppError("FORBIDDEN", "A revoked AWS connection cannot be used.");
    try {
      const client = this.clients.create(connection);
      const identity = await client.getCallerIdentity();
      validateAwsAccountId(identity.accountId);
      const existing = await this.db.awsAccount.findUnique({
        where: { organizationId_awsAccountId: { organizationId: auth.organizationId, awsAccountId: identity.accountId } },
      });
      if (existing && existing.connectionId !== connection.id) throw new AppError("CONFLICT", "This AWS account is already connected to the organization.");
      const now = new Date();
      const result = await this.db.$transaction(async (tx) => {
        const account = await tx.awsAccount.upsert({
          where: { organizationId_awsAccountId: { organizationId: auth.organizationId, awsAccountId: identity.accountId } },
          create: { organizationId: auth.organizationId, connectionId: connection.id, awsAccountId: identity.accountId, status: "ACTIVE", lastVerifiedAt: now },
          update: { connectionId: connection.id, status: "ACTIVE", lastVerifiedAt: now },
        });
        const updated = await tx.awsConnection.update({
          where: { id: connection.id },
          data: { status: "ACTIVE", awsAccountId: identity.accountId, callerArn: identity.arn, callerUserId: identity.userId, lastErrorCategory: null, lastVerifiedAt: now },
        });
        await new AuditEventRepository(tx).append(auth.context, {
          actorUserId: auth.actorUserId,
          action: "aws.connection.verified",
          purpose: "verify AWS caller identity",
          targetType: "aws_connection",
          targetId: connection.id,
          result: "SUCCESS",
          correlationId,
          metadata: { accountId: identity.accountId },
        });
        return { connection: updated, account };
      });
      return { connection: toPublicConnection(result.connection), account: result.account };
    } catch (error) {
      if (error instanceof AppError) throw error;
      throw new AppError("AWS_ERROR", `AWS connection verification failed (${classifyAwsError(error)}).`, { cause: error });
    }
  }

  async revokeConnection(auth: AwsAuthorization, connectionId: string, correlationId: string): Promise<void> {
    requireAwsPermission(auth, "aws.connection.revoke");
    const connection = await this.db.awsConnection.findFirst({ where: { id: connectionId, organizationId: auth.organizationId } });
    if (!connection) throw new AppError("NOT_FOUND", "AWS connection not found.");
    await this.db.$transaction(async (tx) => {
      await tx.awsConnection.update({ where: { id: connection.id }, data: { status: "REVOKED" } });
      await tx.awsAccount.updateMany({ where: { connectionId: connection.id }, data: { status: "REVOKED" } });
      await new AuditEventRepository(tx).append(auth.context, {
        actorUserId: auth.actorUserId,
        action: "aws.connection.revoked",
        purpose: "revoke AWS connection",
        targetType: "aws_connection",
        targetId: connection.id,
        result: "SUCCESS",
        correlationId,
        metadata: {},
      });
    });
  }

  async listAccounts(auth: AwsAuthorization) {
    requireAwsPermission(auth, "aws.connection.read");
    return this.db.awsAccount.findMany({ where: { organizationId: auth.organizationId }, orderBy: { createdAt: "asc" } });
  }

  async listRuns(auth: AwsAuthorization, accountId: string) {
    requireAwsPermission(auth, "aws.inventory.read");
    await this.findAccount(auth, accountId);
    const runs = await this.db.discoveryRun.findMany({ where: { organizationId: auth.organizationId, accountId }, orderBy: { createdAt: "desc" }, take: 100 });
    return runs.map(toPublicRun);
  }

  async listResources(auth: AwsAuthorization, accountId: string) {
    requireAwsPermission(auth, "aws.inventory.read");
    await this.findAccount(auth, accountId);
    return this.db.awsResource.findMany({ where: { organizationId: auth.organizationId, accountId }, orderBy: [{ status: "asc" }, { lastSeenAt: "desc" }], take: 5000 });
  }

  async runDiscovery(auth: AwsAuthorization, accountId: string, correlationId: string, idempotencyKey?: string) {
    requireAwsPermission(auth, "aws.discovery.run");
    const account = await this.findAccount(auth, accountId);
    const connection = await this.db.awsConnection.findFirst({ where: { id: account.connectionId, organizationId: auth.organizationId } });
    if (!connection || connection.status !== "ACTIVE" || account.status !== "ACTIVE") throw new AppError("FORBIDDEN", "An active AWS connection is required.");
    const key = idempotencyKey?.trim();
    if (key && (key.length < 8 || key.length > 255)) throw new AppError("VALIDATION_ERROR", "idempotencyKey must be between 8 and 255 characters.");
    const canonicalKey = key ? `${auth.organizationId}:${accountId}:${key}` : undefined;
    if (canonicalKey) {
      const previous = await this.db.discoveryRun.findUnique({ where: { idempotencyKey: canonicalKey } });
      if (previous) return toPublicRun(previous);
    }
    let run: Prisma.DiscoveryRunGetPayload<object>;
    try {
      run = await this.db.discoveryRun.create({
        data: {
          organizationId: auth.organizationId,
          accountId,
          connectionId: connection.id,
          status: "RUNNING",
          ...(canonicalKey ? { idempotencyKey: canonicalKey } : {}),
          startedAt: new Date(),
          correlationId,
        },
      });
    } catch (error) {
      if (this.persistenceCode(error) === "P2002" && canonicalKey) {
        const previous = await this.db.discoveryRun.findUnique({ where: { idempotencyKey: canonicalKey } });
        if (previous) return toPublicRun(previous);
      }
      throw error;
    }
    await this.audit.append(auth.context, {
      actorUserId: auth.actorUserId,
      action: "aws.discovery.started",
      purpose: "discover AWS account inventory",
      targetType: "discovery_run",
      targetId: run.id,
      result: "SUCCESS",
      correlationId,
      metadata: { accountId: account.awsAccountId },
    });
    try {
      const client = this.clients.create(connection);
      const regions = await client.listRegions();
      const regionCodes = regions.map((region) => region.code);
      const now = new Date();
      await Promise.all(regions.map((region) => this.db.awsRegion.upsert({
        where: { accountId_regionCode: { accountId: account.id, regionCode: region.code } },
        create: { accountId: account.id, regionCode: region.code, ...(region.name ? { regionName: region.name } : {}), status: "AVAILABLE", lastDiscoveredAt: now },
        update: { ...(region.name ? { regionName: region.name } : {}), status: "AVAILABLE", lastDiscoveredAt: now },
      })));
      const errors: Array<{ scope: string; category: string }> = [];
      let regionsSucceeded = 0;
      let resourcesDiscovered = 0;
      let resourcesUpdated = 0;
      let resourcesStale = 0;

      for (const region of regionCodes) {
        try {
          const resources = await client.listEc2Resources(region, account.awsAccountId);
          const counts = await this.persistResources(auth.organizationId, account, connection.id, resources, now);
          resourcesDiscovered += counts.discovered;
          resourcesUpdated += counts.updated;
          resourcesStale += await this.markStale(auth.organizationId, account.id, region, now);
          regionsSucceeded += 1;
        } catch (error) {
          errors.push({ scope: `region:${region}`, category: classifyAwsError(error) });
          await this.db.awsRegion.update({ where: { accountId_regionCode: { accountId: account.id, regionCode: region } }, data: { status: "UNAVAILABLE", lastDiscoveredAt: now } });
        }
      }
      for (const [scope, loader] of [
        ["s3", () => client.listS3Resources(account.awsAccountId)],
        ["iam", () => client.listIamResources(account.awsAccountId)],
      ] as const) {
        try {
          const resources = await loader();
          const counts = await this.persistResources(auth.organizationId, account, connection.id, resources, now);
          resourcesDiscovered += counts.discovered;
          resourcesUpdated += counts.updated;
          resourcesStale += await this.markStale(auth.organizationId, account.id, "global", now, scope.toUpperCase());
        } catch (error) {
          errors.push({ scope, category: classifyAwsError(error) });
        }
      }
      const status = errors.length === 0 ? "COMPLETED" : (regionsSucceeded > 0 || resourcesDiscovered > 0 ? "PARTIAL" : "FAILED");
      const completed = await this.db.discoveryRun.update({
        where: { id: run.id },
        data: { status, finishedAt: new Date(), regionsAttempted: regions.length, regionsSucceeded, regionsFailed: regions.length - regionsSucceeded, resourcesDiscovered, resourcesUpdated, resourcesStale, errorCount: errors.length, errors },
      });
      await this.audit.append(auth.context, {
        actorUserId: auth.actorUserId,
        action: status === "COMPLETED" ? "aws.discovery.completed" : status === "PARTIAL" ? "aws.discovery.partially_completed" : "aws.discovery.failed",
        purpose: "persist AWS account inventory",
        targetType: "discovery_run",
        targetId: run.id,
        result: status === "FAILED" ? "FAILURE" : "SUCCESS",
        ...(errors.length ? { reason: `${errors.length} scope(s) failed` } : {}),
        correlationId,
        metadata: { accountId: account.awsAccountId, resourcesDiscovered, resourcesUpdated, resourcesStale },
      });
      return toPublicRun(completed);
    } catch (error) {
      const failed = await this.db.discoveryRun.update({ where: { id: run.id }, data: { status: "FAILED", finishedAt: new Date(), errorCount: 1, errors: [{ scope: "account", category: classifyAwsError(error) }] } });
      await this.audit.append(auth.context, {
        actorUserId: auth.actorUserId,
        action: "aws.discovery.failed",
        purpose: "discover AWS account inventory",
        targetType: "discovery_run",
        targetId: run.id,
        result: "FAILURE",
        reason: classifyAwsError(error),
        correlationId,
        metadata: {},
      });
      return toPublicRun(failed);
    }
  }

  private async findAccount(auth: AwsAuthorization, accountId: string) {
    const account = await this.db.awsAccount.findFirst({ where: { id: accountId, organizationId: auth.organizationId } });
    if (!account) throw new AppError("NOT_FOUND", "AWS account not found.");
    return account;
  }

  private async persistResources(organizationId: string, account: { id: string }, connectionId: string, resources: readonly NormalizedAwsResource[], observedAt: Date) {
    let discovered = 0;
    let updated = 0;
    for (const resource of resources) {
      if (!resource.service || !resource.resourceType || !resource.resourceId || !resource.region) continue;
      const where = resourceKey(resource, organizationId, account.id);
      const existing = await this.db.awsResource.findUnique({ where });
      await this.db.awsResource.upsert({
        where,
        create: {
          organizationId,
          accountId: account.id,
          connectionId,
          region: resource.region,
          service: resource.service,
          resourceType: resource.resourceType,
          resourceId: resource.resourceId,
          ...(resource.resourceArn ? { resourceArn: resource.resourceArn } : {}),
          ...(resource.resourceName ? { resourceName: resource.resourceName } : {}),
          status: "ACTIVE",
          tags: resource.tags ?? {},
          metadata: jsonValue(resource.metadata ?? {}),
          firstSeenAt: observedAt,
          lastSeenAt: observedAt,
          discoveredAt: observedAt,
        },
        update: {
          connectionId,
          ...(resource.resourceArn ? { resourceArn: resource.resourceArn } : {}),
          ...(resource.resourceName ? { resourceName: resource.resourceName } : {}),
          status: "ACTIVE",
          tags: resource.tags ?? {},
          metadata: jsonValue(resource.metadata ?? {}),
          lastSeenAt: observedAt,
          discoveredAt: observedAt,
        },
      });
      if (existing) updated += 1;
      else discovered += 1;
    }
    return { discovered, updated };
  }

  private async markStale(organizationId: string, accountId: string, region: string, observedAt: Date, service?: string): Promise<number> {
    const result = await this.db.awsResource.updateMany({
      where: { organizationId, accountId, region, ...(service ? { service } : {}), status: "ACTIVE", discoveredAt: { lt: observedAt } },
      data: { status: "STALE" },
    });
    return result.count;
  }

  private persistenceCode(error: unknown): string | undefined {
    return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : undefined;
  }
}

export function customerAwsAuthorization(input: { actorUserId: string; organizationId: string; role: string }): AwsAuthorization {
  return { ...input, context: customerContext(input.organizationId, input.actorUserId) };
}