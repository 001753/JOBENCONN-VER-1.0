import { randomUUID } from "node:crypto";
import { DescribeInstancesCommand, DescribeRegionsCommand, EC2Client } from "@aws-sdk/client-ec2";
import { GetAccountSummaryCommand, IAMClient, ListRolesCommand, ListUsersCommand } from "@aws-sdk/client-iam";
import { GetBucketLocationCommand, ListBucketsCommand, S3Client } from "@aws-sdk/client-s3";
import { GetCallerIdentityCommand, STSClient } from "@aws-sdk/client-sts";
import { fromNodeProviderChain, fromTemporaryCredentials } from "@aws-sdk/credential-providers";
import { NodeHttpHandler } from "@smithy/node-http-handler";
import type { AwsCredentialIdentityProvider } from "@smithy/types";
import { AppError } from "./errors.js";

export type AwsErrorCategory =
  | "INVALID_CREDENTIALS"
  | "ACCESS_DENIED"
  | "THROTTLED"
  | "NOT_FOUND"
  | "REGION_UNAVAILABLE"
  | "NETWORK_ERROR"
  | "TIMEOUT"
  | "AWS_SERVICE_ERROR"
  | "IDENTITY_MISMATCH"
  | "UNKNOWN";

export interface AwsCallerIdentity {
  readonly accountId: string;
  readonly arn: string;
  readonly userId: string;
}

export interface AwsRegionDescription {
  readonly code: string;
  readonly name?: string;
}

export interface NormalizedAwsResource {
  readonly region: string;
  readonly service: string;
  readonly resourceType: string;
  readonly resourceId: string;
  readonly resourceArn?: string;
  readonly resourceName?: string;
  readonly tags?: Record<string, string>;
  readonly metadata?: Record<string, unknown>;
}

export interface AwsRootMfaObservation {
  readonly accountId: string;
  readonly mfaEnabled: boolean;
  readonly observedAt: Date;
  readonly requestId?: string;
}

export interface AwsReadOnlyDiscoveryClient {
  getCallerIdentity(): Promise<AwsCallerIdentity>;
  getRootMfaObservation?(accountId: string): Promise<AwsRootMfaObservation>;
  listRegions(): Promise<readonly AwsRegionDescription[]>;
  listEc2Resources(region: string, accountId: string): Promise<readonly NormalizedAwsResource[]>;
  listS3Resources(accountId: string): Promise<readonly NormalizedAwsResource[]>;
  listIamResources(accountId: string): Promise<readonly NormalizedAwsResource[]>;
}

export interface AwsConnectionCredentialConfig {
  readonly credentialSource: string;
  readonly roleArn?: string | null;
}

export interface AwsCredentialProviderFactory {
  create(config: AwsConnectionCredentialConfig): AwsCredentialIdentityProvider;
}

/**
 * Uses the AWS default provider chain. Role assumption is deliberately kept
 * behind this boundary so a future secret manager can supply external IDs
 * without adding credential material to the application database.
 */
export class DefaultAwsCredentialProviderFactory implements AwsCredentialProviderFactory {
  create(config: AwsConnectionCredentialConfig): AwsCredentialIdentityProvider {
    if (config.credentialSource !== "default-chain") {
      throw new AppError("VALIDATION_ERROR", "Only the explicit default-chain credential source is available.");
    }
    const base = fromNodeProviderChain();
    if (!config.roleArn) return base;
    return fromTemporaryCredentials({
      masterCredentials: base,
      params: {
        RoleArn: config.roleArn,
        RoleSessionName: `joben-discovery-${randomUUID()}`,
      },
    });
  }
}

export class AwsSdkReadOnlyDiscoveryClient implements AwsReadOnlyDiscoveryClient {
  private readonly sts: STSClient;
  private readonly ec2: EC2Client;
  private readonly s3: S3Client;
  private readonly iam: IAMClient;

  constructor(credentials: AwsCredentialIdentityProvider, region = process.env.AWS_REGION ?? "us-east-1") {
    const requestHandler = new NodeHttpHandler({
      connectionTimeout: 5_000,
      requestTimeout: 30_000,
    });
    const shared = { credentials, region, requestHandler };
    this.sts = new STSClient(shared);
    this.ec2 = new EC2Client(shared);
    this.s3 = new S3Client(shared);
    this.iam = new IAMClient(shared);
  }

  async getCallerIdentity(): Promise<AwsCallerIdentity> {
    const result = await retryAws(() => this.sts.send(new GetCallerIdentityCommand({})));
    const accountId = result.Account ?? "";
    const arn = result.Arn ?? "";
    const userId = result.UserId ?? "";
    validateAwsAccountId(accountId);
    if (!arn || !userId) throw new AppError("AWS_ERROR", "AWS caller identity was incomplete.");
    return { accountId, arn, userId };
  }

  async getRootMfaObservation(accountId: string): Promise<AwsRootMfaObservation> {
    validateAwsAccountId(accountId);
    const result = await retryAws(() => this.iam.send(new GetAccountSummaryCommand({})));
    const value = result.SummaryMap?.AccountMFAEnabled;
    if (value !== 0 && value !== 1) {
      throw new AppError("SCHEMA_ERROR", "AWS IAM GetAccountSummary returned an invalid AccountMFAEnabled value.");
    }
    return {
      accountId,
      mfaEnabled: value === 1,
      observedAt: new Date(),
      ...(result.$metadata.requestId ? { requestId: result.$metadata.requestId } : {}),
    };
  }

  async listRegions(): Promise<readonly AwsRegionDescription[]> {
    const result = await retryAws(() => this.ec2.send(new DescribeRegionsCommand({ AllRegions: false })));
    return (result.Regions ?? [])
      .flatMap((region) => region.RegionName ? [{ code: region.RegionName, name: region.RegionName }] : []);
  }

  async listEc2Resources(region: string, accountId: string): Promise<readonly NormalizedAwsResource[]> {
    const client = new EC2Client({
      credentials: this.ec2.config.credentials,
      region,
      requestHandler: this.ec2.config.requestHandler,
    });
    const resources: NormalizedAwsResource[] = [];
    let nextToken: string | undefined;
    do {
      const page = await retryAws(() => client.send(new DescribeInstancesCommand({ NextToken: nextToken })));
      for (const reservation of page.Reservations ?? []) {
        for (const instance of reservation.Instances ?? []) {
          if (!instance.InstanceId) continue;
          const name = instance.Tags?.find((tag) => tag.Key === "Name")?.Value;
          resources.push({
            region,
            service: "EC2",
            resourceType: "instance",
            resourceId: instance.InstanceId,
            resourceArn: `arn:aws:ec2:${region}:${accountId}:instance/${instance.InstanceId}`,
            ...(name ? { resourceName: name } : {}),
            tags: Object.fromEntries((instance.Tags ?? []).flatMap((tag) => tag.Key ? [[tag.Key, tag.Value ?? ""]] : [])),
            metadata: {
              instanceType: instance.InstanceType,
              state: instance.State?.Name,
              vpcId: instance.VpcId,
              subnetId: instance.SubnetId,
            },
          });
        }
      }
      nextToken = page.NextToken;
    } while (nextToken);
    return resources;
  }

  async listS3Resources(accountId: string): Promise<readonly NormalizedAwsResource[]> {
    const result = await retryAws(() => this.s3.send(new ListBucketsCommand({})));
    const resources: NormalizedAwsResource[] = [];
    for (const bucket of result.Buckets ?? []) {
      if (!bucket.Name) continue;
      const location = await retryAws(() => this.s3.send(new GetBucketLocationCommand({ Bucket: bucket.Name })));
      const region = location.LocationConstraint || "us-east-1";
      resources.push({
        region,
        service: "S3",
        resourceType: "bucket",
        resourceId: bucket.Name,
        resourceArn: `arn:aws:s3:::${bucket.Name}`,
        resourceName: bucket.Name,
        metadata: { creationDate: bucket.CreationDate?.toISOString(), accountId },
      });
    }
    return resources;
  }

  async listIamResources(accountId: string): Promise<readonly NormalizedAwsResource[]> {
    const resources: NormalizedAwsResource[] = [];
    const summary = await retryAws(() => this.iam.send(new GetAccountSummaryCommand({})));
    resources.push({
      region: "global",
      service: "IAM",
      resourceType: "account-summary",
      resourceId: accountId,
      resourceArn: `arn:aws:iam::${accountId}:root`,
      metadata: { summaryMap: summary.SummaryMap ?? {} },
    });
    let userMarker: string | undefined;
    do {
      const page = await retryAws(() => this.iam.send(new ListUsersCommand({ Marker: userMarker })));
      for (const user of page.Users ?? []) {
        if (!user.UserId) continue;
        resources.push({
          region: "global",
          service: "IAM",
          resourceType: "user",
          resourceId: user.UserId,
          ...(user.Arn ? { resourceArn: user.Arn } : {}),
          ...(user.UserName ? { resourceName: user.UserName } : {}),
          metadata: { path: user.Path, createdAt: user.CreateDate?.toISOString() },
        });
      }
      userMarker = page.IsTruncated ? page.Marker : undefined;
    } while (userMarker);
    let roleMarker: string | undefined;
    do {
      const page = await retryAws(() => this.iam.send(new ListRolesCommand({ Marker: roleMarker })));
      for (const role of page.Roles ?? []) {
        if (!role.RoleId) continue;
        resources.push({
          region: "global",
          service: "IAM",
          resourceType: "role",
          resourceId: role.RoleId,
          ...(role.Arn ? { resourceArn: role.Arn } : {}),
          ...(role.RoleName ? { resourceName: role.RoleName } : {}),
          metadata: { path: role.Path, createdAt: role.CreateDate?.toISOString() },
        });
      }
      roleMarker = page.IsTruncated ? page.Marker : undefined;
    } while (roleMarker);
    return resources;
  }
}

export function validateAwsAccountId(accountId: string): void {
  if (!/^\d{12}$/.test(accountId)) throw new AppError("VALIDATION_ERROR", "AWS account identity must be a 12-digit account ID.");
}

export function validateRoleArn(roleArn: string): void {
  if (!/^arn:aws:iam::\d{12}:role\/[A-Za-z0-9+=,.@_\/-]{1,512}$/.test(roleArn)) {
    throw new AppError("VALIDATION_ERROR", "roleArn must be a valid AWS IAM role ARN.");
  }
}

export function classifyAwsError(error: unknown): AwsErrorCategory {
  let current: unknown = error;
  for (let depth = 0; depth < 4 && current; depth += 1) {
    const value = current as { name?: string; code?: string; $metadata?: { httpStatusCode?: number }; cause?: unknown };
    const name = `${value.name ?? ""} ${value.code ?? ""}`.toLowerCase();
    const status = value.$metadata?.httpStatusCode;
    if (name.includes("identitymismatch")) return "IDENTITY_MISMATCH";
    if (name.includes("invalidclienttoken") || name.includes("credential") || name.includes("accesskey")) return "INVALID_CREDENTIALS";
    if (name.includes("accessdenied") || name.includes("unauthorized")) return "ACCESS_DENIED";
    if (name.includes("throttl") || status === 429) return "THROTTLED";
    if (name.includes("notfound") || status === 404) return "NOT_FOUND";
    if (name.includes("region") && (name.includes("unavailable") || name.includes("disabled"))) return "REGION_UNAVAILABLE";
    if (name.includes("timeout") || name.includes("requesttimeout") || name.includes("abort") || name.includes("etimedout")) return "TIMEOUT";
    if (name.includes("network") || name.includes("socket") || name.includes("econn")) return "NETWORK_ERROR";
    if (typeof status === "number" && status >= 500) return "AWS_SERVICE_ERROR";
    current = value.cause;
  }
  return "UNKNOWN";
}

export async function retryAws<T>(operation: () => Promise<T>, options: {
  maxAttempts?: number;
  maxElapsedMs?: number;
  baseDelayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  random?: () => number;
} = {}): Promise<T> {
  const maxAttempts = options.maxAttempts ?? 3;
  const maxElapsedMs = options.maxElapsedMs ?? 10_000;
  const sleep = options.sleep ?? ((ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)));
  const random = options.random ?? Math.random;
  const startedAt = Date.now();
  let attempt = 0;
  while (true) {
    try {
      return await operation();
    } catch (error) {
      attempt += 1;
      const category = classifyAwsError(error);
      const retryable = category === "THROTTLED" || category === "NETWORK_ERROR" || category === "AWS_SERVICE_ERROR";
      const elapsedMs = Date.now() - startedAt;
      if (!retryable || attempt >= maxAttempts || elapsedMs >= maxElapsedMs) {
        throw new AppError("AWS_ERROR", `AWS operation failed (${category}).`, { cause: error });
      }
      const exponentialDelay = (options.baseDelayMs ?? 50) * (2 ** (attempt - 1));
      const jitteredDelay = Math.round(exponentialDelay * (0.5 + Math.min(Math.max(random(), 0), 1) * 0.5));
      await sleep(Math.min(jitteredDelay, Math.max(0, maxElapsedMs - elapsedMs)));
    }
  }
}