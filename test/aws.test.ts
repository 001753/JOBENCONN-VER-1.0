import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { disconnectPrisma, getPrismaClient } from "../src/database.js";
import { AppError } from "../src/errors.js";
import { IdentityService } from "../src/identity-service.js";
import { type ExternalIdentity } from "../src/identity-provider.js";
import { SessionManager } from "../src/session.js";
import { AwsService, customerAwsAuthorization, type AwsReadOnlyDiscoveryClientFactory } from "../src/aws-service.js";
import { classifyAwsError, retryAws, validateAwsAccountId, validateRoleArn, type AwsReadOnlyDiscoveryClient } from "../src/aws.js";

test("AWS validation classifies bounded retries and rejects unsafe account input", async () => {
  validateAwsAccountId("123456789012");
  validateRoleArn("arn:aws:iam::123456789012:role/JobenDiscovery");
  assert.throws(() => validateAwsAccountId("123"), (error: unknown) => error instanceof AppError && error.code === "VALIDATION_ERROR");
  assert.throws(() => validateRoleArn("https://169.254.169.254/latest"), (error: unknown) => error instanceof AppError && error.code === "VALIDATION_ERROR");

  let attempts = 0;
  const value = await retryAws(async () => {
    attempts += 1;
    if (attempts < 3) throw Object.assign(new Error("throttled"), { name: "ThrottlingException" });
    return "ok";
  }, { baseDelayMs: 0, sleep: async () => undefined });
  assert.equal(value, "ok");
  assert.equal(attempts, 3);
  assert.equal(classifyAwsError(Object.assign(new Error(), { name: "AccessDeniedException" })), "ACCESS_DENIED");
  await assert.rejects(
    retryAws(async () => { throw Object.assign(new Error(), { name: "AccessDeniedException" }); }, { baseDelayMs: 0, sleep: async () => undefined }),
    (error: unknown) => error instanceof AppError && error.code === "AWS_ERROR",
  );
});

const databaseConfigured = Boolean(process.env.DATABASE_URL);

test("Prompt 04 AWS connection, account, inventory, idempotency, and tenant gates", { skip: !databaseConfigured }, async (t) => {
  const db = getPrismaClient();
  await db.$connect();
  const suffix = randomUUID().slice(0, 8);
  const identityA: ExternalIdentity = { provider: "test", subject: `aws-a-${suffix}`, verified: true, email: `aws-a-${suffix}@example.test` };
  const identityB: ExternalIdentity = { provider: "test", subject: `aws-b-${suffix}`, verified: true, email: `aws-b-${suffix}@example.test` };
  const sessions = new SessionManager(db, 3_600, false);
  const identity = new IdentityService(db, sessions);
  const loginA = await identity.login(identityA, `corr-${suffix}-login-a`);
  const loginB = await identity.login(identityB, `corr-${suffix}-login-b`);
  const authA = customerAwsAuthorization({ actorUserId: loginA.actor.userId, organizationId: loginA.organizationId, role: "OWNER" });
  const authB = customerAwsAuthorization({ actorUserId: loginB.actor.userId, organizationId: loginB.organizationId, role: "OWNER" });

  const client: AwsReadOnlyDiscoveryClient = {
    async getCallerIdentity() {
      return { accountId: "123456789012", arn: "arn:aws:iam::123456789012:role/JobenTest", userId: "AROATEST" };
    },
    async listRegions() {
      return [{ code: "us-east-1", name: "US East (N. Virginia)" }, { code: "ap-southeast-1", name: "Asia Pacific (Singapore)" }];
    },
    async listEc2Resources(region, accountId) {
      return [{
        region,
        service: "EC2",
        resourceType: "instance",
        resourceId: `${region}-instance`,
        resourceArn: `arn:aws:ec2:${region}:${accountId}:instance/${region}-instance`,
        metadata: { readOnly: true },
      }];
    },
    async listS3Resources(accountId) {
      return [{ region: "ap-southeast-1", service: "S3", resourceType: "bucket", resourceId: `joben-${accountId}`, resourceArn: `arn:aws:s3:::joben-${accountId}` }];
    },
    async listIamResources(accountId) {
      return [{ region: "global", service: "IAM", resourceType: "account-summary", resourceId: accountId, metadata: { readOnly: true } }];
    },
  };
  const factory: AwsReadOnlyDiscoveryClientFactory = { create: () => client };
  const service = new AwsService(db, factory);

  t.after(async () => {
    const organizationIds = [loginA.organizationId, loginB.organizationId];
    await db.discoveryRun.deleteMany({ where: { organizationId: { in: organizationIds } } });
    await db.awsResource.deleteMany({ where: { organizationId: { in: organizationIds } } });
    await db.awsRegion.deleteMany({ where: { account: { organizationId: { in: organizationIds } } } });
    await db.awsAccount.deleteMany({ where: { organizationId: { in: organizationIds } } });
    await db.awsConnection.deleteMany({ where: { organizationId: { in: organizationIds } } });
    await db.auditEvent.deleteMany({ where: { organizationId: { in: organizationIds } } });
    await db.session.deleteMany({ where: { userId: { in: [loginA.actor.userId, loginB.actor.userId] } } });
    await db.membership.deleteMany({ where: { userId: { in: [loginA.actor.userId, loginB.actor.userId] } } });
    await db.organization.deleteMany({ where: { id: { in: organizationIds } } });
    await db.user.deleteMany({ where: { id: { in: [loginA.actor.userId, loginB.actor.userId] } } });
    await disconnectPrisma();
  });

  const connection = await service.createConnection(authA, { name: "test-aws", credentialSource: "default-chain" }, `corr-${suffix}-create`);
  assert.equal(connection.connection.status, "ACTIVE");
  assert.equal(connection.account.awsAccountId, "123456789012");
  const accounts = await service.listAccounts(authA);
  assert.equal(accounts.length, 1);
  const firstRun = await service.runDiscovery(authA, accounts[0]!.id, `corr-${suffix}-discovery`, `idempotency-${suffix}`);
  assert.equal(firstRun.status, "COMPLETED");
  assert.equal(firstRun.regionsSucceeded, 2);
  assert.equal(firstRun.resourcesDiscovered, 4);
  const replay = await service.runDiscovery(authA, accounts[0]!.id, `corr-${suffix}-replay`, `idempotency-${suffix}`);
  assert.equal(replay.id, firstRun.id);
  assert.equal((await service.listResources(authA, accounts[0]!.id)).length, 4);

  await assert.rejects(
    service.getConnection(authB, connection.connection.id),
    (error: unknown) => error instanceof AppError && error.code === "NOT_FOUND",
  );
  await assert.rejects(
    service.listResources(authB, accounts[0]!.id),
    (error: unknown) => error instanceof AppError && error.code === "NOT_FOUND",
  );
  await service.revokeConnection(authA, connection.connection.id, `corr-${suffix}-revoke`);
  await assert.rejects(
    service.runDiscovery(authA, accounts[0]!.id, `corr-${suffix}-revoked`),
    (error: unknown) => error instanceof AppError && error.code === "FORBIDDEN",
  );
});