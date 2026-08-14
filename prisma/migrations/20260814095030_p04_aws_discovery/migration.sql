-- CreateEnum
CREATE TYPE "AwsConnectionStatus" AS ENUM ('PENDING', 'ACTIVE', 'ERROR', 'REVOKED');

-- CreateEnum
CREATE TYPE "AwsAccountStatus" AS ENUM ('ACTIVE', 'ERROR', 'REVOKED');

-- CreateEnum
CREATE TYPE "AwsRegionStatus" AS ENUM ('AVAILABLE', 'UNAVAILABLE');

-- CreateEnum
CREATE TYPE "AwsResourceStatus" AS ENUM ('ACTIVE', 'STALE', 'DELETED');

-- CreateEnum
CREATE TYPE "DiscoveryRunStatus" AS ENUM ('QUEUED', 'RUNNING', 'COMPLETED', 'PARTIAL', 'FAILED', 'CANCELLED');

-- AlterTable
ALTER TABLE "Session" ALTER COLUMN "lastUsedAt" SET DATA TYPE TIMESTAMP(3),
ALTER COLUMN "revokedAt" SET DATA TYPE TIMESTAMP(3);

-- CreateTable
CREATE TABLE "AwsConnection" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "name" VARCHAR(160) NOT NULL,
    "credentialSource" VARCHAR(80) NOT NULL,
    "roleArn" VARCHAR(2048),
    "externalIdDigest" VARCHAR(128),
    "status" "AwsConnectionStatus" NOT NULL DEFAULT 'PENDING',
    "awsAccountId" VARCHAR(12),
    "callerArn" VARCHAR(2048),
    "callerUserId" VARCHAR(512),
    "lastErrorCategory" VARCHAR(80),
    "lastVerifiedAt" TIMESTAMPTZ(3),
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "AwsConnection_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AwsAccount" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "connectionId" UUID NOT NULL,
    "awsAccountId" VARCHAR(12) NOT NULL,
    "alias" VARCHAR(200),
    "status" "AwsAccountStatus" NOT NULL DEFAULT 'ACTIVE',
    "lastVerifiedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "AwsAccount_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AwsRegion" (
    "id" UUID NOT NULL,
    "accountId" UUID NOT NULL,
    "regionCode" VARCHAR(64) NOT NULL,
    "regionName" VARCHAR(160),
    "status" "AwsRegionStatus" NOT NULL DEFAULT 'AVAILABLE',
    "lastDiscoveredAt" TIMESTAMP(3),
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "AwsRegion_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AwsResource" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "accountId" UUID NOT NULL,
    "connectionId" UUID NOT NULL,
    "region" VARCHAR(64) NOT NULL,
    "service" VARCHAR(80) NOT NULL,
    "resourceType" VARCHAR(120) NOT NULL,
    "resourceId" VARCHAR(512) NOT NULL,
    "resourceArn" VARCHAR(2048),
    "resourceName" VARCHAR(512),
    "status" "AwsResourceStatus" NOT NULL DEFAULT 'ACTIVE',
    "tags" JSONB NOT NULL DEFAULT '{}',
    "metadata" JSONB NOT NULL DEFAULT '{}',
    "firstSeenAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastSeenAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "discoveredAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AwsResource_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DiscoveryRun" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "accountId" UUID NOT NULL,
    "connectionId" UUID NOT NULL,
    "status" "DiscoveryRunStatus" NOT NULL DEFAULT 'QUEUED',
    "idempotencyKey" VARCHAR(255),
    "startedAt" TIMESTAMP(3),
    "finishedAt" TIMESTAMP(3),
    "regionsAttempted" INTEGER NOT NULL DEFAULT 0,
    "regionsSucceeded" INTEGER NOT NULL DEFAULT 0,
    "regionsFailed" INTEGER NOT NULL DEFAULT 0,
    "resourcesDiscovered" INTEGER NOT NULL DEFAULT 0,
    "resourcesUpdated" INTEGER NOT NULL DEFAULT 0,
    "resourcesStale" INTEGER NOT NULL DEFAULT 0,
    "errorCount" INTEGER NOT NULL DEFAULT 0,
    "errors" JSONB NOT NULL DEFAULT '[]',
    "correlationId" VARCHAR(128) NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "DiscoveryRun_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "AwsConnection_organizationId_status_idx" ON "AwsConnection"("organizationId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "AwsConnection_organizationId_name_key" ON "AwsConnection"("organizationId", "name");

-- CreateIndex
CREATE INDEX "AwsAccount_connectionId_status_idx" ON "AwsAccount"("connectionId", "status");

-- CreateIndex
CREATE UNIQUE INDEX "AwsAccount_organizationId_awsAccountId_key" ON "AwsAccount"("organizationId", "awsAccountId");

-- CreateIndex
CREATE INDEX "AwsRegion_regionCode_status_idx" ON "AwsRegion"("regionCode", "status");

-- CreateIndex
CREATE UNIQUE INDEX "AwsRegion_accountId_regionCode_key" ON "AwsRegion"("accountId", "regionCode");

-- CreateIndex
CREATE INDEX "AwsResource_organizationId_accountId_status_idx" ON "AwsResource"("organizationId", "accountId", "status");

-- CreateIndex
CREATE INDEX "AwsResource_service_resourceType_region_idx" ON "AwsResource"("service", "resourceType", "region");

-- CreateIndex
CREATE UNIQUE INDEX "AwsResource_organizationId_accountId_region_service_resourc_key" ON "AwsResource"("organizationId", "accountId", "region", "service", "resourceType", "resourceId");

-- CreateIndex
CREATE UNIQUE INDEX "DiscoveryRun_idempotencyKey_key" ON "DiscoveryRun"("idempotencyKey");

-- CreateIndex
CREATE INDEX "DiscoveryRun_organizationId_status_createdAt_idx" ON "DiscoveryRun"("organizationId", "status", "createdAt");

-- CreateIndex
CREATE INDEX "DiscoveryRun_accountId_createdAt_idx" ON "DiscoveryRun"("accountId", "createdAt");

-- AddForeignKey
ALTER TABLE "AwsConnection" ADD CONSTRAINT "AwsConnection_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AwsAccount" ADD CONSTRAINT "AwsAccount_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AwsAccount" ADD CONSTRAINT "AwsAccount_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "AwsConnection"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AwsRegion" ADD CONSTRAINT "AwsRegion_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "AwsAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AwsResource" ADD CONSTRAINT "AwsResource_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "AwsResource" ADD CONSTRAINT "AwsResource_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "AwsAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveryRun" ADD CONSTRAINT "DiscoveryRun_organizationId_fkey" FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveryRun" ADD CONSTRAINT "DiscoveryRun_accountId_fkey" FOREIGN KEY ("accountId") REFERENCES "AwsAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "DiscoveryRun" ADD CONSTRAINT "DiscoveryRun_connectionId_fkey" FOREIGN KEY ("connectionId") REFERENCES "AwsConnection"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
