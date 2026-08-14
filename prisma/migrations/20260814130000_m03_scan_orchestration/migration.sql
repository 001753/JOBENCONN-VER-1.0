ALTER TYPE "DiscoveryRunStatus" ADD VALUE IF NOT EXISTS 'CANCELLING';
ALTER TYPE "DiscoveryRunStatus" ADD VALUE IF NOT EXISTS 'DEAD_LETTER';

ALTER TABLE "SecurityScanRun"
  ADD COLUMN "connectionId" UUID,
  ADD COLUMN "requestedByUserId" UUID,
  ADD COLUMN "triggerType" VARCHAR(32) NOT NULL DEFAULT 'MANUAL',
  ADD COLUMN "activeKey" VARCHAR(120),
  ADD COLUMN "durationMs" INTEGER,
  ADD COLUMN "totalChecks" INTEGER,
  ADD COLUMN "completedChecks" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "failedChecks" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "skippedChecks" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "retryCount" INTEGER NOT NULL DEFAULT 0,
  ADD COLUMN "lastErrorCategory" VARCHAR(80),
  ADD COLUMN "lastError" VARCHAR(500),
  ADD COLUMN "cancelRequestedAt" TIMESTAMPTZ(3),
  ADD COLUMN "terminalReason" VARCHAR(255),
  ADD COLUMN "leaseOwner" VARCHAR(128),
  ADD COLUMN "leaseAcquiredAt" TIMESTAMPTZ(3),
  ADD COLUMN "leaseExpiresAt" TIMESTAMPTZ(3);

UPDATE "SecurityScanRun" AS scan
SET "connectionId" = account."connectionId"
FROM "AwsAccount" AS account
WHERE scan."accountId" = account."id";

ALTER TABLE "SecurityScanRun"
  ALTER COLUMN "connectionId" SET NOT NULL,
  ALTER COLUMN "startedAt" DROP DEFAULT,
  ALTER COLUMN "startedAt" DROP NOT NULL;

CREATE UNIQUE INDEX "SecurityScanRun_activeKey_key" ON "SecurityScanRun"("activeKey");
CREATE INDEX "SecurityScanRun_organizationId_connectionId_status_idx" ON "SecurityScanRun"("organizationId", "connectionId", "status");
CREATE INDEX "SecurityScanRun_leaseExpiresAt_status_idx" ON "SecurityScanRun"("leaseExpiresAt", "status");

ALTER TABLE "SecurityScanRun"
  ADD CONSTRAINT "SecurityScanRun_connectionId_fkey"
  FOREIGN KEY ("connectionId") REFERENCES "AwsConnection"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "SecurityScanRun_requestedByUserId_fkey"
  FOREIGN KEY ("requestedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

CREATE TYPE "ScanJobStatus" AS ENUM ('QUEUED', 'RUNNING', 'RETRY_WAIT', 'COMPLETED', 'CANCELLED', 'DEAD_LETTER');

CREATE TABLE "ScanJob" (
    "id" UUID NOT NULL,
    "scanRunId" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "accountId" UUID NOT NULL,
    "status" "ScanJobStatus" NOT NULL DEFAULT 'QUEUED',
    "attempt" INTEGER NOT NULL DEFAULT 0,
    "availableAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "leasedAt" TIMESTAMPTZ(3),
    "leaseExpiresAt" TIMESTAMPTZ(3),
    "workerId" VARCHAR(128),
    "lastError" VARCHAR(500),
    "correlationId" VARCHAR(128) NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "ScanJob_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ScanJob_scanRunId_key" ON "ScanJob"("scanRunId");
CREATE INDEX "ScanJob_status_availableAt_createdAt_idx" ON "ScanJob"("status", "availableAt", "createdAt");
CREATE INDEX "ScanJob_organizationId_status_createdAt_idx" ON "ScanJob"("organizationId", "status", "createdAt");
CREATE INDEX "ScanJob_leaseExpiresAt_status_idx" ON "ScanJob"("leaseExpiresAt", "status");
CREATE INDEX "ScanJob_scanRunId_idx" ON "ScanJob"("scanRunId");

ALTER TABLE "ScanJob"
  ADD CONSTRAINT "ScanJob_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "ScanJob_accountId_fkey"
  FOREIGN KEY ("accountId") REFERENCES "AwsAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "ScanJob_scanRunId_fkey"
  FOREIGN KEY ("scanRunId") REFERENCES "SecurityScanRun"("id") ON DELETE CASCADE ON UPDATE CASCADE;

CREATE TABLE "ScanCheckOutcome" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "scanRunId" UUID NOT NULL,
    "checkId" VARCHAR(120) NOT NULL,
    "checkVersion" VARCHAR(32) NOT NULL,
    "resourceIdentity" VARCHAR(512) NOT NULL,
    "status" VARCHAR(32) NOT NULL,
    "startedAt" TIMESTAMPTZ(3) NOT NULL,
    "finishedAt" TIMESTAMPTZ(3) NOT NULL,
    "durationMs" INTEGER NOT NULL,
    "errorClass" VARCHAR(80),
    "errorMessage" VARCHAR(500),
    "attempt" INTEGER NOT NULL DEFAULT 1,
    "correlationId" VARCHAR(128) NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ScanCheckOutcome_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ScanCheckOutcome_scanRunId_checkId_checkVersion_resourceIdentity_attempt_key"
  ON "ScanCheckOutcome"("scanRunId", "checkId", "checkVersion", "resourceIdentity", "attempt");
CREATE INDEX "ScanCheckOutcome_organizationId_scanRunId_createdAt_idx" ON "ScanCheckOutcome"("organizationId", "scanRunId", "createdAt");
CREATE INDEX "ScanCheckOutcome_scanRunId_resourceIdentity_idx" ON "ScanCheckOutcome"("scanRunId", "resourceIdentity");

ALTER TABLE "ScanCheckOutcome"
  ADD CONSTRAINT "ScanCheckOutcome_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "ScanCheckOutcome_scanRunId_fkey"
  FOREIGN KEY ("scanRunId") REFERENCES "SecurityScanRun"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

CREATE TABLE "ScanEvent" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "scanRunId" UUID NOT NULL,
    "eventType" VARCHAR(64) NOT NULL,
    "correlationId" VARCHAR(128) NOT NULL,
    "payload" JSONB NOT NULL DEFAULT '{}',
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ScanEvent_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ScanEvent_scanRunId_eventType_key" ON "ScanEvent"("scanRunId", "eventType");
CREATE INDEX "ScanEvent_organizationId_createdAt_idx" ON "ScanEvent"("organizationId", "createdAt");
CREATE INDEX "ScanEvent_scanRunId_createdAt_idx" ON "ScanEvent"("scanRunId", "createdAt");

ALTER TABLE "ScanEvent"
  ADD CONSTRAINT "ScanEvent_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "ScanEvent_scanRunId_fkey"
  FOREIGN KEY ("scanRunId") REFERENCES "SecurityScanRun"("id") ON DELETE RESTRICT ON UPDATE CASCADE;