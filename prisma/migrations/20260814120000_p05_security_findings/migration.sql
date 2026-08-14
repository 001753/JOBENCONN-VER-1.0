CREATE TYPE "SecurityFindingSeverity" AS ENUM ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO');

CREATE TYPE "SecurityFindingStatus" AS ENUM ('OPEN', 'ACKNOWLEDGED', 'RESOLVED');

CREATE TABLE "SecurityScanRun" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "accountId" UUID NOT NULL,
    "discoveryRunId" UUID,
    "status" "DiscoveryRunStatus" NOT NULL DEFAULT 'RUNNING',
    "idempotencyKey" VARCHAR(255) NOT NULL,
    "snapshotFingerprint" VARCHAR(128) NOT NULL,
    "startedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "finishedAt" TIMESTAMPTZ(3),
    "totalResources" INTEGER NOT NULL DEFAULT 0,
    "evaluatedResources" INTEGER NOT NULL DEFAULT 0,
    "insufficientEvidence" INTEGER NOT NULL DEFAULT 0,
    "failedResources" INTEGER NOT NULL DEFAULT 0,
    "rulesEvaluated" INTEGER NOT NULL DEFAULT 0,
    "findingsCreated" INTEGER NOT NULL DEFAULT 0,
    "findingsResolved" INTEGER NOT NULL DEFAULT 0,
    "ruleErrors" JSONB NOT NULL DEFAULT '[]',
    "correlationId" VARCHAR(128) NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "SecurityScanRun_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "SecurityFinding" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "ruleId" VARCHAR(80) NOT NULL,
    "ruleVersion" VARCHAR(32) NOT NULL,
    "awsResourceId" UUID NOT NULL,
    "accountId" UUID NOT NULL,
    "resourceId" VARCHAR(512) NOT NULL,
    "resourceType" VARCHAR(120) NOT NULL,
    "awsAccountId" VARCHAR(12) NOT NULL,
    "region" VARCHAR(64) NOT NULL,
    "severity" "SecurityFindingSeverity" NOT NULL,
    "status" "SecurityFindingStatus" NOT NULL DEFAULT 'OPEN',
    "title" VARCHAR(255) NOT NULL,
    "description" TEXT NOT NULL,
    "evidence" JSONB NOT NULL,
    "recommendation" TEXT NOT NULL,
    "firstDetectedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "lastDetectedAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "acknowledgedAt" TIMESTAMPTZ(3),
    "resolvedAt" TIMESTAMPTZ(3),
    "resolutionReason" VARCHAR(500),
    "discoveryRunId" UUID,
    "scanRunId" UUID NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "SecurityFinding_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "SecurityScanRun_idempotencyKey_key" ON "SecurityScanRun"("idempotencyKey");
CREATE INDEX "SecurityScanRun_organizationId_accountId_createdAt_idx" ON "SecurityScanRun"("organizationId", "accountId", "createdAt");
CREATE INDEX "SecurityScanRun_organizationId_status_createdAt_idx" ON "SecurityScanRun"("organizationId", "status", "createdAt");

CREATE UNIQUE INDEX "SecurityFinding_organizationId_ruleId_ruleVersion_awsAccountId_region_resourceId_key"
  ON "SecurityFinding"("organizationId", "ruleId", "ruleVersion", "awsAccountId", "region", "resourceId");
CREATE INDEX "SecurityFinding_organizationId_status_severity_lastDetectedAt_idx" ON "SecurityFinding"("organizationId", "status", "severity", "lastDetectedAt");
CREATE INDEX "SecurityFinding_organizationId_ruleId_resourceType_idx" ON "SecurityFinding"("organizationId", "ruleId", "resourceType");
CREATE INDEX "SecurityFinding_organizationId_awsAccountId_region_idx" ON "SecurityFinding"("organizationId", "awsAccountId", "region");
CREATE INDEX "SecurityFinding_organizationId_accountId_status_idx" ON "SecurityFinding"("organizationId", "accountId", "status");
CREATE INDEX "SecurityFinding_resourceId_idx" ON "SecurityFinding"("resourceId");

ALTER TABLE "SecurityScanRun"
  ADD CONSTRAINT "SecurityScanRun_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SecurityScanRun"
  ADD CONSTRAINT "SecurityScanRun_accountId_fkey"
  FOREIGN KEY ("accountId") REFERENCES "AwsAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SecurityScanRun"
  ADD CONSTRAINT "SecurityScanRun_discoveryRunId_fkey"
  FOREIGN KEY ("discoveryRunId") REFERENCES "DiscoveryRun"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "SecurityFinding"
  ADD CONSTRAINT "SecurityFinding_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SecurityFinding"
  ADD CONSTRAINT "SecurityFinding_awsResourceId_fkey"
  FOREIGN KEY ("awsResourceId") REFERENCES "AwsResource"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SecurityFinding"
  ADD CONSTRAINT "SecurityFinding_accountId_fkey"
  FOREIGN KEY ("accountId") REFERENCES "AwsAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "SecurityFinding"
  ADD CONSTRAINT "SecurityFinding_discoveryRunId_fkey"
  FOREIGN KEY ("discoveryRunId") REFERENCES "DiscoveryRun"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "SecurityFinding"
  ADD CONSTRAINT "SecurityFinding_scanRunId_fkey"
  FOREIGN KEY ("scanRunId") REFERENCES "SecurityScanRun"("id") ON DELETE RESTRICT ON UPDATE CASCADE;