CREATE TYPE "EvidenceType" AS ENUM ('PROVIDER_RESPONSE', 'SCAN_CHECK', 'INVENTORY_SNAPSHOT', 'CONFIGURATION');
CREATE TYPE "EvidenceIntegrityStatus" AS ENUM ('VALID', 'INTEGRITY_FAILED');
CREATE TYPE "EvidenceLegalHoldStatus" AS ENUM ('NONE', 'ACTIVE', 'RELEASED');

CREATE TABLE "Evidence" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "sourceIntegrationId" UUID,
    "scanRunId" UUID,
    "scanCheckOutcomeId" UUID,
    "findingId" UUID,
    "controlStatusId" UUID,
    "type" "EvidenceType" NOT NULL,
    "provider" VARCHAR(80) NOT NULL,
    "storageRef" VARCHAR(512) NOT NULL,
    "storageUrl" VARCHAR(2048),
    "storageVersionId" VARCHAR(255),
    "contentHash" VARCHAR(64) NOT NULL,
    "canonicalizationVersion" VARCHAR(32) NOT NULL,
    "schemaVersion" VARCHAR(80) NOT NULL,
    "providerRequestId" VARCHAR(255),
    "sourceEndpoint" VARCHAR(2048),
    "collectedAt" TIMESTAMPTZ(3) NOT NULL,
    "retentionUntil" TIMESTAMPTZ(3) NOT NULL,
    "immutable" BOOLEAN NOT NULL DEFAULT true,
    "integrityStatus" "EvidenceIntegrityStatus" NOT NULL DEFAULT 'VALID',
    "integrityVerifiedAt" TIMESTAMPTZ(3),
    "integrityFailureReason" VARCHAR(255),
    "legalHoldStatus" "EvidenceLegalHoldStatus" NOT NULL DEFAULT 'NONE',
    "supersedesEvidenceId" UUID,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "Evidence_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "ObservedFact" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "evidenceId" UUID NOT NULL,
    "provider" VARCHAR(80) NOT NULL,
    "resourceKey" VARCHAR(512) NOT NULL,
    "observedAt" TIMESTAMPTZ(3) NOT NULL,
    "payloadSchema" VARCHAR(80) NOT NULL,
    "extractedFields" JSONB NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ObservedFact_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "EvidenceLegalHold" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "evidenceId" UUID NOT NULL,
    "status" "EvidenceLegalHoldStatus" NOT NULL DEFAULT 'ACTIVE',
    "reason" VARCHAR(500) NOT NULL,
    "createdByUserId" UUID NOT NULL,
    "releasedByUserId" UUID,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "releasedAt" TIMESTAMPTZ(3),
    CONSTRAINT "EvidenceLegalHold_pkey" PRIMARY KEY ("id")
);

CREATE TABLE "DomainEvent" (
    "id" UUID NOT NULL,
    "eventType" VARCHAR(120) NOT NULL,
    "eventVersion" INTEGER NOT NULL DEFAULT 1,
    "occurredAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "actorUserId" UUID,
    "organizationId" UUID NOT NULL,
    "entityId" UUID NOT NULL,
    "entityVersion" INTEGER NOT NULL DEFAULT 1,
    "correlationId" VARCHAR(128) NOT NULL,
    "dataRef" VARCHAR(512) NOT NULL,
    CONSTRAINT "DomainEvent_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "Evidence_storageRef_key" ON "Evidence"("storageRef");
CREATE UNIQUE INDEX "Evidence_organizationId_contentHash_type_sourceIntegrationId_key"
  ON "Evidence"("organizationId", "contentHash", "type", "sourceIntegrationId");
CREATE INDEX "Evidence_organizationId_scanRunId_createdAt_idx" ON "Evidence"("organizationId", "scanRunId", "createdAt");
CREATE INDEX "Evidence_organizationId_contentHash_idx" ON "Evidence"("organizationId", "contentHash");
CREATE INDEX "Evidence_organizationId_integrityStatus_integrityVerifiedAt_idx" ON "Evidence"("organizationId", "integrityStatus", "integrityVerifiedAt");
CREATE INDEX "Evidence_organizationId_retentionUntil_legalHoldStatus_idx" ON "Evidence"("organizationId", "retentionUntil", "legalHoldStatus");
CREATE INDEX "Evidence_organizationId_legalHoldStatus_idx" ON "Evidence"("organizationId", "legalHoldStatus");

CREATE UNIQUE INDEX "ObservedFact_evidenceId_provider_resourceKey_key"
  ON "ObservedFact"("evidenceId", "provider", "resourceKey");
CREATE INDEX "ObservedFact_organizationId_evidenceId_idx" ON "ObservedFact"("organizationId", "evidenceId");
CREATE INDEX "ObservedFact_organizationId_provider_resourceKey_idx" ON "ObservedFact"("organizationId", "provider", "resourceKey");
CREATE INDEX "ObservedFact_observedAt_idx" ON "ObservedFact"("observedAt");

CREATE INDEX "EvidenceLegalHold_organizationId_evidenceId_status_idx" ON "EvidenceLegalHold"("organizationId", "evidenceId", "status");
CREATE INDEX "EvidenceLegalHold_organizationId_status_createdAt_idx" ON "EvidenceLegalHold"("organizationId", "status", "createdAt");

CREATE UNIQUE INDEX "DomainEvent_entityId_eventType_entityVersion_key"
  ON "DomainEvent"("entityId", "eventType", "entityVersion");
CREATE INDEX "DomainEvent_organizationId_occurredAt_idx" ON "DomainEvent"("organizationId", "occurredAt");
CREATE INDEX "DomainEvent_organizationId_eventType_entityId_idx" ON "DomainEvent"("organizationId", "eventType", "entityId");

ALTER TABLE "Evidence"
  ADD CONSTRAINT "Evidence_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "Evidence_sourceIntegrationId_fkey"
  FOREIGN KEY ("sourceIntegrationId") REFERENCES "AwsConnection"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "Evidence_scanRunId_fkey"
  FOREIGN KEY ("scanRunId") REFERENCES "SecurityScanRun"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "Evidence_scanCheckOutcomeId_fkey"
  FOREIGN KEY ("scanCheckOutcomeId") REFERENCES "ScanCheckOutcome"("id") ON DELETE SET NULL ON UPDATE CASCADE,
  ADD CONSTRAINT "Evidence_supersedesEvidenceId_fkey"
  FOREIGN KEY ("supersedesEvidenceId") REFERENCES "Evidence"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

ALTER TABLE "ObservedFact"
  ADD CONSTRAINT "ObservedFact_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "ObservedFact_evidenceId_fkey"
  FOREIGN KEY ("evidenceId") REFERENCES "Evidence"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "EvidenceLegalHold"
  ADD CONSTRAINT "EvidenceLegalHold_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "EvidenceLegalHold_evidenceId_fkey"
  FOREIGN KEY ("evidenceId") REFERENCES "Evidence"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "EvidenceLegalHold_createdByUserId_fkey"
  FOREIGN KEY ("createdByUserId") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "EvidenceLegalHold_releasedByUserId_fkey"
  FOREIGN KEY ("releasedByUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;

ALTER TABLE "DomainEvent"
  ADD CONSTRAINT "DomainEvent_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "DomainEvent_actorUserId_fkey"
  FOREIGN KEY ("actorUserId") REFERENCES "User"("id") ON DELETE SET NULL ON UPDATE CASCADE;