-- M-06: first real AWS control result and evidence lineage.
CREATE TABLE "ControlResult" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "scanRunId" UUID NOT NULL,
    "scanCheckOutcomeId" UUID,
    "evidenceId" UUID,
    "checkId" VARCHAR(120) NOT NULL,
    "checkVersion" VARCHAR(32) NOT NULL,
    "evaluatorVersion" VARCHAR(32) NOT NULL,
    "provider" VARCHAR(80) NOT NULL,
    "service" VARCHAR(80) NOT NULL,
    "operation" VARCHAR(160) NOT NULL,
    "resourceKey" VARCHAR(512) NOT NULL,
    "status" VARCHAR(32) NOT NULL,
    "observedAt" TIMESTAMPTZ(3) NOT NULL,
    "coverage" VARCHAR(500) NOT NULL,
    "dataQuality" VARCHAR(80) NOT NULL,
    "message" VARCHAR(1000) NOT NULL,
    "errorCode" VARCHAR(80),
    "evidenceHash" VARCHAR(64),
    "canonicalizationVersion" VARCHAR(32),
    "provenance" JSONB NOT NULL DEFAULT '{}',
    "remediation" JSONB,
    "soc2Mapping" JSONB,
    "attempt" INTEGER NOT NULL DEFAULT 1,
    "correlationId" VARCHAR(128) NOT NULL,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT "ControlResult_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ControlResult_scanRunId_checkId_checkVersion_resourceKey_attempt_key"
  ON "ControlResult"("scanRunId", "checkId", "checkVersion", "resourceKey", "attempt");
CREATE INDEX "ControlResult_organizationId_checkId_status_observedAt_idx"
  ON "ControlResult"("organizationId", "checkId", "status", "observedAt");
CREATE INDEX "ControlResult_organizationId_resourceKey_observedAt_idx"
  ON "ControlResult"("organizationId", "resourceKey", "observedAt");

ALTER TABLE "ControlResult" ADD CONSTRAINT "ControlResult_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
ALTER TABLE "ControlResult" ADD CONSTRAINT "ControlResult_scanRunId_fkey"
  FOREIGN KEY ("scanRunId") REFERENCES "SecurityScanRun"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "ControlResult" ADD CONSTRAINT "ControlResult_scanCheckOutcomeId_fkey"
  FOREIGN KEY ("scanCheckOutcomeId") REFERENCES "ScanCheckOutcome"("id") ON DELETE SET NULL ON UPDATE CASCADE;
ALTER TABLE "ControlResult" ADD CONSTRAINT "ControlResult_evidenceId_fkey"
  FOREIGN KEY ("evidenceId") REFERENCES "Evidence"("id") ON DELETE SET NULL ON UPDATE CASCADE;