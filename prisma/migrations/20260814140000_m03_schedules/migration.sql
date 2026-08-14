CREATE TABLE "ScanSchedule" (
    "id" UUID NOT NULL,
    "organizationId" UUID NOT NULL,
    "accountId" UUID NOT NULL,
    "name" VARCHAR(160) NOT NULL,
    "frequency" VARCHAR(32) NOT NULL,
    "localTime" VARCHAR(5) NOT NULL,
    "timezone" VARCHAR(64) NOT NULL,
    "paused" BOOLEAN NOT NULL DEFAULT false,
    "nextRunAt" TIMESTAMPTZ(3),
    "lastRunAt" TIMESTAMPTZ(3),
    "lastRunId" UUID,
    "createdAt" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "ScanSchedule_pkey" PRIMARY KEY ("id")
);

CREATE UNIQUE INDEX "ScanSchedule_organizationId_name_key"
  ON "ScanSchedule"("organizationId", "name");
CREATE INDEX "ScanSchedule_paused_nextRunAt_idx"
  ON "ScanSchedule"("paused", "nextRunAt");
CREATE INDEX "ScanSchedule_organizationId_accountId_paused_idx"
  ON "ScanSchedule"("organizationId", "accountId", "paused");

ALTER TABLE "ScanSchedule"
  ADD CONSTRAINT "ScanSchedule_organizationId_fkey"
  FOREIGN KEY ("organizationId") REFERENCES "Organization"("id") ON DELETE RESTRICT ON UPDATE CASCADE,
  ADD CONSTRAINT "ScanSchedule_accountId_fkey"
  FOREIGN KEY ("accountId") REFERENCES "AwsAccount"("id") ON DELETE RESTRICT ON UPDATE CASCADE;