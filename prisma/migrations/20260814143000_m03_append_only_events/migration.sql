ALTER TABLE "ScanEvent"
  ADD COLUMN "attempt" INTEGER NOT NULL DEFAULT 1;

DROP INDEX "ScanEvent_scanRunId_eventType_key";

CREATE UNIQUE INDEX "ScanEvent_scanRunId_eventType_attempt_key"
  ON "ScanEvent"("scanRunId", "eventType", "attempt");