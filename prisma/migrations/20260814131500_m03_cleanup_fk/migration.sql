ALTER TABLE "ScanCheckOutcome" DROP CONSTRAINT "ScanCheckOutcome_scanRunId_fkey";
ALTER TABLE "ScanCheckOutcome"
  ADD CONSTRAINT "ScanCheckOutcome_scanRunId_fkey"
  FOREIGN KEY ("scanRunId") REFERENCES "SecurityScanRun"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ScanEvent" DROP CONSTRAINT "ScanEvent_scanRunId_fkey";
ALTER TABLE "ScanEvent"
  ADD CONSTRAINT "ScanEvent_scanRunId_fkey"
  FOREIGN KEY ("scanRunId") REFERENCES "SecurityScanRun"("id") ON DELETE CASCADE ON UPDATE CASCADE;