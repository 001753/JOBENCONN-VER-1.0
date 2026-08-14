/*
  Superseded evidence remains immutable and independently retained. Once its
  retention expires and no legal hold is active, deletion is allowed; the
  successor's optional lineage pointer is cleared by PostgreSQL rather than
  mutating the committed evidence through an application update.
*/
ALTER TABLE "Evidence"
  DROP CONSTRAINT "Evidence_supersedesEvidenceId_fkey",
  ADD CONSTRAINT "Evidence_supersedesEvidenceId_fkey"
    FOREIGN KEY ("supersedesEvidenceId") REFERENCES "Evidence"("id")
    ON DELETE SET NULL ON UPDATE CASCADE;