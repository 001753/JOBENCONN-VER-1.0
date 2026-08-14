-- Protect the resource lifecycle from dangling AWS connection references.
ALTER TABLE "AwsResource"
  ADD CONSTRAINT "AwsResource_connectionId_fkey"
  FOREIGN KEY ("connectionId") REFERENCES "AwsConnection"("id")
  ON DELETE RESTRICT ON UPDATE CASCADE;