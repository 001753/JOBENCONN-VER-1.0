# M-05 Integrity Verification Runbook

For an evidence record, resolve `storageRef` and `storageVersionId`, check
object existence, retrieve canonical bytes, recompute SHA-256, compare with
`contentHash`, and compare object metadata with PostgreSQL metadata.

Success sets `integrityStatus=VALID` and records the verification timestamp.
Missing, unreadable, mismatched, or inconsistent objects set
`integrityStatus=INTEGRITY_FAILED`, retain the original hash, append an audit
incident, and emit `EvidenceIntegrityFailed`. Consumers use
`assertEligible` and must reject failed evidence.

Do not repair a hash, overwrite an object, or replace a corrupted record.
Corrected evidence is a new immutable record linked with
`supersedesEvidenceId`.

The deterministic integrity drill commits an object, verifies `VALID`,
corrupts the test object, verifies `INTEGRITY_FAILED`, checks audit/event
creation, and confirms downstream eligibility rejection.
