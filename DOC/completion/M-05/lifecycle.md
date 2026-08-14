# M-05 Evidence Lifecycle

1. Receive provider response in memory.
2. Recursively redact secret-bearing keys and known credential/token patterns.
3. Validate the redacted payload against an explicit provider/schema contract.
4. Canonicalize with `JCS-1` and compute SHA-256 over canonical UTF-8 bytes.
5. Write to the tenant/type/hash content-addressed storage key.
6. Read back and verify the object hash.
7. Persist metadata, ObservedFact lineage, `EvidenceCommitted`, and audit in
   one PostgreSQL transaction.
8. Verify on demand or via a worker; mismatch/missing data becomes
   `INTEGRITY_FAILED`, never silently repaired.
9. Correct only by committing a new record with `supersedesEvidenceId`.
10. Delete only through the expired-retention workflow, with no active legal
    hold and valid integrity.

Evidence payload fields are not updateable. Metadata integrity state is
explicitly mutable so verification incidents can be recorded without changing
the immutable payload.
