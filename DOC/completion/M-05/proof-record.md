# M-05 Proof Record

| Requirement | Implementation | Test / evidence | Expected | Actual | Status |
|---|---|---|---|---|---|
| Tenant-scoped metadata and references | Prisma `Evidence` + organization filters | PostgreSQL integration | Cross-tenant read denied | Denied with `NOT_FOUND` and audit | TEST_VERIFIED |
| Secret safety | Recursive redaction + canary | `evidence.test.ts`, integration test | No canary in object/audit | Absent | TEST_VERIFIED |
| Provider validation | Explicit versioned schemas | schema failure test | `schema_error`, no valid evidence | Confirmed | TEST_VERIFIED |
| Deterministic bytes/hash | `JCS-1` + SHA-256 | canonicalization test | Equivalent objects hash equally | Confirmed | TEST_VERIFIED |
| Immutable/content-addressed commit | Storage adapter + unique `storageRef` | overwrite/idempotency tests | No overwrite, same commit idempotent | Confirmed | TEST_VERIFIED |
| ObservedFact lineage | `Evidence` to `ObservedFact` | PostgreSQL integration | Fact references evidence | Confirmed | TEST_VERIFIED |
| Retention/legal hold | metadata + hold history + workflow | PostgreSQL integration | Active hold blocks delete | Confirmed | TEST_VERIFIED |
| Integrity incident | verification service + event/audit | corruption drill | Failed object is rejected | Confirmed | TEST_VERIFIED |
| M-03 integration | scan/check foreign keys | PostgreSQL integration | Evidence references scan outcome | Confirmed | TEST_VERIFIED |
| Live AWS Object Lock | abstraction boundary only | No AWS/Object Lock environment | Never claim live | `VERIFICATION_REQUIRED` | PARTIAL |

Reviewer: Replit Agent. Reverification is required before enabling live AWS
WORM claims or changing canonicalization version.
