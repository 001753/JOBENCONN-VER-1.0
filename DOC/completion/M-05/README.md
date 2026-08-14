# M-05 Evidence Vault & Integrity — Completion Dossier

## Final status

**PARTIAL — TEST_VERIFIED; live object-lock storage remains VERIFICATION_REQUIRED.**

The PostgreSQL-backed M-05 scope is implemented and verified without a
destructive reset. The remaining limitation is external: this environment
does not have verified live S3 credentials/Object Lock configuration, so the
deterministic versioned adapter is not promoted to a live-WORM claim.

Verification timestamp: **2026-08-14T13:27Z** (Asia/Jakarta workspace run).

## Architecture and lifecycle

The Evidence lifecycle is:

```text
provider payload
  -> recursive redaction
  -> provider/schema validation
  -> JCS-1 canonical bytes
  -> SHA-256 content address
  -> versioned storage put + read-back hash check
  -> PostgreSQL Evidence + ObservedFact transaction
  -> EvidenceCommitted domain event + audit event
```

Reads are organization-scoped. Content retrieval performs a fresh integrity
verification first. A mismatch or missing object changes the record to
`INTEGRITY_FAILED`, emits `EvidenceIntegrityFailed`, audits the failure, and
never repairs the object automatically.

## Gap matrix and fixes

| Requirement | Implemented | Tested | Integrated | Persisted | Status |
| --- | --- | --- | --- | --- | --- |
| PostgreSQL schema/migration | yes | Prisma validate/status/deploy | yes | yes | TEST_VERIFIED |
| Evidence + ObservedFact persistence | yes | PostgreSQL integration | M-03 outcome reference | yes | TEST_VERIFIED |
| Recursive redaction and secret canary | yes | nested keys, values, arrays | commit pipeline | redacted bytes only | TEST_VERIFIED |
| Schema validation | yes | invalid provider fixture | commit gate | failure only | TEST_VERIFIED |
| Canonicalization and version | yes | key order, arrays, unicode/null coverage | commit pipeline | `JCS-1` | TEST_VERIFIED |
| SHA-256 authority | yes | storage and DB read-back | content address | `contentHash` | TEST_VERIFIED |
| Immutability/overwrite protection | yes | same bytes idempotent, overwrite conflict | service/storage | immutable metadata | TEST_VERIFIED |
| Supersession | yes | successor preserves original before expiry deletion | audit + FK lineage | `supersedesEvidenceId` | TEST_VERIFIED |
| Retention/legal hold | yes | active/expired/held/released paths | delete gate | hold records/status | TEST_VERIFIED |
| Integrity drill | yes | deliberate corruption | downstream eligibility blocked | failure status/event/audit | TEST_VERIFIED |
| Events and audit | yes | commit/failure/hold/supersession/read | transactional boundaries | PostgreSQL | TEST_VERIFIED |
| Tenant/RBAC | yes | cross-tenant and MEMBER mutation denial | authenticated org context | scoped queries | TEST_VERIFIED |
| M-03 failure boundary | yes | `commitForScan` failure test | outcome becomes FAILED | outcome + evidence reference | TEST_VERIFIED |
| Live S3 SSE/versioning/Object Lock | adapter contract only | no live provider | not live-connected | not claimed | VERIFICATION_REQUIRED |

## Security and integrity proof

- Secret canaries containing authorization, access keys, tokens, private keys,
  webhook secrets, nested credentials, and array values are removed before
  validation/canonicalization/persistence.
- Canonical payloads with different object ordering produce identical bytes and
  SHA-256; arrays retain order and `JCS-1` is persisted.
- Storage rejects a supplied hash that does not match bytes, returns the same
  version for identical content, and rejects a different overwrite.
- The corruption drill changes stored bytes, detects the mismatch, records
  `INTEGRITY_FAILED`, emits `EvidenceIntegrityFailed`, and blocks eligibility.
- Expired retention is still blocked by legal hold; hold create/release actions
  are audited. Unsafe force-delete is not exposed.

## API and runtime proof

Protected routes:

```text
POST   /evidence
GET    /evidence/:id
GET    /evidence/:id/content
POST   /evidence/:id/verify
POST   /evidence/:id/legal-hold
POST   /evidence/legal-holds/:holdId/release
POST   /evidence/:id/supersede
DELETE /evidence/:id
```

Runtime smoke verification on 2026-08-14:

- `GET /health/live` → 200.
- `GET /health/ready` → 200 with PostgreSQL `pass`.
- Unauthenticated `/evidence/...` → 401.
- Authenticated dev-session flow: commit → metadata → canonical content →
  verify all succeeded.
- The returned canonical content contained `[REDACTED]` and no secret canary.
- Invalid Evidence IDs are rejected safely instead of surfacing a Prisma error.

## Full verification commands

```text
npx prisma generate
npx prisma validate
npx prisma migrate deploy
npx prisma migrate status
npm run typecheck
npm run build
npm test
```

Result: **52 tests passed**, build and typecheck passed, and Prisma reported all
12 migrations applied with no pending migrations.

## External verification boundary

The storage adapter reports SSE-S3-compatible encryption metadata, versioning,
and Object Lock compatibility for deterministic tests, but
`liveVerified=false`. No live AWS S3/WORM claim is made. A future verification
must use the existing storage abstraction, real provider credentials, bucket
versioning, default retention, Object Lock governance/compliance settings, and
an independent read/retention check before changing the capability state.