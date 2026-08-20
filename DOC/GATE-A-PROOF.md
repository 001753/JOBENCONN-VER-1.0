# Gate A Proof

## Result

**Gate A: NOT PASSED as an overall 01–08 completion gate.**

The repository foundation and PostgreSQL-backed test gates are verified. Gate A
is not promoted because the external verification prerequisites are incomplete:
the configured identity provider is not live-connected, AWS provider identity
has not been verified, and the live object-storage/WORM boundary for the
Evidence Vault has not been exercised.

This is a conservative proof statement. It does not invalidate the passing
local and PostgreSQL-backed tests.

## Evidence

| Area | Result | Evidence |
|---|---|---|
| Prompt 01 foundation | PASS | `test/foundation.test.ts`, build, typecheck, health smoke checks |
| Prompt 02 persistence | PASS | 13 migrations applied to the configured PostgreSQL database; `test/persistence.test.ts` |
| Prompt 03 tenant/RBAC | TEST_VERIFIED | `test/identity.integration.test.ts`; provider live verification pending |
| Prompt 04 AWS boundary | TEST_VERIFIED | `test/aws.test.ts`; live STS verification pending |
| Prompt 05 rule/findings engine | INTEGRATION_VERIFIED | `test/security-rules.test.ts`, `test/security.integration.test.ts` |
| Prompt 06 scan lifecycle | INTEGRATION_VERIFIED | `test/m03-orchestrator.integration.test.ts` |
| Prompt 07 evidence integrity | TEST_VERIFIED | `test/evidence.test.ts`, `test/evidence.integration.test.ts`; live S3/WORM pending |
| Prompt 08 control slice | TEST_VERIFIED | `test/root-mfa-control.test.ts`, `test/m06-root-mfa.integration.test.ts`; real AWS pending |

## Gate interpretation

`TEST_VERIFIED` and `INTEGRATION_VERIFIED` are not `LIVE_VERIFIED`. No fixture,
test AWS client, dashboard render, or HTTP 200 is used as external-provider
proof.

## Verification record — 2026-08-20

- **Commit SHA:** `f62dcbb9a4404b33dc5583bff0f84448bf7f20f2`
- **Environment class:** Replit development environment with managed
  PostgreSQL; Node.js `v24.13.0`; `DATABASE_URL` was not written to this file.
- **Clean install:** `npm ci` completed at
  `2026-08-20T10:26:40Z` with exit code `0`. The first pre-runtime check used
  Node 20 and emitted `EBADENGINE`; the install was repeated under the
  required Node 24 runtime and is the authoritative result.
- **Typecheck:** `npm run typecheck` completed at `2026-08-20T10:28:21Z`,
  exit code `0`, zero compiler errors.
- **Build:** `npm run build` completed at `2026-08-20T10:28:31Z`, exit code
  `0`; `dist/` contained 111 files and 750217 bytes.
- **Tests before migration:** the unmodified suite recorded 32 tests, 25
  passed, 7 failed, 0 skipped because the target database had no Prisma
  tables. The failures were recorded rather than suppressed.
- **Migration before state:** database was reachable; public table query
  returned no tables and `_prisma_migrations` did not exist.
- **Migration deploy:** `npm run prisma:migrate:deploy` completed at
  `2026-08-20T10:29:08Z`, exit code `0`; all 13 checked-in migrations were
  applied.
- **Migration after state:** public tables were present for `AuditEvent`,
  `AwsAccount`, `AwsConnection`, `AwsRegion`, `AwsResource`, `CapabilityRecord`,
  `ControlResult`, `DiscoveryRun`, `DomainEvent`, `Evidence`,
  `EvidenceLegalHold`, `IdempotencyRecord`, `Invitation`, `Membership`,
  `ObservedFact`, `Organization`, `ScanCheckOutcome`, `ScanEvent`, `ScanJob`,
  `ScanSchedule`, `SecurityFinding`, `SecurityScanRun`, `Session`, `User`, and
  `_prisma_migrations`. The latest migration was
  `20260814170000_m06_root_mfa_control`, with `applied_steps_count=1` and no
  rollback timestamp.
- **Migration status:** `npm run prisma:status` completed at
  `2026-08-20T10:29:22Z`, exit code `0`; schema was up to date.
- **Tests after migration:** the unmodified suite recorded 55 tests, 55
  passed, 0 failed, 0 skipped, exit code `0`, completed at
  `2026-08-20T10:29:34Z`.
- **Health runtime:** `/health/live` returned HTTP 200 with correlation ID
  `7260cca8-d597-4e93-966b-076ce8715d05`. `/health/ready` returned HTTP 200
  with database `pass` and correlation ID
  `2c6c31b8-1be7-4f52-8a51-e5311932b6b3` (the response captured by the
  runtime used correlation ID `2c6c31b8-1be7-4f52-8a51-e5311932b6b3`).
- **Health negative test:** an isolated process with an unreachable database
  returned HTTP 503 and `DEPENDENCY_ERROR`, correlation ID
  `3ea00fe1-157f-42ad-914f-50d70365f399`. It did not return readiness/pass.
- **Production configuration rejection:** removing `SESSION_SECRET` caused
  `npm start` to exit `1` with
  `CONFIGURATION_ERROR: Required production configuration is missing:
  SESSION_SECRET`. Setting `AUTH_PROVIDER=clerk` without `CLERK_SECRET_KEY`
  likewise exited `1` with the corresponding configuration error. No secret
  value was printed.
- **Workflow/hosting:** the `Start application` workflow ran `npm run dev`,
  listened on port 5000, and emitted a structured `application.started`
  record. CI was aligned to the required Node 24 runtime.

### Gate A status after this record

The foundation requirements above are **PASS** with the evidence recorded
here. Gate A remains **NOT PASSED overall** and no capability is promoted to
`LIVE_VERIFIED`, because the external identity provider, live AWS STS,
provider-backed evidence storage/Object Lock, isolated backup/restore target,
and a real migration rollback/recovery drill were not available or safely
executable in this environment. These remain `VERIFICATION_REQUIRED` or
blocked as documented in `DOC/CAPABILITY-REGISTRY.md`,
`DOC/KNOWN-LIMITATIONS.md`, and `DOC/BACKUP-RESTORE.md`.