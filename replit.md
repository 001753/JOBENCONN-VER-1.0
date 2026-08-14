# JOBEN Enterprise

## Project overview

TypeScript/Node repository for JOBEN Enterprise. The implemented scope includes
the P0 persistence/HTTP foundation plus Prompt 03 identity, durable sessions,
organization context, tenant isolation, RBAC, invitations, membership
lifecycle, ownership protection, audit integration, and the M-03 scan/job
orchestrator (durable queue, worker leases, retries, cancellation, replay,
cursor history, schedules, and circuit-breaker guard).

## Development preferences

- Preserve the existing stack and keep changes inside the active master prompt.
- Prefer deterministic, dependency-light implementations.
- Treat server state as authoritative; do not make UI state a source of truth.
- Never commit secrets or use fake production credentials.
- Verify every claimed capability with a repeatable command or test.

See `DOC/P0-READINESS.md` and `DOC/CAPABILITY-REGISTRY.md` for the current
boundary and status.

## Run and verify

```sh
npm ci
npm test
npm run typecheck
npm run build
npm run dev
```

The development server listens on port 5000. Health endpoints are public:
`/health/live` and `/health/ready`. Authentication routes require PostgreSQL.
For local verification, `POST /auth/dev/session` accepts the
`x-dev-identity` and optional `x-dev-email` headers. This adapter is disabled
in production and is not a Clerk production claim.

Cookie-authenticated mutations require the CSRF token returned in the
`joben_csrf` cookie to also be sent as `X-CSRF-Token`. PostgreSQL-backed Prompt
03 and M-03 integration tests run when `DATABASE_URL` is configured and
migrations have been applied with `npx prisma migrate deploy`.

### Prompt 04.A AWS verification

The AWS adapter uses the AWS SDK v3 default credential provider chain
(environment, shared profile, or workload/IAM role). It never accepts or stores
access keys, secret keys, session tokens, or raw external IDs. An optional
`roleArn` is assumed through the official SDK provider and is verified with
`STS GetCallerIdentity` before the connection becomes active.

AWS calls use a bounded SDK request timeout and retry only throttling,
transient-network, or temporary 5xx failures. Discovery is read-only, paginated
for EC2/IAM, idempotent at the database constraint, and records region/service
partial failures without discarding successful inventory. Interrupted runs older
than the recovery window are marked failed rather than left running forever.

Run a live smoke check only in an environment with an AWS provider configured.
Create a connection through the authenticated API; the live result must come
from AWS STS. Without an available provider, live verification remains pending
and no success is fabricated. Required least-privilege actions are listed in
`DOC/AWS-INTEGRATION.md`.

### Prompt 05 AWS security analysis

The security engine reads the normalized `AwsResource` inventory and evaluates
only trusted, versioned rules in `src/security-rules.ts`. It never makes one
AWS call per rule. Findings and scan runs are organization-scoped Prisma data,
with deterministic idempotency, evidence, provenance, automatic resolve/reopen,
and audit events. See `DOC/AWS-SECURITY-ANALYSIS.md`.

Apply the Prompt 05 migration with `npx prisma migrate deploy` before using the
protected `/security/*` routes. The findings permissions are
`findings.read`, `findings.run`, `findings.acknowledge`, and `findings.resolve`;
the existing role matrix grants read-only findings access to MEMBER/VIEWER and
mutation access to OWNER/ADMIN.

### M-05 Evidence Vault

Evidence is committed through the protected `/evidence` API and is scoped to
the authenticated active organization. The available operations are:

- `POST /evidence` — redact, validate, canonicalize, hash, store, and persist
  evidence metadata plus optional `ObservedFact` records.
- `GET /evidence/:id` — read tenant-scoped metadata only.
- `GET /evidence/:id/content` — retrieve canonical bytes after a fresh
  integrity verification.
- `POST /evidence/:id/verify` — recompute the SHA-256 and publish integrity
  success/failure proof.
- `POST /evidence/:id/legal-hold` and
  `POST /evidence/legal-holds/:holdId/release` — manage retention holds.
- `POST /evidence/:id/supersede` — create an immutable successor.
- `DELETE /evidence/:id` — only eligible after retention expiry, no legal hold,
  and successful integrity verification.

All mutations require the existing CSRF token. The local deterministic storage
adapter is versioned and content-addressed for integration tests and drills;
live S3 encryption/versioning/Object Lock remains
`VERIFICATION_REQUIRED` until provider credentials and Object Lock are
verified. See `DOC/completion/M-05/README.md`.

### Imported project setup verification

The Replit workflow uses Node.js 24, PostgreSQL, and `npm run dev`. The
development database was reachable and all 13 checked-in Prisma migrations were
applied with `npx prisma migrate deploy`. Verification completed with:

- `npm test` — 55 tests passed
- `npm run typecheck` — passed
- `npm run build` — passed
- `/health/live` — HTTP 200
- `/health/ready` — HTTP 200 with PostgreSQL connectivity verified
- `/dashboard` — HTTP 200; unauthenticated state is explicit and protected
- authenticated `/dashboard/summary` — real tenant-backed data with
  `NOT_EVALUATED` / `NOT_CALCULATED` when no scan exists