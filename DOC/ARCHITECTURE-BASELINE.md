# JOBEN Architecture Baseline

Status: **P0 foundation implemented; business capabilities are not implemented.**

## Runtime authority

- **Server** is the authority for request handling and capability status.
- **PostgreSQL** is the durable relational store. Prisma migrations and typed persistence repositories provide the database boundary introduced by Master Prompt 02.
- **External providers** will be observation sources behind adapters; no provider is connected in this baseline.
- **UI** is not present and must not become a source of truth.

## Layers and boundaries

The baseline owns runtime foundation concerns: configuration, HTTP boundary, error taxonomy, structured logging, health endpoints, and the migration-first persistence foundation.

The following conceptual boundaries are reserved without fake implementations:

`IDENTITY`, `AUTHORIZATION`, `PROVIDER`, `SCAN`, `EVIDENCE`, `CONTROL`, `FINDING`, `REMEDIATION`, `REPORT`, `NOTIFICATION`, `BILLING`, `AI`, `GOVERNANCE`.

Persistence models for identity references, organizations, memberships,
invitations, audits, capabilities, and idempotency now exist. Authentication,
authorization semantics, and workflows remain deferred.

Future work must keep tenant isolation, RBAC, auditability, provider adapters, scan orchestration, deterministic evaluation, evidence, remediation, billing, and AI Gateway behind server-owned boundaries.

## Health behavior

- `GET /health/live` proves only that the process can answer.
- `GET /health/ready` proves configuration is valid and checks PostgreSQL when `DATABASE_URL` is configured.
- With no `DATABASE_URL` in an explicit development/test process, readiness reports `not_configured` rather than inventing a database success.

## Security baseline

The server applies safe response headers, caps declared request bodies at 1 MiB, never logs request bodies, redacts sensitive log keys, and returns generic internal errors. This is a foundation, not a claim of complete enterprise security or production security.

## Commands

```sh
npm ci
npm run typecheck
npm test
npm run build
npm start
```