# JOBEN Architecture Baseline

Status: **Prompts 01–08 are implemented to their tested boundaries; external provider and live-object-storage verification remains required.**

## Runtime authority

- **Server** is the authority for request handling and capability status.
- **PostgreSQL** is the durable relational store. Prisma migrations and typed persistence repositories provide the database boundary introduced by Master Prompt 02.
- **External providers** are observation sources behind adapters. The AWS adapter
  is implemented and read-only, but no live provider proof is claimed in this
  repository state.
- **PostgreSQL-backed server APIs** are the source of truth for scans, findings,
  controls, and evidence. The dashboard is a projection and must not create
  metrics or findings.

## Layers and boundaries

The baseline owns runtime foundation concerns: configuration, HTTP boundary,
error taxonomy, structured logging, health endpoints, and the migration-first
persistence foundation. Prompt 03 identity/access control, Prompt 04 AWS
discovery, Prompt 05 analysis, Prompt 06 orchestration, Prompt 07 evidence, and
Prompt 08 root-MFA control are implemented behind their documented acceptance
boundaries.

The following conceptual boundaries are reserved without fake implementations:

`PROVIDER`, `SCAN`, `EVIDENCE`, `CONTROL`, `FINDING`, `REMEDIATION`, `REPORT`, `NOTIFICATION`, `BILLING`, `AI`, `GOVERNANCE`.

Persistence models for identity references, users, organizations, memberships,
invitations, sessions, audits, capabilities, and idempotency exist. Prompt 03
adds provider, session, tenant, RBAC, invitation, ownership, and audit workflows.

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