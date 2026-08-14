# JOBEN Architecture Baseline

Status: **P0 foundation implemented; business capabilities are not implemented.**

## Runtime authority

- **Server** is the authority for request handling and capability status.
- **PostgreSQL** is the planned durable relational store. The migration and repository implementation are deferred to Master Prompt 02.
- **External providers** will be observation sources behind adapters; no provider is connected in this baseline.
- **UI** is not present and must not become a source of truth.

## Layers and boundaries

The baseline owns only runtime foundation concerns: configuration, HTTP boundary, error taxonomy, structured logging, and health endpoints.

The following conceptual boundaries are reserved without fake implementations:

`IDENTITY`, `ORGANIZATION`, `AUTHORIZATION`, `AUDIT`, `PROVIDER`, `SCAN`, `EVIDENCE`, `CONTROL`, `FINDING`, `REMEDIATION`, `REPORT`, `NOTIFICATION`, `BILLING`, `AI`, `GOVERNANCE`.

Future work must keep tenant isolation, RBAC, auditability, provider adapters, scan orchestration, deterministic evaluation, evidence, remediation, billing, and AI Gateway behind server-owned boundaries.

## Health behavior

- `GET /health/live` proves only that the process can answer.
- `GET /health/ready` proves configuration is valid and returns ready because this P0 foundation has no required external runtime dependency.
- PostgreSQL connectivity is intentionally not claimed or checked until the database work package exists.

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