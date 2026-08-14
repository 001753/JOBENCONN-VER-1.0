# M-03 Scan & Job Orchestrator

## Scope

This dossier records the first production-oriented orchestration slice for
tenant-scoped AWS security scans. `SecurityScanRun` remains the canonical run
ledger. `ScanJob` is a durable PostgreSQL queue record; `ScanCheckOutcome` is
append-only execution history; `ScanEvent` is the completion boundary for
downstream notification/report modules.

## Non-goals

- No Redis, Kafka, SQS, or global scheduler was introduced.
- No notification delivery, evidence, controls, remediation, dashboard, or
  report module was built.
- AWS credential retrieval remains exclusively in the existing AWS adapter.
- Automatic calendar scheduling is intentionally deferred until its PRD
  timezone/calendar contract is available.

## Operational status

The queue, worker, leases, recovery, retry/dead-letter path, cancellation,
replay, circuit-breaker guard, cursor history, and deterministic schedule
trigger are implemented and `TEST_VERIFIED` against PostgreSQL. A live AWS
verification is not claimed unless the AWS connection is verified by the
existing Prompt 04 flow.

See `contract.md`, `permission-matrix.md`, `test-matrix.md`, `proof-record.md`,
and `runbook.md`.