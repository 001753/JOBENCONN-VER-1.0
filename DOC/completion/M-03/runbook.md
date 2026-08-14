# M-03 Recovery Runbook

## Diagnose

1. Check `GET /security/queue` within the authenticated organization.
2. Inspect `GET /security/scans/:scanId` and its correlation ID.
3. Query structured application logs using that correlation ID.
4. Check PostgreSQL migration status before treating a persistence failure as
   a worker failure.

## Stuck scan / worker crash

Leases are time bounded. A later worker reclaims a job after lease expiry,
preserving existing `ScanCheckOutcome` rows. Do not delete the run to clear a
stuck state. If the database is unavailable, restore database connectivity
first; queued state is the source of truth.

## Retry and dead letter

Transient/system failures use at most three attempts with bounded exponential
backoff. Authorization, validation, and permission failures are not retried.
An exhausted job becomes `DEAD_LETTER` and retains its last error and
correlation ID. Replay is not exposed as a casual customer action; it should be
an audited operator procedure after the cause is understood.

## Provider outage / credential revoke

Do not fabricate a result. Verify or reconnect the AWS integration using the
existing Prompt 04 flow. The circuit breaker opens after five consecutive
total failures and blocks new work while the connection is `ERROR`. A
successful re-verification returns the connection to the existing active
state.

## Queue backlog

Use the tenant-scoped backlog endpoint. Investigate oldest queued age before
increasing workers. Multi-instance workers are safe because claim and lease
assignment are conditional database operations.