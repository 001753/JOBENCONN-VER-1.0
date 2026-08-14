# M-03 Contract

## Lifecycle

`QUEUED -> RUNNING -> COMPLETED | PARTIAL | FAILED`, with
`RUNNING -> CANCELLING -> CANCELLED`. Unsafe or exhausted work terminates in
`DEAD_LETTER`. Recovery from an expired lease returns work to `QUEUED`; replay
of a dead letter is an operator follow-up, not an implicit state mutation.

Only the PostgreSQL-backed worker may enter execution and terminal states.
HTTP clients can request a scan, cancel it, and read status/progress.

## API

- `POST /security/accounts/:accountId/scans`
- `GET /security/accounts/:accountId/scans?page=&pageSize=&status=&from=&to=`
- `GET /security/scans/:scanId`
- `GET /security/scans/:scanId/progress`
- `POST /security/scans/:scanId/cancel`
- `GET /security/queue`

Create returns HTTP 202 with `id`, `status`, `correlationId`, and server
timestamps. Idempotency is organization/account scoped and backed by a
database unique constraint. Reusing a key with a different inventory
fingerprint returns conflict.

## Persistence and safety

All queue/run/outcome/event reads require organization scope. `activeKey`
prevents two active runs for one integration. Worker claims use conditional
database updates, leases expire, and another worker can recover expired work.
Credentials never enter scan rows, outcomes, events, audit metadata, or logs.

## Completion boundary

The worker writes one of `ScanCompleted`, `ScanPartial`, `ScanFailed`, or
`ScanCancelled` to `ScanEvent` with a correlation ID. Delivery is intentionally
owned by the future notification module.