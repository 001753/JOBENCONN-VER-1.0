# M-03 Proof Record

## Status

`IMPLEMENTED` and `TEST_VERIFIED` for the defined M-03 orchestration scope.
`LIVE_VERIFIED` is not claimed for AWS because no live AWS provider credentials
were available for this proof run.

## Verified

- Node/TypeScript build succeeds.
- Prisma schema validates and all 10 official migrations are applied; migration
  status is up to date.
- Full suite passes: 40 tests, including the real PostgreSQL M-03 integration
  proof suite.
- Two-worker atomic claim, expired lease recovery, retry/dead-letter, replay,
  queued/running cancellation race, circuit-breaker threshold, cursor
  pagination, schedule trigger/pause, and MEMBER RBAC are verified.
- Scan completion remains server/worker authoritative; HTTP creation returns
  `202 QUEUED`.
- Correlation IDs and append-only `ScanEvent` records are retained through
  retry, cancellation, and replay.

## Evidence

Run:

```sh
npm run typecheck
npm test
npx prisma generate
npx prisma validate
npx prisma migrate status
npx prisma migrate deploy
npm run dev
curl -i http://localhost:5000/health/live
curl -i http://localhost:5000/health/ready
```

## Known limitations

- Live AWS STS/provider execution is `VERIFICATION_REQUIRED`; tests use the
  existing provider boundary and do not fabricate AWS success.
- No frontend or dead-letter dashboard UI is in M-03. Operators use the
  protected history/status and replay routes.
- Calendar scheduling is a deterministic due-schedule service path with
  timezone-aware next-run calculation; a distributed scheduler is not part of
  this module.