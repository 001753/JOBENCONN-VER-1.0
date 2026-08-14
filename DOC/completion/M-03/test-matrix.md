# M-03 Test Matrix

| Area | Verification |
|---|---|
| State transitions | `test/scan-orchestration.test.ts` |
| Invalid transition | `test/scan-orchestration.test.ts` |
| Progress and 99% ceiling | `test/scan-orchestration.test.ts` |
| Retry classification/backoff | `test/scan-orchestration.test.ts` |
| Idempotency and tenant isolation | Existing PostgreSQL security integration test |
| Durable schema/migration | `npx prisma migrate deploy` |
| Build/type safety | `npm run typecheck`, `npm run build` |
| Queue/lease runtime | `ScanWorker` uses conditional PostgreSQL claim and lease expiry recovery |

The available integration suite is run against the configured PostgreSQL
database. Live AWS behavior is not fabricated by tests.