# M-03 Test Matrix

| Area | Verification |
|---|---|
| State transitions | `test/scan-orchestration.test.ts` |
| Invalid transition | `test/scan-orchestration.test.ts` |
| Progress and 99% ceiling | `test/scan-orchestration.test.ts` |
| Retry classification/backoff | `test/scan-orchestration.test.ts` |
| Retry 429/500/503/timeout and retry exhaustion | `test/m03-orchestrator.integration.test.ts` |
| 401/403 no-retry behavior | `test/m03-orchestrator.integration.test.ts` |
| Idempotency and tenant isolation | Existing PostgreSQL security integration test |
| Atomic claim with two workers | `test/m03-orchestrator.integration.test.ts` |
| Expired lease recovery and attempt accounting | `test/m03-orchestrator.integration.test.ts` |
| Queued/running cancellation race | `test/m03-orchestrator.integration.test.ts` |
| Dead-letter visibility, operator replay, append-only events | `test/m03-orchestrator.integration.test.ts` |
| Circuit-breaker threshold | `test/m03-orchestrator.integration.test.ts` |
| Cursor pagination and stable no-duplicate pages | `test/m03-orchestrator.integration.test.ts` |
| Schedule persistence, trigger, pause, tenant scope | `test/m03-orchestrator.integration.test.ts` |
| MEMBER create/cancel/replay denial | `test/m03-orchestrator.integration.test.ts` |
| Durable schema/migration | `npx prisma migrate deploy` |
| Build/type safety | `npm run typecheck`, `npm run build` |
| Queue/lease runtime | `ScanWorker` uses conditional PostgreSQL claim, heartbeat, and lease expiry recovery |

The integration suite is run against the configured PostgreSQL database. The
worker tests use a deterministic provider-boundary executor; live AWS behavior
is not fabricated by tests.