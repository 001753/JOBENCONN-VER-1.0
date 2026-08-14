# Database Foundation

Status: **Prompt 02 persistence foundation implemented and verified locally.**

## Architecture

PostgreSQL is the durable source of truth. Prisma 6.19.0 provides the typed
client and versioned migration layer. `src/database.ts` owns client lifecycle:
production uses one process client, while development/test reuse a guarded
`globalThis` client to avoid hot-reload connection multiplication.

The HTTP readiness endpoint runs a sanitized `SELECT 1` check when
`DATABASE_URL` is configured. The URL is never logged, returned, or included in
audit metadata.

## Transaction and concurrency contracts

`withTransaction` exposes Prisma's transaction client to service code. A
business mutation and its required audit append can therefore share one
PostgreSQL transaction. The repository's mutable membership, invitation, and
idempotency updates condition on `version`; a stale version returns `CONFLICT`.

## Migration policy

Development:

```sh
npm run prisma:migrate:dev -- --name descriptive_change
```

Production/deployment:

```sh
npm run prisma:migrate:deploy
```

`prisma db push` is not a production migration strategy. Destructive changes
must use an expand/contract migration and document the irreversible step.

## Security boundary

Database errors are translated to safe application errors before crossing the
HTTP boundary. Audit metadata rejects common secret-bearing keys. Invitation
records store only a token digest, never an invitation secret.

## Deferred

Clerk synchronization, sessions, RBAC, membership workflows, provider data,
scan/evidence/report/billing/AI models, and full authorization are deferred to
later master prompts. No future business tables are included in this schema.