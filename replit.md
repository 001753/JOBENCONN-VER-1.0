# JOBEN Enterprise

## Project overview

TypeScript/Node repository for JOBEN Enterprise. The implemented scope includes
the P0 persistence/HTTP foundation plus Prompt 03 identity, durable sessions,
organization context, tenant isolation, RBAC, invitations, membership
lifecycle, ownership protection, and audit integration.

## Development preferences

- Preserve the existing stack and keep changes inside the active master prompt.
- Prefer deterministic, dependency-light implementations.
- Treat server state as authoritative; do not make UI state a source of truth.
- Never commit secrets or use fake production credentials.
- Verify every claimed capability with a repeatable command or test.

See `DOC/P0-READINESS.md` and `DOC/CAPABILITY-REGISTRY.md` for the current
boundary and status.

## Run and verify

```sh
npm ci
npm test
npm run typecheck
npm run build
npm run dev
```

The development server listens on port 5000. Health endpoints are public:
`/health/live` and `/health/ready`. Authentication routes require PostgreSQL.
For local verification, `POST /auth/dev/session` accepts the
`x-dev-identity` and optional `x-dev-email` headers. This adapter is disabled
in production and is not a Clerk production claim.

Cookie-authenticated mutations require the CSRF token returned in the
`joben_csrf` cookie to also be sent as `X-CSRF-Token`. PostgreSQL-backed Prompt
03 integration tests run when `DATABASE_URL` is configured and migrations have
been applied with `npx prisma migrate deploy`.