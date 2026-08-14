# Capability Registry

State model: `PLANNED`, `NOT_IMPLEMENTED`, `EXPERIMENTAL`, `DEMO`,
`LIVE_VERIFIED`, plus the foundation-only states `IMPLEMENTED` and `VERIFIED`.
`LIVE_VERIFIED` requires the acceptance gate from the PRD/roadmap; availability
of a function, route, mock, fixture, seed, or HTTP 200 is not sufficient.

| Capability ID | Name | Phase | Module | State | Source of truth | Implementation status | Verification status | Limitation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `DATABASE_PERSISTENCE_FOUNDATION` | PostgreSQL persistence baseline | P0 / WP-02 | persistence | VERIFIED | Master Prompt 02 | Implemented | Migration and integration tests | Requires configured PostgreSQL |
| `PRISMA_MIGRATION_BASELINE` | Versioned Prisma migrations | P0 / WP-02 | persistence | VERIFIED | Master Prompt 02 | Implemented | Migration status and clean migration application | Production uses `prisma migrate deploy` |
| `SCOPED_REPOSITORY_FOUNDATION` | Explicit customer/system repository scope | P0 / WP-02 | persistence | VERIFIED | Master Prompt 02 | Implemented | Tenant isolation tests | Authentication and authorization remain Prompt 03 |
| `AUDIT_PERSISTENCE` | Append-oriented audit persistence | P0 / WP-02 | audit | VERIFIED | Master Prompt 02 | Implemented | Append and atomicity tests | No normal update/delete path |
| `IDEMPOTENCY_PERSISTENCE` | Idempotency record persistence | P0 / WP-02 | persistence | VERIFIED | Master Prompt 02 | Implemented | Duplicate claim and concurrency tests | Future workflows must call the repository |
| `BACKUP_RESTORE_SMOKE` | Backup/restore operator foundation | P0 / WP-02 | operations | IMPLEMENTED | Master Prompt 02 | Documented | Blocked pending isolated restore target | No production-grade DR claim |
| `FOUNDATION.CONFIG` | Environment contract and validation | P0 / WP-01 | foundation | VERIFIED | Master Prompt 01 §7–8 | Implemented | Unit-tested, including production failure | Does not load secrets or connect to external services |
| `FOUNDATION.HTTP` | HTTP server boundary | P0 / WP-01 | foundation | VERIFIED | Master Prompt 01 §9–11 | Implemented | Startup and endpoint tests | No business routes |
| `FOUNDATION.LOGGING` | Structured logging and redaction | P0 / WP-01 | foundation | VERIFIED | Master Prompt 01 §10, §15 | Implemented | Redaction test | No centralized remote sink |
| `FOUNDATION.CI` | Deterministic install, typecheck, test, build | P0 / WP-01 | engineering | VERIFIED | Master Prompt 01 §3, §13 | Implemented | Local commands and CI definition | CI execution depends on repository provider |
| `IDENTITY_FOUNDATION` | Identity and session management | Prompt 03 | identity | VERIFICATION_REQUIRED | Master Prompt 03 | Provider boundary, local provisioning, durable sessions, CSRF, revoke/rotate implemented | Unit/build evidence; PostgreSQL/provider verification required | Clerk is not live-connected |
| `ORGANIZATION` | Multi-organization model | P0 / WP-02 | organization | IMPLEMENTED | Master Prompt 02 | Persistence only | Repository and schema tests | Auth and lifecycle workflows deferred |
| `AUTHORIZATION` | RBAC and tenant isolation | Prompt 03 | authorization | VERIFICATION_REQUIRED | Master Prompt 03 | Centralized RBAC, active membership/org checks, scoped route boundary implemented | PostgreSQL integration evidence required | No system-admin UI or future modules |
| `TENANT_ISOLATION` | Server-side organization isolation | Prompt 03 | authorization | VERIFICATION_REQUIRED | Master Prompt 03 | Actor + membership + organization context required before protected reads | PostgreSQL integration evidence required | No customer resource modules yet |
| `RBAC` | Organization-scoped roles and permissions | Prompt 03 | authorization | VERIFICATION_REQUIRED | Master Prompt 03 | OWNER/ADMIN/MEMBER/VIEWER matrix and centralized guards | PostgreSQL integration evidence required | Matrix is application-core scope |
| `INVITATION_LIFECYCLE` | Idempotent invitation workflow | Prompt 03 | identity | VERIFICATION_REQUIRED | Master Prompt 03 | Digest, expiry, revoke, atomic accept, replay protection | PostgreSQL integration evidence required | Delivery channel deferred |
| `MEMBERSHIP_LIFECYCLE` | Membership state and access lifecycle | Prompt 03 | authorization | VERIFICATION_REQUIRED | Master Prompt 03 | Active/suspended/removed checks, role changes, session revocation | PostgreSQL integration evidence required | UI deferred |
| `OWNERSHIP_TRANSFER` | Concurrency-safe owner transfer | Prompt 03 | authorization | VERIFICATION_REQUIRED | Master Prompt 03 | Serializable transaction and last-owner invariant | PostgreSQL integration evidence required | Production load test deferred |
| `AUDIT_AUTHORIZATION` | Authorization and security audit integration | Prompt 03 | governance | VERIFICATION_REQUIRED | Master Prompt 03 | Durable success/denial audit with correlation ID and metadata safety | PostgreSQL integration evidence required | Remote sink deferred |
| `SYSTEM_ADMIN_BOUNDARY` | Explicit system/customer context separation | Prompt 03 | authorization | VERIFICATION_REQUIRED | Master Prompt 03 | Separate system/customer contexts in repository and auth contracts | Build/integration evidence | No superadmin product workflow requested |
| `PROVIDER` | Cloud/source provider adapters | Future | provider | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | No AWS/GitHub integration |
| `SCAN` | Scan orchestration and workers | Future | scan | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | No queue or scanner |
| `EVIDENCE` | Evidence and control evaluation | Future | evidence/control | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | No compliance or evidence engine |
| `FINDING` | Finding lifecycle | Future | finding | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | No finding API |
| `REMEDIATION` | Remediation workflows | Future | remediation | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | Deferred |
| `REPORT` | Report generation | Future | report | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | Deferred |
| `NOTIFICATION` | Notifications | Future | notification | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | Deferred |
| `BILLING` | Billing and subscriptions | Future | billing | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | Deferred |
| `AI` | AI Gateway | Future | AI | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | Deferred |
| `GOVERNANCE` | Governance, audit, and trust surfaces | Future | governance | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | No audit/trust portal |