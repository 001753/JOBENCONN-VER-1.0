# Capability Registry

State model: `PLANNED`, `NOT_IMPLEMENTED`, `EXPERIMENTAL`, `DEMO`,
`LIVE_VERIFIED`, plus the foundation-only states `IMPLEMENTED` and `VERIFIED`.
`LIVE_VERIFIED` requires the acceptance gate from the PRD/roadmap; availability
of a function, route, mock, fixture, seed, or HTTP 200 is not sufficient.

| Capability ID | Name | Phase | Module | State | Source of truth | Implementation status | Verification status | Limitation |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `FOUNDATION.CONFIG` | Environment contract and validation | P0 / WP-01 | foundation | VERIFIED | Master Prompt 01 §7–8 | Implemented | Unit-tested, including production failure | Does not load secrets or connect to external services |
| `FOUNDATION.HTTP` | HTTP server boundary | P0 / WP-01 | foundation | VERIFIED | Master Prompt 01 §9–11 | Implemented | Startup and endpoint tests | No business routes |
| `FOUNDATION.LOGGING` | Structured logging and redaction | P0 / WP-01 | foundation | VERIFIED | Master Prompt 01 §10, §15 | Implemented | Redaction test | No centralized remote sink |
| `FOUNDATION.CI` | Deterministic install, typecheck, test, build | P0 / WP-01 | engineering | VERIFIED | Master Prompt 01 §3, §13 | Implemented | Local commands and CI definition | CI execution depends on repository provider |
| `IDENTITY` | Identity and session management | Future | identity | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | Deferred to a later master prompt |
| `ORGANIZATION` | Multi-organization model | Future | organization | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | No schema exists yet |
| `AUTHORIZATION` | RBAC and tenant isolation | Future | authorization | PLANNED | JOBEN PRD / roadmap | Not implemented | Not verified | No auth boundary implementation yet |
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