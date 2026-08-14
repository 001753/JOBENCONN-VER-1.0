# Core Data Model

All timestamps are PostgreSQL `timestamptz(3)` values and are returned as UTC
instants by Prisma.

| Entity | Purpose | Tenant scope |
| --- | --- | --- |
| `User` | Stable application identity reference | Global identity; not a tenant |
| `Organization` | Primary customer boundary | Root tenant |
| `Membership` | User-to-organization relationship, role reference, status, version | Required organization |
| `Invitation` | Pending organization invitation reference | Required organization; token digest only |
| `AuditEvent` | Durable append-oriented security/business record | Optional organization for system events |
| `CapabilityRecord` | Capability state and verification evidence reference | Optional organization |
| `IdempotencyRecord` | Duplicate mutation guard and result reference | Explicit organization or system scope |

Foreign keys enforce references and restrict deletion of organizations/users
that still own core records, except nullable actor/reference fields that use
`SET NULL`. Important uniqueness and lookup indexes are database constraints,
not frontend validation.

Capability records may contain `LIVE_VERIFIED` as a stored state for future
verification records, but Prompt 02 does not automatically create or promote
any capability to that state.