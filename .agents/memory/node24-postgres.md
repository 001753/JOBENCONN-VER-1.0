---
name: Node 24 and PostgreSQL runtime
description: Environment-specific runtime and timestamp behavior for the JOBEN persistence foundation.
---

The Replit environment supports Node.js 24 through the `nodejs-24` module, and
Prisma 6.19.0 runs successfully on it. PostgreSQL may report its UTC timezone
as `GMT`; timestamp correctness should therefore accept either equivalent
label while verifying that persisted instants are UTC-safe.

**Why:** The repository contract requires Node 24 and UTC timestamps, while
the base environment initially exposed Node 20 and the database reports GMT.

**How to apply:** Keep the project/runtime contract at Node 24; do not
downgrade to satisfy the initial shell runtime. Treat GMT as UTC-equivalent
when validating the managed PostgreSQL environment.