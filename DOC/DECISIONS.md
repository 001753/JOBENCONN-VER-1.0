# Decisions

## ADR-001 — Keep the P0 runtime dependency-free

The HTTP foundation uses Node's built-in HTTP server and test runner. TypeScript
is the only development dependency.

**Why:** The repository is greenfield and the prompt prioritizes deterministic,
credit-efficient work. Avoiding a framework at this stage reduces dependency
and configuration surface without blocking later domain modules.

## ADR-002 — Require `DATABASE_URL` only in production

Production configuration fails fast when `DATABASE_URL` is missing. Development
and test do not connect to PostgreSQL yet.

**Why:** PostgreSQL is the durable-store architecture decision, but migrations,
repositories, and connectivity checks belong to Master Prompt 02. A local fake
database or fake health check would violate the source-of-truth rules.

## ADR-003 — Do not add business-domain placeholders that return success

Future domain boundaries are documented, not exposed as fake routes or dummy
implementations.

**Why:** A route or mock response must not be mistaken for a verified
capability. Future work must add explicit contracts and acceptance gates.

## ADR-004 — Explicit organization/system contexts and optimistic concurrency

Customer repository calls require an organization context; system operations
must opt into a separate system context. Important mutable records condition
updates on an integer `version` and return a conflict when stale.

**Why:** This keeps accidental cross-tenant reads and lost updates out of the
data-access boundary before authentication and authorization are implemented in
Prompt 03.