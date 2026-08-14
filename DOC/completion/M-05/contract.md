# M-05 Evidence Vault & Integrity Contract

## Scope

M-05 owns the lifecycle from provider response through redaction, provider
schema validation, versioned canonicalization, SHA-256 hashing, immutable
content-addressed object storage, PostgreSQL metadata, integrity verification,
tenant authorization, audit, and domain events.

Actors are authenticated organization members, authorized operators, and
workers/services. Customer data is organization-scoped. Provider evidence and
potentially sensitive configuration metadata are classified as sensitive;
credentials, tokens, private keys, and unnecessary PII must not survive
redaction.

## Source of truth

The canonical evidence payload is in object storage. PostgreSQL contains only
the evidence metadata, object reference, retention/hold state, provenance, and
integrity state. PostgreSQL is never a second mutable copy of the payload.

The write path is:

`provider response -> redact -> provider schema validate -> canonicalize ->
SHA-256 -> immutable object write -> object verification -> metadata/event/audit
transaction`.

Observed facts are lineage only:

`Evidence -> ObservedFact -> future Finding`.

M-05 does not evaluate findings, calculate scores or compliance status, build
reports/dashboards, use AI, or perform remediation.

## M-03 boundary

Evidence may reference `SecurityScanRun` and `ScanCheckOutcome`. A failed
evidence commit updates the associated check outcome to `FAILED` with
`EVIDENCE_COMMIT_FAILED`; M-05 does not rewrite scan orchestration.
