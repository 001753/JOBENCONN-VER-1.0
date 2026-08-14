# M-05 Security and Redaction

`redactEvidencePayload` copies nested objects and arrays without mutating the
provider response. Exact sensitive keys include authorization headers, API
keys, tokens, passwords, credential fields, private keys, webhook secrets,
session secrets, database URLs, and connection strings. Known AWS access-key,
Bearer-token, and private-key value patterns are also replaced.

The marker is `[REDACTED]`. `assertNoSensitiveEvidencePayload` is called after
redaction and before validation/canonicalization. Audit metadata contains
hashes, references, versions, and operation state only; it never contains raw
payload bytes or redacted values.

The mandatory canary test injects nested authorization, token, private-key,
webhook-secret, and credential values and proves they are absent from the
canonical object bytes and audit metadata. Structured logging uses the
existing redaction boundary.

Provider schemas are explicit (`aws.v1`, `aws-discovery.v1`, `aws-security.v1`,
and the deterministic `test.v1` fixture contract). Unknown schemas fail with
deterministic `schema_error`; they are not accepted by a permissive fallback.
