# M-06 / Prompt 08 — Root MFA control

## Status

**VERIFICATION_REQUIRED** — implementation and PostgreSQL-backed contract tests
are complete. Live AWS verification is pending because no disposable AWS
account and credentials were available in this environment.

This dossier does not claim AWS live verification, SOC 2 compliance, or
certification.

## Implemented vertical slice

`AWS GetAccountSummary -> AWS adapter -> ScanRun/ScanJob worker -> redacted
schema-validated evidence -> JCS-1/SHA-256 verification -> deterministic
Root MFA evaluator -> ControlResult -> ScanCheckOutcome -> audit/domain events
-> protected API -> live-data dashboard`.

The stable control identity is `AWS-IAM-ROOT-MFA`, check version `1`, evaluator
version `1`, resource key `aws-account:{12-digit-account-id}:root-mfa`.

## Provider contract

- Provider/service: AWS IAM
- Operation: `IAM.GetAccountSummary`
- Minimum permission: `iam:GetAccountSummary`
- Authoritative field: `SummaryMap.AccountMFAEnabled` (`0` disabled, `1` enabled)
- Source: [AWS IAM GetAccountSummary API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html)
- Error behavior: authorization is `PERMISSION_DENIED`; throttling and bounded
  transient service/network errors follow the existing retry policy; malformed
  responses are `SCHEMA_DRIFT`; evidence commit/integrity failures cannot pass.

The adapter uses the existing AWS SDK v3 client and does not store or expose
credential material.

## Result and UI boundary

PASS/FAIL/ERROR are persisted with evidence reference, hash, observed time,
coverage, data quality, check/evaluator version, provider source revision,
scan/outcome lineage, organization scope, and correlation ID. FAIL includes a
read-only remediation reference; JOBEN never mutates AWS in this slice.

The dashboard reads `/dashboard/summary`, `/security/controls`,
`/security/accounts/{id}/scans`, `/search`, and evidence APIs. It does not
invent scores, findings, evidence, or live status. Compliance scoring remains
explicitly not calculated until the next control-system phase.

## Verification record

- Unit contract/evaluator tests: `test/root-mfa-control.test.ts`
- PostgreSQL vertical-slice tests: `test/m06-root-mfa.integration.test.ts`
- Existing M-03/M-05 integration and security tests: passing
- Migration: `20260814170000_m06_root_mfa_control`
- Runtime: `/health/live`, `/health/ready`, and `/dashboard`
- Live AWS proof: **not available**
- Gate B: candidate only; status remains `VERIFICATION_REQUIRED`

Reverify when a disposable AWS account is available, capturing the redacted
account identity, permission check, request operation, observation timestamp,
scan ID, evidence ID/hash, and control/evaluator versions.