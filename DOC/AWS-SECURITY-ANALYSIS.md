# AWS Security Analysis and Findings

Prompt 05 adds a deterministic analysis layer on top of the existing normalized
`AwsResource` inventory. It does not make AWS calls, mutate AWS resources, or
claim compliance certification.

## Architecture

`AwsResource` snapshot → trusted rule registry → in-memory evaluation →
transactional finding lifecycle persistence.

Rules are application code (`src/security-rules.ts`), not database or
user-supplied executable content. Every rule has a stable ID, version, declared
resource type, severity, evidence builder, and recommendation.

The initial registry contains:

| Rule | Resource | Severity | Evidence boundary |
| --- | --- | --- | --- |
| `AWS-SEC-001` | S3 bucket | HIGH | Explicit encryption metadata; otherwise `INSUFFICIENT_EVIDENCE` |
| `AWS-SEC-002` | IAM account summary | HIGH | `summaryMap.AccountMFAEnabled` |
| `AWS-SEC-003` | IAM account summary | CRITICAL | `summaryMap.AccountAccessKeysPresent` |
| `AWS-SEC-004` | EC2 instance | HIGH | Explicit public-address metadata |

An evaluation is `PASS`, `FAIL`, `NOT_APPLICABLE`, or
`INSUFFICIENT_EVIDENCE`. Missing fields never become a security failure.

## Findings and lifecycle

Findings are organization-scoped and uniquely identified by organization, rule
and version, AWS account, region, and external resource ID. Re-running the same
inventory updates `lastDetectedAt` and evidence rather than creating a second
row. A resolved violation reopens the same row. A finding that no longer
violates a rule is resolved and retained; acknowledged findings remain
acknowledged while the violation is still present.

Machine-readable evidence is persisted with each finding. It contains inventory
values only; credentials, authorization headers, session tokens, and secret
values are not accepted as part of the analysis or audit metadata. The finding
links to the source `AwsResource`, the latest known `DiscoveryRun`, and the
`SecurityScanRun`.

## Scan lifecycle and idempotency

`SecurityScanRun` uses the existing discovery lifecycle vocabulary:
`RUNNING`, `COMPLETED`, `PARTIAL`, and `FAILED`. A scan is `PARTIAL` when any
resource lacks evidence or a rule execution fails. Metrics include total,
evaluated, insufficient-evidence, failed resources, evaluated rules, findings
created, and findings resolved.

Without an explicit key, the service derives an idempotency key from a
canonicalized inventory snapshot and active rule versions. An explicit key is
also scoped to organization and account and cannot be reused for a different
snapshot.

## Protected API

All routes require an authenticated session, active organization membership,
the applicable existing RBAC permission, and organization-scoped database
queries. Mutations require the existing CSRF header.

- `POST /security/accounts/:accountId/scans`
- `GET /security/accounts/:accountId/scans`
- `GET /security/scans/:scanId`
- `GET /security/findings` with `severity`, `status`, `ruleId`,
  `resourceType`, `awsAccountId`, `region`, `page`, and `pageSize`
- `GET /security/findings/:findingId`
- `POST /security/findings/:findingId/acknowledge`
- `POST /security/findings/:findingId/resolve` with a required `reason`

Finding list ordering is severity priority (`CRITICAL` through `INFO`) and
then latest detection and finding ID for stable pagination. The API returns only normalized finding/resource fields,
not AWS credentials or secret material.

## Operator runbook

- **Scan gagal:** cek `GET /security/scans/:scanId`, correlation ID, dan audit
  `SCAN_FAILED`. Periksa database/provider availability lalu jalankan ulang
  dengan idempotency key baru hanya setelah penyebabnya diperbaiki.
- **Provider permission failure:** jangan menganggap hasil sebagai `PASS`.
  Perbaiki IAM policy sesuai `DOC/AWS-INTEGRATION.md`, ulangi discovery, lalu
  ulangi scan.
- **Insufficient evidence:** lengkapi field inventory yang disebut
  `requiredEvidence` pada rule; hasil ini tetap `PARTIAL`, bukan `FAIL`.
- **Partial scan:** gunakan `totalResources`, `evaluatedResources`,
  `insufficientEvidence`, `failedResources`, dan `ruleErrors` untuk menentukan
  cakupan sebelum mengambil keputusan.
- **Duplicate prevention:** gunakan kembali idempotency key untuk retry request
  yang sama. Key yang sama untuk snapshot berbeda ditolak dengan `CONFLICT`.
- **Finding stuck state:** periksa status scan dan event audit berdasarkan
  `scanRunId`; jangan menghapus finding historis. Resolve manual memerlukan
  alasan operator dan tercatat atomically bersama mutasinya.
- **Database failure:** anggap hasil tidak berhasil sampai status scan dan audit
  dapat diverifikasi; perbaiki koneksi/migration dan ulangi operasi dengan key
  yang sesuai.

## Known limitations

- Prompt 04.A inventory does not yet collect S3 encryption, EC2 public-address,
  or all IAM posture fields. Those rules therefore correctly report
  `INSUFFICIENT_EVIDENCE` until the inventory contains the field.
- Scans run in the HTTP process; no worker queue or scheduler is introduced.
- Rule evaluation is not a compliance certification or a remediation action.
- Live AWS verification still depends on an available AWS credential provider.