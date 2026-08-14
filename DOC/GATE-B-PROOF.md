# Gate B Proof

## Result

**Gate B: NOT PASSED.**

The first real AWS control is implemented and PostgreSQL-backed tests prove the
vertical-slice behavior with a test-only provider boundary. The hard Gate B
requirements that depend on an authorized AWS account have not been proven in
this environment.

## Requirement matrix

| Gate B requirement | Result | Evidence / limitation |
|---|---|---|
| AWS integration verified | NOT PROVEN | No authorized AWS provider was available |
| Credential and account identity verified | NOT PROVEN | No live STS `GetCallerIdentity` proof |
| One real AWS check executed | NOT PROVEN | No live IAM `GetAccountSummary` observation |
| Permission matrix | IMPLEMENTED | `DOC/completion/M-06/provider-check.md`; `iam:GetAccountSummary` |
| Immutable evidence | TEST_VERIFIED | Evidence service and PostgreSQL integration tests; live S3 WORM pending |
| Evidence hash re-verification | TEST_VERIFIED | Corruption drill and integrity failure tests |
| Deterministic finding/control projection | TEST_VERIFIED | `src/root-mfa-control.ts` and M-06 integration test |
| Freshness and coverage fields | IMPLEMENTED / TEST_VERIFIED | `ControlResult` schema and root-MFA contract |
| Permission-negative behavior | TEST_VERIFIED | Provider errors become error/insufficient evidence, never PASS |
| Cross-tenant negative behavior | TEST_VERIFIED | M-06 integration test |
| Provider error is not PASS | TEST_VERIFIED | Root-MFA evaluator and security tests |
| Incomplete/stale evidence is not PASS | TEST_VERIFIED | Evidence and security rule tests |
| Dashboard is server projection | TEST_VERIFIED | Protected API routes and explicit no-data/unauthenticated UI state |
| Controlled-account manual comparison | NOT PROVEN | Requires an authorized disposable AWS account |
| Proof record | PARTIAL | Contract/provider dossier exists; no live proof record generated |

## First control contract

The implemented control is:

- Check ID: `AWS-IAM-ROOT-MFA`
- Version: `1`
- Evaluator version: `1`
- Provider/service: AWS IAM
- Operation: `GetAccountSummary`
- Required permission: `iam:GetAccountSummary`
- Resource scope: AWS account root MFA state
- Evidence: immutable, canonicalized, SHA-256 content-addressed evidence linked
  to the control result

These are implementation and test facts, not a live AWS claim.

## Promotion condition

Do not change this document to `PASS` until a controlled run supplies:

1. STS account identity and region;
2. successful read-only IAM observation;
3. persisted evidence and re-verification hash;
4. deterministic control result and API projection;
5. permission-denied and tenant-isolation negative proof; and
6. a dated proof record that can be compared with the controlled account.