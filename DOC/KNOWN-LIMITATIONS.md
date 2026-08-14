# Known Limitations After Prompt 01–08 Audit

These limitations are intentionally explicit. None is converted into a fake
success state.

## External verification pending

1. **AWS live verification:** no authorized AWS provider was available during
   this audit. STS identity, IAM root-MFA observation, live resource discovery,
   and controlled-account comparison remain pending.
2. **Evidence object storage:** the deterministic in-memory storage adapter is
   `TEST_VERIFIED`. Live S3 encryption, versioning, retention, and Object Lock
   have not been verified.
3. **Identity provider:** the development identity adapter is explicit and
   disabled in production. Clerk/provider connection and live authentication
   acceptance proof remain pending.

## Scope boundaries

1. No Prompt 09+ decision/control expansion, remediation, reports, billing,
   GitHub provider, governance product, or AI capability was implemented.
2. Backup/restore is documented as an operator foundation; no production-grade
   disaster-recovery claim is made.
3. Logging is structured and redacted locally; no centralized remote sink is
   claimed.
4. Dashboard values are server-derived. With no authenticated organization or
   scan data, the UI states that data is unavailable rather than showing
   zero-risk, a score, a finding, or a compliance result.

## Required next proof

Run a controlled, read-only AWS verification in an environment with authorized
credentials and the required `iam:GetAccountSummary` permission. Record the
provider observation, evidence hash, result, freshness, coverage, errors, and
negative tests before considering Gate B.