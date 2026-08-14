# M-06 provider/check dossier

| Field | Value |
|---|---|
| checkId | `AWS-IAM-ROOT-MFA` |
| checkVersion | `1` |
| evaluatorVersion | `1` |
| provider | AWS |
| service | IAM |
| operation | `GetAccountSummary` |
| action/permission | `iam:GetAccountSummary` |
| purpose | Read the authoritative account-level root MFA state |
| risk | Read-only account metadata; no AWS mutation |
| API source/revision | AWS IAM API Reference — GetAccountSummary, https://docs.aws.amazon.com/IAM/latest/APIReference/API_GetAccountSummary.html |
| sandbox verification | `NOT_RUN` — no disposable AWS credentials available |
| fixture | `test/root-mfa-control.test.ts`; `test/m06-root-mfa.integration.test.ts` |
| capability state | `VERIFICATION_REQUIRED` |
| live proof | Not generated; no fabricated account, result, screenshot, or hash |
| re-verification | Required before promoting to `LIVE_VERIFIED` |

The minimum permission is intentionally narrower than the full discovery
permission set. Access denied is recorded as insufficient evidence/error, never
as PASS or FAIL.