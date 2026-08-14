# Environment Contract

Values are read from the process environment. No secrets belong in source control.

| Variable | Scope | Required | Purpose / format |
| --- | --- | --- | --- |
| `NODE_ENV` | development, test, production | Optional; defaults to `development` | Exact value: `development`, `test`, or `production`. |
| `DATABASE_URL` | development, test, production | Required when database-backed runtime/tests are used; required in production | PostgreSQL connection URL. Never log or expose this value. |
| `SESSION_SECRET` | development, test, production | Required in production | Session configuration secret; never log or expose it. |
| `AUTH_PROVIDER` | development, test, production | Optional; defaults to `dev` | `dev` adapter for local verification or `clerk` for the isolated provider boundary. |
| `CLERK_SECRET_KEY` | development, test, production | Required when `AUTH_PROVIDER=clerk` in production | Provider credential; never commit or log it. |
| `SESSION_TTL_SECONDS` | development, test, production | Optional; defaults to 28800 | Positive session lifetime in seconds. |
| `PORT` | development, test, production | Optional; defaults to `5000` | Integer from 1 to 65535. |
| `HOST` | development, test, production | Optional; defaults to `0.0.0.0` | Bind host for the HTTP process. |
| `LOG_LEVEL` | development, test, production | Optional; defaults to `info` | Exact value: `debug`, `info`, `warn`, or `error`. |
| `AWS_REGION` | development, test, production | Optional | Default region for the AWS SDK provider chain; discovery uses AWS `DescribeRegions` as its source of truth. |

Production fails fast with a configuration error if `DATABASE_URL` is absent. Database-backed readiness is checked when the variable is configured. `.env.example` contains no real credentials.

AWS credentials are intentionally not listed as application secrets. AWS SDK v3
uses its default provider chain and the application does not persist or accept
raw credential material. A live AWS connection requires an external provider
and the least-privilege IAM policy documented in `DOC/AWS-INTEGRATION.md`.