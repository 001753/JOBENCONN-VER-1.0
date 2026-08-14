# Environment Contract

Values are read from the process environment. No secrets belong in source control.

| Variable | Scope | Required | Purpose / format |
| --- | --- | --- | --- |
| `NODE_ENV` | development, test, production | Optional; defaults to `development` | Exact value: `development`, `test`, or `production`. |
| `DATABASE_URL` | production | **Required in production** | PostgreSQL connection URL. Not used for connectivity in this baseline; database work is deferred. |
| `SESSION_SECRET` | development, test, production | Optional in P0 | Reserved secret for future identity/session work. Never use an example value. |
| `PORT` | development, test, production | Optional; defaults to `5000` | Integer from 1 to 65535. |
| `HOST` | development, test, production | Optional; defaults to `0.0.0.0` | Bind host for the HTTP process. |
| `LOG_LEVEL` | development, test, production | Optional; defaults to `info` | Exact value: `debug`, `info`, `warn`, or `error`. |

Production fails fast with a configuration error if `DATABASE_URL` is absent. Development and test do not invent a database dependency because no database implementation exists in P0. `.env.example` contains no real credentials.