# Identity and Authentication

Status: **implemented behind a provider boundary; external provider verification required**.

## Boundary

Authentication resolves a verified external identity through `IdentityProvider`.
The application then provisions a stable local `User` projection keyed by the
unique `provider:subject` reference. Authorization never trusts a client user
ID, role, permission, or organization ID.

`DevIdentityProvider` is available only in development/test and is explicit
about being a test adapter. `ClerkIdentityProvider` is isolated and refuses to
accept unverified requests until a verified Clerk SDK adapter and provider
connection are configured. JOBEN does not store passwords or OAuth tokens.

## Session lifecycle

`SessionManager` stores only SHA-256 digests of random session and CSRF tokens.
The session cookie is HttpOnly, SameSite=Lax, Secure in production, and has a
controlled expiry. The CSRF token is a separate non-HttpOnly cookie and must be
returned in `X-CSRF-Token` for cookie-authenticated mutations. Sessions can be
created, validated, rotated, expired, revoked individually, or revoked for all
sessions belonging to a user.

Authentication states are represented by safe domain errors:
`UNAUTHENTICATED`, `SESSION_EXPIRED`, `SESSION_REVOKED`, and `FORBIDDEN`.
Every request receives or propagates an `X-Correlation-Id`.

## Minimal verification routes

- `POST /auth/dev/session` — development/test adapter only; send
  `x-dev-identity` and optional `x-dev-email`.
- `GET /auth/me` — authenticated actor and active organization projection.
- `POST /auth/switch-organization` — authenticated, CSRF-protected switch.
- `POST /auth/logout` — authenticated, CSRF-protected revocation.
- `POST /auth/invitations/accept` — verified provider identity + single-use token.

There is no UI scope in Prompt 03.