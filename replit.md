# JOBEN Enterprise

## Project overview

Greenfield TypeScript/Node repository baseline for JOBEN Enterprise. The current
scope is Master Prompt 01 / P0 foundation only. Business features are
intentionally deferred and must not be represented by fake routes or success
responses.

## Development preferences

- Preserve the existing stack and keep changes inside the active master prompt.
- Prefer deterministic, dependency-light implementations.
- Treat server state as authoritative; do not make UI state a source of truth.
- Never commit secrets or use fake production credentials.
- Verify every claimed capability with a repeatable command or test.

See `DOC/P0-READINESS.md` and `DOC/CAPABILITY-REGISTRY.md` for the current
boundary and status.