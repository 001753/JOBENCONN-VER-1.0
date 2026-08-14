# JOBEN Enterprise

Repository baseline and P0 readiness foundation for JOBEN Enterprise.

## Current scope

This greenfield repository contains only the engineering foundation: a small
TypeScript HTTP service, centralized configuration validation, safe structured
logging, error boundaries, liveness/readiness endpoints, deterministic tests,
and CI. Business capabilities are intentionally not implemented.

See [`DOC/P0-READINESS.md`](DOC/P0-READINESS.md) for the verified gate and
[`DOC/CAPABILITY-REGISTRY.md`](DOC/CAPABILITY-REGISTRY.md) for capability state.

## Run locally

```sh
npm ci
npm test
npm start
```

The service listens on port 5000 by default. Check:

```sh
curl http://localhost:5000/health/live
curl http://localhost:5000/health/ready
```