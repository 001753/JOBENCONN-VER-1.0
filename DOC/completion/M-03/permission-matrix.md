# M-03 Permission Matrix

| Operation | Permission | OWNER | ADMIN | MEMBER | VIEWER |
|---|---|---:|---:|---:|---:|
| Read scan/status/progress/backlog | `scan.read` | yes | yes | yes | yes |
| Request scan | `scan.create` | yes | yes | no | no |
| Cancel scan | `scan.cancel` | yes | yes | no | no |
| Existing findings read/run | existing `findings.*` | existing matrix | existing matrix | existing matrix | existing matrix |

Organization identity is taken from the authenticated session. A client
supplied organization ID is never used as authorization context.