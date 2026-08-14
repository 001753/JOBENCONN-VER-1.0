# Tenant, RBAC, and Access Control

## Request pipeline

Protected work follows:

`session -> actor -> active membership -> active organization -> permission -> scoped repository -> audit`.

`customerContext(organizationId, actorUserId)` is only created after the
server-side membership check. `systemContext` is a distinct persistence scope
and is never inferred from organization ownership.

## Role and permission matrix

| Permission | OWNER | ADMIN | MEMBER | VIEWER |
| --- | --- | --- | --- | --- |
| organization.read | yes | yes | yes | yes |
| organization.update | yes | yes | no | no |
| member.read | yes | yes | yes | yes |
| member.invite | yes | yes | no | no |
| member.update | yes | yes | no | no |
| member.remove | yes | yes | no | no |
| role.change | yes | yes | no | no |
| ownership.transfer | yes | no | no | no |
| audit.read | yes | yes | no | no |
| settings.update | yes | yes | no | no |

Roles are membership-scoped. A user can be OWNER in one organization and MEMBER
in another. Suspended, removed, or unknown-role memberships are denied.

## Lifecycle invariants

- Invitations store only a token digest, expire, can be revoked, and are
  consumed atomically and idempotently.
- Membership role/status changes use optimistic versions and audit events.
- Removal revokes the member's active sessions.
- Role demotion, removal, and deactivation cannot remove the last active owner.
- Ownership transfer promotes the replacement before demoting the prior owner
  in a serializable transaction, so no durable zero-owner state is created.

Sensitive denials are audited with actor, organization, action, reason,
correlation ID, and no secret material.