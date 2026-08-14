# Tenant Scope Contract

`OrganizationContext` has two explicit forms:

- `customerContext(organizationId, actorUserId?)` — all customer repository
  reads and writes are restricted to that organization.
- `systemContext(actorUserId?)` — cross-organization operations are explicit
  system work and are never the customer default.

An absent context is not interpreted as "all organizations". Customer
repository methods either add the organization predicate or reject a
cross-organization target. The isolation test creates two organizations and
verifies that a customer context cannot return the other organization's data.

This is a persistence boundary, not an authorization engine. Prompt 03 must
validate the actor, session, organization membership, and permissions before
constructing a customer context.