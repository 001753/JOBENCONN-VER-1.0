# AWS Account Discovery Foundation

## Discovery flow

1. An authenticated organization owner/admin creates a connection.
2. JOBEN calls STS and derives the verified 12-digit account ID from AWS.
3. The account is persisted with an organization-level uniqueness constraint.
4. A discovery run calls `DescribeRegions`.
5. Each returned region is persisted and EC2 instances are paginated and
   normalized.
6. S3 buckets and IAM summary/users/roles are read and normalized.
7. Resources are upserted by organization, account, region, service, type, and
   resource ID.
8. A run is marked `COMPLETED`, `PARTIAL`, or `FAILED` with counts and safe
   error categories.

The run record is the durable job boundary. An idempotency key is canonicalized
with organization and account scope, so replaying a request returns the
original run rather than creating a duplicate.

## Normalized inventory

Every `AwsResource` includes:

- organization and AWS account scope;
- connection ID and region (`global` for IAM);
- service, resource type, and resource ID;
- optional ARN/name;
- JSON tags and normalized metadata;
- first seen, last seen, and discovery timestamps;
- `ACTIVE`, `STALE`, or `DELETED` lifecycle state.

Resources observed in a successful scope are refreshed. Previously active
resources absent from that successful scope become `STALE`; resources in a
failed region are not fabricated or marked stale. Discovery never hard-deletes
history.

## Protected API

- `GET /aws/connections`
- `POST /aws/connections`
- `GET /aws/connections/:id`
- `POST /aws/connections/:id/verify`
- `POST /aws/connections/:id/revoke`
- `GET /aws/accounts`
- `POST /aws/accounts/:id/discovery`
- `GET /aws/accounts/:id/discovery`
- `GET /aws/accounts/:id/resources`

All routes require a session and active organization context. Mutations also
require the existing CSRF header.

## Verification boundary

Unit and PostgreSQL integration tests use an explicit fake read-only client.
They verify account identity validation, multi-region pagination behavior,
normalization, replay idempotency, account/tenant isolation, and revocation.
Live AWS verification remains pending until a real AWS provider with the
documented least-privilege policy is connected. Prompt 04 does not implement
security findings, compliance scoring, remediation, reporting, billing, or
dashboard UI.
