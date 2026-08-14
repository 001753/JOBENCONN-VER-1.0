# AWS Integration Foundation

Status: **code verified; live AWS provider verification pending**.

## Tenant and connection model

AWS access belongs to an organization:

`Organization -> AwsConnection -> AwsAccount -> AwsRegion/AwsResource`

Connections, accounts, regions, resources, and discovery runs are durable
PostgreSQL records. Every lookup includes the authenticated organization scope;
client-supplied organization or account IDs are never used as authorization
proof.

Connection lifecycle:

`PENDING -> ACTIVE` after a successful STS `GetCallerIdentity` call.

Failed verification records `ERROR`. Revocation records `REVOKED` and also
revokes the connected account representation. History is retained; revoked
connections cannot start discovery or be verified again.

## Credential strategy

The application never stores AWS access keys, secret keys, session tokens, or
raw external IDs. The connection stores only a credential source reference and
optional role ARN. The default implementation uses the AWS SDK v3 default
credential provider chain. Role assumption is isolated behind
`AwsCredentialProviderFactory` and uses `fromTemporaryCredentials`; an
environment-specific secret manager can supply additional role context without
changing persistence.

The HTTP API accepts only the explicit `default-chain` source. It never accepts
credential material and never returns credential material. Clerk or AWS live
credentials are not configured in this development environment, so this
repository does not claim live AWS verification.

## Authorization

AWS operations follow:

`session -> actor -> active organization membership -> AWS permission -> scoped connection/account -> AWS operation`

Owner and admin roles can manage connections and run discovery. Member and
viewer roles can read connections and inventory, but cannot create, verify,
revoke, or run discovery. The service performs the final role check even when
called outside HTTP routes.

## Minimum read-only IAM permissions

The implemented adapters require only:

| Action | Purpose |
| --- | --- |
| `sts:GetCallerIdentity` | Verify caller account, ARN, and user ID |
| `ec2:DescribeRegions` | Discover enabled regions |
| `ec2:DescribeInstances` | Discover EC2 instances and metadata |
| `s3:ListAllMyBuckets` | Discover accessible buckets |
| `s3:GetBucketLocation` | Normalize bucket region |
| `iam:GetAccountSummary` | Persist account IAM summary |
| `iam:ListUsers` | Discover IAM user identities |
| `iam:ListRoles` | Discover IAM role identities |

No create, update, delete, start, stop, terminate, reboot, ACL, policy, or
object-download operation is used by discovery.

## Security and failure behavior

AWS errors are normalized into safe categories. Only throttling, transient
network failures, and bounded 5xx service failures are retried with bounded
exponential backoff. Access denied, invalid credentials, validation errors, and
not-found responses are not blindly retried. Raw AWS errors do not cross the
HTTP boundary or enter audit metadata.

Security-sensitive connection and discovery transitions are append-audited with
organization, actor, target, result, reason, and correlation ID. Secrets are
rejected by the existing audit metadata safety check.
