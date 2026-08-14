import { AppError } from "./errors.js";

export const ROLES = ["OWNER", "ADMIN", "MEMBER", "VIEWER"] as const;
export type Role = (typeof ROLES)[number];

export const PERMISSIONS = [
  "organization.read",
  "organization.update",
  "member.read",
  "member.invite",
  "member.update",
  "member.remove",
  "role.change",
  "ownership.transfer",
  "audit.read",
  "settings.update",
  "aws.connection.read",
  "aws.connection.create",
  "aws.connection.update",
  "aws.connection.revoke",
  "aws.discovery.run",
  "aws.inventory.read",
  "findings.read",
  "findings.run",
  "findings.acknowledge",
  "findings.resolve",
  "scan.read",
  "scan.create",
  "scan.cancel",
] as const;
export type Permission = (typeof PERMISSIONS)[number];

const rolePermissions: Record<Role, ReadonlySet<Permission>> = {
  OWNER: new Set(PERMISSIONS),
  ADMIN: new Set(PERMISSIONS.filter((permission) => permission !== "ownership.transfer")),
  MEMBER: new Set(["organization.read", "member.read", "aws.connection.read", "aws.inventory.read", "findings.read", "scan.read"]),
  VIEWER: new Set(["organization.read", "member.read", "aws.connection.read", "aws.inventory.read", "findings.read", "scan.read"]),
};

export interface AuthorizationActor {
  readonly userId: string;
  readonly membership: { readonly organizationId: string; readonly role: string; readonly status: string };
}

export interface CustomerAuthorizationContext {
  readonly kind: "customer";
  readonly organizationId: string;
  readonly actorUserId: string;
  readonly role: Role;
}

export interface SystemAuthorizationContext {
  readonly kind: "system";
  readonly actorUserId?: string;
}

export type AuthorizationContext = CustomerAuthorizationContext | SystemAuthorizationContext;

export function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}

export function authorize(input: { actor: AuthorizationActor; organizationId: string; permission: Permission }): { allowed: true } | { allowed: false; reason: string } {
  if (input.actor.membership.organizationId !== input.organizationId) return { allowed: false, reason: "organization_mismatch" };
  if (input.actor.membership.status !== "ACTIVE") return { allowed: false, reason: "membership_inactive" };
  if (!isRole(input.actor.membership.role)) return { allowed: false, reason: "unknown_role" };
  return rolePermissions[input.actor.membership.role].has(input.permission)
    ? { allowed: true }
    : { allowed: false, reason: "permission_denied" };
}

export function requirePermission(input: { actor: AuthorizationActor; organizationId: string; permission: Permission }): Role {
  const result = authorize(input);
  if (!result.allowed) {
    if (result.reason === "membership_inactive") throw new AppError("MEMBERSHIP_SUSPENDED", "Active organization membership is required.");
    if (result.reason === "unknown_role" || result.reason === "permission_denied") throw new AppError("ROLE_INSUFFICIENT", "The role does not allow this action.");
    throw new AppError("FORBIDDEN", "The action is not allowed in this organization.");
  }
  return input.actor.membership.role as Role;
}

export function customerAuthorizationContext(userId: string, organizationId: string, role: string): CustomerAuthorizationContext {
  if (!isRole(role)) throw new AppError("ROLE_INSUFFICIENT", "The membership role is invalid.");
  return { kind: "customer", actorUserId: userId, organizationId, role };
}

export function systemAuthorizationContext(actorUserId?: string): SystemAuthorizationContext {
  return actorUserId ? { kind: "system", actorUserId } : { kind: "system" };
}

export function permissionMatrix(): Record<Role, Record<Permission, boolean>> {
  return Object.fromEntries(ROLES.map((role) => [role, Object.fromEntries(PERMISSIONS.map((permission) => [permission, rolePermissions[role].has(permission)]))])) as Record<Role, Record<Permission, boolean>>;
}