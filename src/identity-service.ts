import { createHash, randomBytes } from "node:crypto";
import { Prisma, type PrismaClient } from "@prisma/client";
import { AppError } from "./errors.js";
import { authorize, customerAuthorizationContext, isRole, requirePermission, type Permission, type Role } from "./authorization.js";
import { externalIdentityRef, normalizeIdentityEmail, type ExternalIdentity } from "./identity-provider.js";
import { customerContext, AuditEventRepository, type OrganizationContext } from "./persistence.js";
import { SessionManager, type AuthenticatedSession } from "./session.js";

type Db = PrismaClient | Prisma.TransactionClient;

export interface Actor {
  readonly userId: string;
  readonly session: AuthenticatedSession;
  readonly externalIdentityRef: string | null;
  readonly email: string | null;
}

export interface OrganizationAuthorization {
  readonly actor: Actor;
  readonly organizationId: string;
  readonly membershipId: string;
  readonly role: Role;
  readonly context: OrganizationContext;
}

export interface InvitationCreation {
  readonly invitationId: string;
  readonly invitedEmail: string;
  readonly role: Role;
  readonly rawToken: string;
  readonly expiresAt: Date;
}

function sha256(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

function persistenceCode(error: unknown): string | undefined {
  return typeof error === "object" && error !== null && "code" in error && typeof error.code === "string" ? error.code : undefined;
}

function mapConcurrency(error: unknown): never {
  if (persistenceCode(error) === "P2034") throw new AppError("CONCURRENCY_CONFLICT", "The concurrent mutation could not be applied.", { cause: error });
  throw error;
}

function normalizeRole(role: string): Role {
  const normalized = role.trim().toUpperCase();
  if (!isRole(normalized)) throw new AppError("VALIDATION_ERROR", "The requested role is invalid.");
  return normalized;
}

function normalizeEmail(email: string): string {
  const normalized = normalizeIdentityEmail(email);
  if (!normalized || normalized.length > 320 || !normalized.includes("@")) throw new AppError("VALIDATION_ERROR", "A valid invitation email is required.");
  return normalized;
}

export class IdentityService {
  private readonly audit: AuditEventRepository;

  constructor(
    private readonly db: PrismaClient,
    private readonly sessions: SessionManager,
  ) {
    this.audit = new AuditEventRepository(db);
  }

  async syncUser(identity: ExternalIdentity): Promise<Prisma.UserGetPayload<object>> {
    if (!identity.verified) throw new AppError("UNAUTHENTICATED", "A verified external identity is required.");
    const ref = externalIdentityRef(identity);
    const email = normalizeIdentityEmail(identity.email);
    const existing = await this.db.user.findUnique({ where: { externalIdentityRef: ref } });
    if (existing) {
      if (existing.status !== "ACTIVE") throw new AppError("FORBIDDEN", "This user is not active.");
      return this.db.user.update({ where: { id: existing.id }, data: email ? { email } : {} });
    }
    try {
      return await this.db.user.create({ data: { externalIdentityRef: ref, ...(email ? { email } : {}) } });
    } catch (error) {
      if (persistenceCode(error) === "P2002") {
        const raced = await this.db.user.findUnique({ where: { externalIdentityRef: ref } });
        if (raced) return raced;
      }
      throw error;
    }
  }

  async ensurePersonalOrganization(userId: string, correlationId: string): Promise<Prisma.OrganizationGetPayload<object>> {
    const membership = await this.db.membership.findFirst({
      where: { userId, status: "ACTIVE" },
      include: { organization: true },
      orderBy: { createdAt: "asc" },
    });
    if (membership?.organization) return membership.organization;
    try {
      return await this.db.$transaction(async (tx) => {
        const organization = await tx.organization.create({
          data: { name: "Personal Organization", slug: `personal-${userId}` },
        });
        await tx.membership.create({ data: { organizationId: organization.id, userId, role: "OWNER", status: "ACTIVE" } });
        await new AuditEventRepository(tx).append(customerContext(organization.id, userId), {
          actorUserId: userId,
          action: "organization.created",
          purpose: "provision personal organization",
          targetType: "organization",
          targetId: organization.id,
          result: "SUCCESS",
          correlationId,
          metadata: { provisioning: "personal" },
        });
        return organization;
      });
    } catch (error) {
      if (persistenceCode(error) === "P2002") {
        const raced = await this.db.membership.findFirst({ where: { userId, status: "ACTIVE" }, include: { organization: true } });
        if (raced?.organization) return raced.organization;
      }
      throw error;
    }
  }

  async login(identity: ExternalIdentity, correlationId: string): Promise<{ actor: Actor; sessionToken: string; csrfToken: string; organizationId: string }> {
    let user: Prisma.UserGetPayload<object>;
    try {
      user = await this.syncUser(identity);
    } catch (error) {
      throw error;
    }
    const organization = await this.ensurePersonalOrganization(user.id, correlationId);
    const created = await this.sessions.create(user.id, organization.id);
    await this.audit.append(customerContext(organization.id, user.id), {
      actorUserId: user.id,
      action: "login.succeeded",
      purpose: "authenticate application session",
      targetType: "session",
      targetId: created.session.id,
      result: "SUCCESS",
      correlationId,
      metadata: { provider: identity.provider },
    });
    return {
      actor: { userId: user.id, session: created.session, externalIdentityRef: user.externalIdentityRef, email: user.email },
      sessionToken: created.sessionToken,
      csrfToken: created.csrfToken,
      organizationId: organization.id,
    };
  }

  async actorFromSession(sessionToken: string | undefined): Promise<Actor> {
    const session = await this.sessions.validate(sessionToken);
    const user = await this.db.user.findUnique({ where: { id: session.userId } });
    if (!user || user.status !== "ACTIVE") throw new AppError("UNAUTHENTICATED", "Authentication is required.");
    return { userId: user.id, session, externalIdentityRef: user.externalIdentityRef, email: user.email };
  }

  async logout(actor: Actor, correlationId: string): Promise<void> {
    await this.sessions.revoke(actor.session.id, actor.userId);
    if (actor.session.activeOrganizationId) {
      await this.audit.append(customerContext(actor.session.activeOrganizationId, actor.userId), {
        actorUserId: actor.userId,
        action: "logout.completed",
        purpose: "end application session",
        targetType: "session",
        targetId: actor.session.id,
        result: "SUCCESS",
        correlationId,
        metadata: {},
      });
    }
  }

  async authorizeOrganization(actor: Actor, organizationId: string, permission: Permission, correlationId: string): Promise<OrganizationAuthorization> {
    const membership = await this.db.membership.findUnique({ where: { userId_organizationId: { userId: actor.userId, organizationId } } });
    if (!membership) {
      await this.audit.append(systemContextForAudit(actor.userId), {
        organizationId,
        actorUserId: actor.userId,
        action: "authorization.denied",
        purpose: "organization access control",
        targetType: "organization",
        targetId: organizationId,
        result: "FAILURE",
        reason: "not_a_member",
        correlationId,
        metadata: { permission },
      }).catch(() => undefined);
      throw new AppError("NOT_A_MEMBER", "Active membership is required.");
    }
    const org = await this.db.organization.findUnique({ where: { id: organizationId } });
    if (!org) throw new AppError("ORG_NOT_FOUND", "Organization not found.");
    if (org.status !== "ACTIVE") throw new AppError("FORBIDDEN", "The organization is not active.");
    try {
      const role = requirePermission({ actor: { userId: actor.userId, membership }, organizationId, permission });
      return {
        actor,
        organizationId,
        membershipId: membership.id,
        role,
        context: customerContext(organizationId, actor.userId),
      };
    } catch (error) {
      await this.audit.append(systemContextForAudit(actor.userId), {
        organizationId,
        actorUserId: actor.userId,
        action: "authorization.denied",
        purpose: "organization access control",
        targetType: "organization",
        targetId: organizationId,
        result: "FAILURE",
        reason: error instanceof AppError ? error.code : "denied",
        correlationId,
        metadata: { permission },
      }).catch(() => undefined);
      throw error;
    }
  }

  async switchOrganization(actor: Actor, organizationId: string, correlationId: string): Promise<AuthenticatedSession> {
    const authorization = await this.authorizeOrganization(actor, organizationId, "organization.read", correlationId);
    const session = await this.sessions.setActiveOrganization(actor.session.id, actor.userId, organizationId, actor.session.version);
    await this.audit.append(authorization.context, {
      actorUserId: actor.userId,
      action: "organization.switched",
      purpose: "change active organization context",
      targetType: "organization",
      targetId: organizationId,
      result: "SUCCESS",
      correlationId,
      metadata: {},
    });
    return session;
  }

  async createOrganization(actor: Actor, input: { name: string; slug: string; correlationId: string }): Promise<Prisma.OrganizationGetPayload<object>> {
    const name = input.name.trim();
    const slug = input.slug.trim().toLowerCase();
    if (!name || name.length > 200 || !/^[a-z0-9][a-z0-9-]{1,119}$/.test(slug)) throw new AppError("VALIDATION_ERROR", "Organization name or slug is invalid.");
    try {
      return await this.db.$transaction(async (tx) => {
        const organization = await tx.organization.create({ data: { name, slug } });
        await tx.membership.create({ data: { organizationId: organization.id, userId: actor.userId, role: "OWNER", status: "ACTIVE" } });
        await new AuditEventRepository(tx).append(customerContext(organization.id, actor.userId), {
          actorUserId: actor.userId,
          action: "organization.created",
          purpose: "create organization",
          targetType: "organization",
          targetId: organization.id,
          result: "SUCCESS",
          correlationId: input.correlationId,
          metadata: {},
        });
        return organization;
      });
    } catch (error) {
      if (persistenceCode(error) === "P2002") throw new AppError("CONFLICT", "The organization slug is already in use.", { cause: error });
      return mapConcurrency(error);
    }
  }

  async createInvitation(auth: OrganizationAuthorization, input: { email: string; role: string; expiresAt?: Date; correlationId: string }): Promise<InvitationCreation> {
    requirePermission({ actor: { userId: auth.actor.userId, membership: { organizationId: auth.organizationId, role: auth.role, status: "ACTIVE" } }, organizationId: auth.organizationId, permission: "member.invite" });
    const invitedEmail = normalizeEmail(input.email);
    const role = normalizeRole(input.role);
    if (role === "OWNER") throw new AppError("FORBIDDEN", "Ownership must be transferred explicitly.");
    const expiresAt = input.expiresAt ?? new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    if (expiresAt.getTime() <= Date.now()) throw new AppError("VALIDATION_ERROR", "Invitation expiry must be in the future.");
    const duplicate = await this.db.invitation.findFirst({ where: { organizationId: auth.organizationId, invitedEmail, status: "PENDING", expiresAt: { gt: new Date() } } });
    if (duplicate) throw new AppError("CONFLICT", "A pending invitation already exists for this email.");
    const rawToken = randomBytes(32).toString("base64url");
    try {
      return await this.db.$transaction(async (tx) => {
        const invitation = await tx.invitation.create({ data: { organizationId: auth.organizationId, invitedEmail, role, tokenDigest: sha256(rawToken), expiresAt } });
        await new AuditEventRepository(tx).append(auth.context, {
          actorUserId: auth.actor.userId,
          action: "invitation.created",
          purpose: "invite organization member",
          targetType: "invitation",
          targetId: invitation.id,
          result: "SUCCESS",
          correlationId: input.correlationId,
          metadata: { role, invitedEmail },
        });
        return { invitationId: invitation.id, invitedEmail, role, rawToken, expiresAt };
      });
    } catch (error) {
      return mapConcurrency(error);
    }
  }

  async acceptInvitation(identity: ExternalIdentity, rawToken: string, correlationId: string): Promise<Prisma.MembershipGetPayload<object>> {
    if (!identity.verified) throw new AppError("UNAUTHENTICATED", "A verified external identity is required.");
    const user = await this.syncUser(identity);
    const tokenDigest = sha256(rawToken);
    try {
      return await this.db.$transaction(async (tx) => {
        const invitation = await tx.invitation.findUnique({ where: { tokenDigest } });
        if (!invitation) throw new AppError("NOT_FOUND", "Invitation not found.");
        if (invitation.status === "ACCEPTED") {
          if (invitation.acceptedByUserId === user.id) {
            const existing = await tx.membership.findUnique({ where: { userId_organizationId: { userId: user.id, organizationId: invitation.organizationId } } });
            if (existing) return existing;
          }
          throw new AppError("INVITATION_ALREADY_USED", "The invitation has already been used.");
        }
        if (invitation.status === "REVOKED") throw new AppError("INVITATION_REVOKED", "The invitation has been revoked.");
        if (invitation.expiresAt.getTime() <= Date.now() || invitation.status === "EXPIRED") {
          await tx.invitation.updateMany({ where: { id: invitation.id, version: invitation.version, status: "PENDING" }, data: { status: "EXPIRED", version: { increment: 1 } } });
          throw new AppError("INVITATION_EXPIRED", "The invitation has expired.");
        }
        if (!user.email || normalizeEmail(user.email) !== invitation.invitedEmail) throw new AppError("FORBIDDEN", "The invitation target identity does not match.");
        const consumed = await tx.invitation.updateMany({
          where: { id: invitation.id, status: "PENDING", version: invitation.version, expiresAt: { gt: new Date() } },
          data: { status: "ACCEPTED", acceptedAt: new Date(), acceptedByUserId: user.id, version: { increment: 1 } },
        });
        if (consumed.count !== 1) throw new AppError("CONCURRENCY_CONFLICT", "The invitation was changed by another request.");
        const membership = await tx.membership.upsert({
          where: { userId_organizationId: { userId: user.id, organizationId: invitation.organizationId } },
          create: { userId: user.id, organizationId: invitation.organizationId, role: invitation.role, status: "ACTIVE" },
          update: { role: invitation.role, status: "ACTIVE", version: { increment: 1 } },
        });
        const context = customerContext(invitation.organizationId, user.id);
        await new AuditEventRepository(tx).append(context, {
          actorUserId: user.id,
          action: "invitation.accepted",
          purpose: "join organization",
          targetType: "invitation",
          targetId: invitation.id,
          result: "SUCCESS",
          correlationId,
          metadata: { role: invitation.role },
        });
        await new AuditEventRepository(tx).append(context, {
          actorUserId: user.id,
          action: "membership.created",
          purpose: "activate invitation membership",
          targetType: "membership",
          targetId: membership.id,
          result: "SUCCESS",
          correlationId,
          metadata: { role: invitation.role },
        });
        return membership;
      }, { isolationLevel: Prisma.TransactionIsolationLevel.Serializable });
    } catch (error) {
      return mapConcurrency(error);
    }
  }

  async revokeInvitation(auth: OrganizationAuthorization, invitationId: string, correlationId: string): Promise<void> {
    requirePermission({ actor: { userId: auth.actor.userId, membership: { organizationId: auth.organizationId, role: auth.role, status: "ACTIVE" } }, organizationId: auth.organizationId, permission: "member.invite" });
    const invitation = await this.db.invitation.findUnique({ where: { id: invitationId } });
    if (!invitation || invitation.organizationId !== auth.organizationId) throw new AppError("NOT_FOUND", "Invitation not found.");
    if (invitation.status !== "PENDING") throw new AppError("CONFLICT", "Only pending invitations can be revoked.");
    const updated = await this.db.invitation.updateMany({ where: { id: invitationId, organizationId: auth.organizationId, status: "PENDING", version: invitation.version }, data: { status: "REVOKED", revokedAt: new Date(), version: { increment: 1 } } });
    if (updated.count !== 1) throw new AppError("CONCURRENCY_CONFLICT", "The invitation was changed by another request.");
    await this.audit.append(auth.context, { actorUserId: auth.actor.userId, action: "invitation.revoked", purpose: "revoke organization invitation", targetType: "invitation", targetId: invitationId, result: "SUCCESS", correlationId, metadata: {} });
  }

  async changeRole(auth: OrganizationAuthorization, membershipId: string, roleInput: string, expectedVersion: number, correlationId: string): Promise<Prisma.MembershipGetPayload<object>> {
    requirePermission({ actor: { userId: auth.actor.userId, membership: { organizationId: auth.organizationId, role: auth.role, status: "ACTIVE" } }, organizationId: auth.organizationId, permission: "role.change" });
    const role = normalizeRole(roleInput);
    const target = await this.db.membership.findUnique({ where: { id: membershipId } });
    if (!target || target.organizationId !== auth.organizationId) throw new AppError("NOT_FOUND", "Membership not found.");
    if (target.role === "OWNER" && role !== "OWNER") await this.assertNotLastOwner(auth.organizationId);
    if (target.userId === auth.actor.userId && role !== auth.role) throw new AppError("FORBIDDEN", "Self-service privilege changes are not allowed.");
    const updated = await this.db.membership.updateMany({ where: { id: membershipId, organizationId: auth.organizationId, version: expectedVersion, status: "ACTIVE" }, data: { role, version: { increment: 1 } } });
    if (updated.count !== 1) throw new AppError("CONCURRENCY_CONFLICT", "The membership was changed by another request.");
    const result = await this.db.membership.findUnique({ where: { id: membershipId } });
    if (!result) throw new AppError("NOT_FOUND", "Membership not found.");
    await this.audit.append(auth.context, { actorUserId: auth.actor.userId, action: "membership.role_changed", purpose: "change member role", targetType: "membership", targetId: membershipId, result: "SUCCESS", correlationId, metadata: { role } });
    return result;
  }

  async removeMembership(auth: OrganizationAuthorization, membershipId: string, expectedVersion: number, correlationId: string): Promise<void> {
    requirePermission({ actor: { userId: auth.actor.userId, membership: { organizationId: auth.organizationId, role: auth.role, status: "ACTIVE" } }, organizationId: auth.organizationId, permission: "member.remove" });
    const target = await this.db.membership.findUnique({ where: { id: membershipId } });
    if (!target || target.organizationId !== auth.organizationId) throw new AppError("NOT_FOUND", "Membership not found.");
    if (target.role === "OWNER") await this.assertNotLastOwner(auth.organizationId);
    const result = await this.db.$transaction(async (tx) => {
      const updated = await tx.membership.updateMany({ where: { id: membershipId, organizationId: auth.organizationId, version: expectedVersion, status: "ACTIVE" }, data: { status: "REMOVED", version: { increment: 1 } } });
      if (updated.count !== 1) throw new AppError("CONCURRENCY_CONFLICT", "The membership was changed by another request.");
      await tx.session.updateMany({ where: { userId: target.userId, revokedAt: null }, data: { revokedAt: new Date(), version: { increment: 1 } } });
      await new AuditEventRepository(tx).append(auth.context, { actorUserId: auth.actor.userId, action: "membership.removed", purpose: "remove organization member", targetType: "membership", targetId: membershipId, result: "SUCCESS", correlationId, metadata: {} });
      return undefined;
    }, { isolationLevel: Prisma.TransactionIsolationLevel.Serializable });
    return result;
  }

  async transferOwnership(auth: OrganizationAuthorization, targetMembershipId: string, expectedTargetVersion: number, correlationId: string): Promise<void> {
    requirePermission({ actor: { userId: auth.actor.userId, membership: { organizationId: auth.organizationId, role: auth.role, status: "ACTIVE" } }, organizationId: auth.organizationId, permission: "ownership.transfer" });
    const target = await this.db.membership.findUnique({ where: { id: targetMembershipId } });
    if (!target || target.organizationId !== auth.organizationId || target.status !== "ACTIVE") throw new AppError("NOT_FOUND", "Active target membership not found.");
    if (target.userId === auth.actor.userId) throw new AppError("VALIDATION_ERROR", "Ownership transfer requires another member.");
    const source = await this.db.membership.findUnique({ where: { userId_organizationId: { userId: auth.actor.userId, organizationId: auth.organizationId } } });
    if (!source || source.role !== "OWNER") throw new AppError("ROLE_INSUFFICIENT", "Only an owner can transfer ownership.");
    try {
      await this.db.$transaction(async (tx) => {
        const promoted = await tx.membership.updateMany({ where: { id: targetMembershipId, organizationId: auth.organizationId, status: "ACTIVE", version: expectedTargetVersion }, data: { role: "OWNER", version: { increment: 1 } } });
        if (promoted.count !== 1) throw new AppError("CONCURRENCY_CONFLICT", "The target membership was changed by another request.");
        const demoted = await tx.membership.updateMany({ where: { id: source.id, organizationId: auth.organizationId, status: "ACTIVE", role: "OWNER" }, data: { role: "ADMIN", version: { increment: 1 } } });
        if (demoted.count !== 1) throw new AppError("CONCURRENCY_CONFLICT", "The source membership was changed by another request.");
        await new AuditEventRepository(tx).append(auth.context, { actorUserId: auth.actor.userId, action: "ownership.transferred", purpose: "transfer organization ownership", targetType: "membership", targetId: targetMembershipId, result: "SUCCESS", correlationId, metadata: { previousOwnerMembershipId: source.id } });
      }, { isolationLevel: Prisma.TransactionIsolationLevel.Serializable });
    } catch (error) {
      return mapConcurrency(error);
    }
  }

  private async assertNotLastOwner(organizationId: string): Promise<void> {
    const owners = await this.db.membership.count({ where: { organizationId, role: "OWNER", status: "ACTIVE" } });
    if (owners <= 1) throw new AppError("LAST_OWNER_PROTECTED", "An organization must retain at least one active owner.");
  }
}

function systemContextForAudit(actorUserId: string): OrganizationContext {
  return { kind: "system", actorUserId };
}