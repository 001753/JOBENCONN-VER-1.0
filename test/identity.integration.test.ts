import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import test from "node:test";
import { disconnectPrisma, getPrismaClient } from "../src/database.js";
import { AppError } from "../src/errors.js";
import { IdentityService } from "../src/identity-service.js";
import { StaticIdentityProvider, type ExternalIdentity } from "../src/identity-provider.js";
import { SessionManager } from "../src/session.js";

const databaseConfigured = Boolean(process.env.DATABASE_URL);

test("Prompt 03 durable identity, tenant, invitation, session, and owner gates", { skip: !databaseConfigured }, async (t) => {
  const db = getPrismaClient();
  await db.$connect();
  const suffix = randomUUID().slice(0, 8);
  const identityA: ExternalIdentity = { provider: "test", subject: `a-${suffix}`, verified: true, email: `a-${suffix}@example.test` };
  const identityB: ExternalIdentity = { provider: "test", subject: `b-${suffix}`, verified: true, email: `b-${suffix}@example.test` };
  const provider = new StaticIdentityProvider(identityA);
  const sessions = new SessionManager(db, 3_600, false);
  const service = new IdentityService(db, sessions);
  const loginA = await service.login(await provider.resolveExternalIdentity(), `corr-${suffix}-login-a`);
  const loginARepeat = await service.login(identityA, `corr-${suffix}-login-a-repeat`);
  const loginB = await service.login(identityB, `corr-${suffix}-login-b`);
  const orgA = loginA.organizationId;
  const userIds = [loginA.actor.userId, loginB.actor.userId];

  t.after(async () => {
    await db.auditEvent.deleteMany({ where: { actorUserId: { in: userIds } } });
    await db.invitation.deleteMany({ where: { organizationId: orgA } });
    await db.session.deleteMany({ where: { userId: { in: userIds } } });
    await db.membership.deleteMany({ where: { userId: { in: userIds } } });
    await db.organization.deleteMany({ where: { id: { in: [loginA.organizationId, loginB.organizationId] } } });
    await db.user.deleteMany({ where: { id: { in: userIds } } });
    await disconnectPrisma();
  });

  await t.test("provisioning is idempotent and cross-tenant access is denied", async () => {
    assert.equal(loginA.actor.userId, loginARepeat.actor.userId);
    await assert.rejects(
      service.authorizeOrganization(loginB.actor, orgA, "member.read", `corr-${suffix}-cross`),
      (error: unknown) => error instanceof AppError && error.code === "NOT_A_MEMBER",
    );
  });

  await t.test("invitation accept is target-bound and replay-safe", async () => {
    const authA = await service.authorizeOrganization(loginA.actor, orgA, "member.invite", `corr-${suffix}-invite-auth`);
    const invitation = await service.createInvitation(authA, { email: identityB.email ?? "", role: "MEMBER", correlationId: `corr-${suffix}-invite` });
    const membership = await service.acceptInvitation(identityB, invitation.rawToken, `corr-${suffix}-accept`);
    const replay = await service.acceptInvitation(identityB, invitation.rawToken, `corr-${suffix}-replay`);
    assert.equal(replay.id, membership.id);
    const authB = await service.authorizeOrganization(loginB.actor, orgA, "member.read", `corr-${suffix}-member`);
    assert.equal(authB.role, "MEMBER");
  });

  await t.test("last owner and privilege escalation boundaries hold", async () => {
    const authA = await service.authorizeOrganization(loginA.actor, orgA, "role.change", `corr-${suffix}-role-auth`);
    const owner = await db.membership.findUnique({ where: { userId_organizationId: { userId: loginA.actor.userId, organizationId: orgA } } });
    assert.ok(owner);
    await assert.rejects(
      service.changeRole(authA, owner.id, "ADMIN", owner.version, `corr-${suffix}-demote-last`),
      (error: unknown) => error instanceof AppError && error.code === "LAST_OWNER_PROTECTED",
    );
    await assert.rejects(
      service.removeMembership(authA, owner.id, owner.version, `corr-${suffix}-remove-last`),
      (error: unknown) => error instanceof AppError && error.code === "LAST_OWNER_PROTECTED",
    );
  });

  await t.test("revoked sessions cannot authenticate", async () => {
    await sessions.revoke(loginA.actor.session.id, loginA.actor.userId);
    await assert.rejects(
      service.actorFromSession(loginA.sessionToken),
      (error: unknown) => error instanceof AppError && error.code === "SESSION_REVOKED",
    );
  });
});