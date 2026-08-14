import assert from "node:assert/strict";
import test from "node:test";
import { authorize, permissionMatrix, requirePermission } from "../src/authorization.js";
import { AppError } from "../src/errors.js";
import { DevIdentityProvider } from "../src/identity-provider.js";
import { FixedWindowRateLimiter } from "../src/rate-limit.js";
import { parseCookies, serializeCookie } from "../src/session.js";

test("development identity provider is explicit and verified", async () => {
  const provider = new DevIdentityProvider(true);
  const identity = await provider.resolveExternalIdentity({
    headers: { "x-dev-identity": "user-123", "x-dev-email": "Person@Example.test" },
  });
  assert.deepEqual(identity, { provider: "dev", subject: "user-123", verified: true, email: "person@example.test" });
  await assert.rejects(
    provider.resolveExternalIdentity({ headers: {} }),
    (error: unknown) => error instanceof AppError && error.code === "UNAUTHENTICATED",
  );
});

test("central authorization is organization-scoped and role-based", () => {
  const allowed = authorize({
    actor: { userId: "a", membership: { organizationId: "org-a", role: "OWNER", status: "ACTIVE" } },
    organizationId: "org-a",
    permission: "ownership.transfer",
  });
  assert.deepEqual(allowed, { allowed: true });
  const crossTenant = authorize({
    actor: { userId: "a", membership: { organizationId: "org-a", role: "OWNER", status: "ACTIVE" } },
    organizationId: "org-b",
    permission: "organization.read",
  });
  assert.deepEqual(crossTenant, { allowed: false, reason: "organization_mismatch" });
  assert.throws(
    () => requirePermission({
      actor: { userId: "member", membership: { organizationId: "org-a", role: "MEMBER", status: "ACTIVE" } },
      organizationId: "org-a",
      permission: "member.remove",
    }),
    (error: unknown) => error instanceof AppError && error.code === "ROLE_INSUFFICIENT",
  );
  assert.equal(permissionMatrix().VIEWER["organization.update"], false);
});

test("CSRF/session cookie boundary is server-readable without exposing the session cookie", () => {
  const sessionCookie = serializeCookie("joben_session", "opaque", { httpOnly: true, secure: true, maxAge: 60 });
  const csrfCookie = serializeCookie("joben_csrf", "csrf", { secure: true, maxAge: 60 });
  assert.match(sessionCookie, /HttpOnly/);
  assert.match(sessionCookie, /Secure/);
  assert.doesNotMatch(csrfCookie, /HttpOnly/);
  assert.deepEqual(parseCookies("joben_session=opaque; joben_csrf=csrf"), { joben_session: "opaque", joben_csrf: "csrf" });
});

test("rate-limit hook is deterministic and process-local", () => {
  const limiter = new FixedWindowRateLimiter(2, 1_000);
  limiter.consume("login", 0);
  limiter.consume("login", 100);
  assert.throws(() => limiter.consume("login", 200), (error: unknown) => error instanceof AppError && error.code === "AUTHENTICATION_ERROR");
  limiter.consume("login", 1_000);
});