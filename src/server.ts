import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import type { AppConfig } from "./config.js";
import { checkDatabaseConnection, getPrismaClient } from "./database.js";
import { AppError, errorResponse } from "./errors.js";
import { DevIdentityProvider, ClerkIdentityProvider } from "./identity-provider.js";
import { IdentityService } from "./identity-service.js";
import { StructuredLogger } from "./logger.js";
import { SessionManager, SESSION_COOKIE, parseCookies } from "./session.js";
import { FixedWindowRateLimiter } from "./rate-limit.js";

const MAX_REQUEST_BYTES = 1_048_576;
const authRateLimiter = new FixedWindowRateLimiter(10, 60_000);

function sendJson(response: ServerResponse, statusCode: number, payload: unknown, setCookies: string[] = []): void {
  if (statusCode === 204) {
    response.statusCode = statusCode;
    if (setCookies.length > 0) response.setHeader("Set-Cookie", setCookies);
    response.removeHeader("Content-Type");
    response.removeHeader("Content-Length");
    response.end();
    return;
  }
  const body = JSON.stringify(payload);
  response.statusCode = statusCode;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", Buffer.byteLength(body));
  if (setCookies.length > 0) response.setHeader("Set-Cookie", setCookies);
  response.end(body);
}

function applySecurityHeaders(response: ServerResponse): void {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Cache-Control", "no-store");
}

async function readJson(request: IncomingMessage): Promise<Record<string, unknown>> {
  let body = "";
  for await (const chunk of request) {
    body += Buffer.isBuffer(chunk) ? chunk.toString("utf8") : String(chunk);
    if (Buffer.byteLength(body) > MAX_REQUEST_BYTES) throw new AppError("VALIDATION_ERROR", "Request body exceeds the 1 MiB limit.");
  }
  if (!body.trim()) return {};
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    throw new AppError("VALIDATION_ERROR", "Request body must be valid JSON.");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new AppError("VALIDATION_ERROR", "Request body must be a JSON object.");
  return parsed as Record<string, unknown>;
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.trim()) throw new AppError("VALIDATION_ERROR", `${field} is required.`);
  return value.trim();
}

async function route(request: IncomingMessage, response: ServerResponse, config: AppConfig, correlationId: string): Promise<void> {
  const method = request.method ?? "GET";
  const path = new URL(request.url ?? "/", "http://joben.local").pathname;

  if (path === "/health/live") {
    if (method !== "GET") throw new AppError("VALIDATION_ERROR", "Health liveness is read-only.");
    sendJson(response, 200, { status: "ok", endpoint: "liveness", capabilityState: "IMPLEMENTED" });
    return;
  }
  if (path === "/health/ready") {
    if (method !== "GET") throw new AppError("VALIDATION_ERROR", "Health readiness is read-only.");
    if (config.databaseUrl) {
      try {
        await checkDatabaseConnection();
      } catch (error) {
        throw new AppError("DEPENDENCY_ERROR", "Durable database is unavailable.", { cause: error });
      }
    }
    sendJson(response, 200, {
      status: "ready",
      endpoint: "readiness",
      checks: { configuration: "pass", database: config.databaseUrl ? "pass" : "not_configured" },
      note: config.databaseUrl
        ? "PostgreSQL connectivity is verified for this process."
        : "DATABASE_URL is not configured for this development/test process.",
    });
    return;
  }

  const db = getPrismaClient();
  const sessions = new SessionManager(db, config.sessionTtlSeconds, config.environment === "production");
  const identityProvider = config.authProvider === "clerk"
    ? new ClerkIdentityProvider(config.clerkSecretKey)
    : new DevIdentityProvider(config.environment !== "production");
  const identity = new IdentityService(db, sessions);
  const cookies = parseCookies(request.headers.cookie);
  const sessionToken = cookies[SESSION_COOKIE];
  const csrfToken = request.headers["x-csrf-token"];
  const csrfHeader = Array.isArray(csrfToken) ? csrfToken[0] : csrfToken;

  if (path === "/auth/dev/session" && method === "POST") {
    if (config.authProvider !== "dev" || config.environment === "production") throw new AppError("NOT_IMPLEMENTED", "The development authentication route is not available.");
    const source = request.socket.remoteAddress ?? "unknown";
    authRateLimiter.consume(`dev-session:${source}`);
    const external = await identityProvider.resolveExternalIdentity({ headers: request.headers });
    const result = await identity.login(external, correlationId);
    sendJson(response, 201, {
      actor: { userId: result.actor.userId, email: result.actor.email, provider: external.provider },
      session: result.actor.session,
      organizationId: result.organizationId,
      authenticationState: "AUTHENTICATED",
      providerState: "DEV_ADAPTER",
    }, sessions.cookieHeaders(result.sessionToken, result.csrfToken));
    return;
  }

  if (path === "/auth/invitations/accept" && method === "POST") {
    const body = await readJson(request);
    const external = await identityProvider.resolveExternalIdentity({ headers: request.headers });
    const membership = await identity.acceptInvitation(external, requiredString(body.token, "token"), correlationId);
    sendJson(response, 200, { membership, authenticationState: "IDENTITY_PROVISIONED" });
    return;
  }

  const actor = await identity.actorFromSession(sessionToken);
  const requireCsrf = async (): Promise<void> => sessions.verifyCsrf(sessionToken, csrfHeader);

  if (path === "/auth/me" && method === "GET") {
    const organizationId = actor.session.activeOrganizationId;
    if (!organizationId) {
      sendJson(response, 200, { actor: { userId: actor.userId, email: actor.email }, authenticationState: "AUTHENTICATED", organization: null });
      return;
    }
    const auth = await identity.authorizeOrganization(actor, organizationId, "organization.read", correlationId);
    sendJson(response, 200, {
      actor: { userId: actor.userId, email: actor.email },
      authenticationState: "AUTHENTICATED",
      organization: { id: auth.organizationId, role: auth.role, membershipId: auth.membershipId },
    });
    return;
  }

  if (path === "/auth/logout" && method === "POST") {
    await requireCsrf();
    await identity.logout(actor, correlationId);
    sendJson(response, 204, null, sessions.clearCookieHeaders());
    return;
  }

  if (path === "/auth/switch-organization" && method === "POST") {
    await requireCsrf();
    const body = await readJson(request);
    const session = await identity.switchOrganization(actor, requiredString(body.organizationId, "organizationId"), correlationId);
    sendJson(response, 200, { activeOrganizationId: session.activeOrganizationId, session });
    return;
  }

  if (path === "/organizations" && method === "POST") {
    await requireCsrf();
    const body = await readJson(request);
    const organization = await identity.createOrganization(actor, {
      name: requiredString(body.name, "name"),
      slug: requiredString(body.slug, "slug"),
      correlationId,
    });
    sendJson(response, 201, { organization });
    return;
  }

  const memberMatch = /^\/organizations\/([^/]+)\/members$/.exec(path);
  if (memberMatch && method === "GET") {
    const organizationId = memberMatch[1];
    if (!organizationId) throw new AppError("NOT_FOUND", "Route not found.");
    const auth = await identity.authorizeOrganization(actor, organizationId, "member.read", correlationId);
    const members = await db.membership.findMany({ where: { organizationId: auth.organizationId }, select: { id: true, userId: true, role: true, status: true, version: true } });
    sendJson(response, 200, { organizationId: auth.organizationId, members });
    return;
  }

  const invitationMatch = /^\/organizations\/([^/]+)\/invitations$/.exec(path);
  if (invitationMatch && method === "POST") {
    const organizationId = invitationMatch[1];
    if (!organizationId) throw new AppError("NOT_FOUND", "Route not found.");
    await requireCsrf();
    const body = await readJson(request);
    const auth = await identity.authorizeOrganization(actor, organizationId, "member.invite", correlationId);
    const invitation = await identity.createInvitation(auth, { email: requiredString(body.email, "email"), role: requiredString(body.role, "role"), correlationId });
    sendJson(response, 201, { invitationId: invitation.invitationId, invitedEmail: invitation.invitedEmail, role: invitation.role, expiresAt: invitation.expiresAt, token: invitation.rawToken });
    return;
  }

  throw new AppError("NOT_FOUND", "Route not found.");
}

export function createAppServer(config: AppConfig, logger: StructuredLogger): Server {
  return createHttpServer((request, response) => {
    applySecurityHeaders(response);
    const correlationIdHeader = request.headers["x-correlation-id"] ?? request.headers["x-request-id"];
    const correlationId = (Array.isArray(correlationIdHeader) ? correlationIdHeader[0] : correlationIdHeader)?.trim() || randomUUID();
    response.setHeader("X-Correlation-Id", correlationId);
    const startedAt = Date.now();
    void (async () => {
      try {
        const contentLength = Number(request.headers["content-length"] ?? 0);
        if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BYTES) {
          throw new AppError("VALIDATION_ERROR", "Request body exceeds the 1 MiB limit.");
        }
          await route(request, response, config, correlationId);
        logger.info("http.request.completed", {
          method: request.method,
          path: request.url,
          statusCode: response.statusCode,
          durationMs: Date.now() - startedAt,
        });
      } catch (error) {
        const appError = error instanceof AppError ? error : new AppError("INTERNAL_ERROR", "Unhandled request error.", { cause: error });
        const payload = errorResponse(appError, correlationId);
        sendJson(response, appError.statusCode, payload);
        logger.error("http.request.failed", {
          method: request.method,
          path: request.url,
          statusCode: appError.statusCode,
          errorCode: appError.code,
          errorType: error instanceof Error ? error.name : typeof error,
          durationMs: Date.now() - startedAt,
        });
      }
    })();
  });
}