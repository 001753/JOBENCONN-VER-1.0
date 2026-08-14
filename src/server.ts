import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { randomUUID } from "node:crypto";
import { type EvidenceType } from "@prisma/client";
import type { AppConfig } from "./config.js";
import type { Permission } from "./authorization.js";
import { checkDatabaseConnection, getPrismaClient } from "./database.js";
import { AppError, errorResponse } from "./errors.js";
import { DevIdentityProvider, ClerkIdentityProvider } from "./identity-provider.js";
import { IdentityService } from "./identity-service.js";
import { StructuredLogger } from "./logger.js";
import { SessionManager, SESSION_COOKIE, parseCookies } from "./session.js";
import { FixedWindowRateLimiter } from "./rate-limit.js";
import { AwsService, customerAwsAuthorization } from "./aws-service.js";
import { SecurityAnalysisService, customerSecurityAuthorization } from "./security-service.js";
import { EvidenceService } from "./evidence-service.js";
import { DefaultAwsReadOnlyDiscoveryClientFactory } from "./aws-service.js";
import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

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

function sendText(response: ServerResponse, statusCode: number, body: string, contentType: string): void {
  response.statusCode = statusCode;
  response.setHeader("Content-Type", `${contentType}; charset=utf-8`);
  response.setHeader("Content-Length", Buffer.byteLength(body));
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

function requiredDate(value: unknown, field: string): Date {
  const date = new Date(requiredString(value, field));
  if (Number.isNaN(date.getTime())) throw new AppError("VALIDATION_ERROR", `${field} must be a valid timestamp.`);
  return date;
}

function evidenceType(value: unknown): EvidenceType {
  if (value === "PROVIDER_RESPONSE" || value === "INVENTORY_SNAPSHOT" || value === "SCAN_CHECK" || value === "CONFIGURATION") return value;
  throw new AppError("VALIDATION_ERROR", "type must be a supported evidence type.");
}

function optionalString(value: unknown, field: string): string | undefined {
  if (value === undefined || value === null) return undefined;
  if (typeof value !== "string" || !value.trim()) throw new AppError("VALIDATION_ERROR", `${field} must be a non-empty string when provided.`);
  return value.trim();
}

function requiredUuid(value: string, field: string): string {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
    throw new AppError("NOT_FOUND", `${field} not found.`);
  }
  return value;
}

async function route(
  request: IncomingMessage,
  response: ServerResponse,
  config: AppConfig,
  correlationId: string,
  evidence: EvidenceService,
): Promise<void> {
  const method = request.method ?? "GET";
  const path = new URL(request.url ?? "/", "http://joben.local").pathname;

  if (path === "/" || path === "/dashboard") {
    if (method !== "GET") throw new AppError("VALIDATION_ERROR", "Dashboard is read-only.");
    const html = await readFile(resolve(process.cwd(), "public/dashboard.html"), "utf8");
    sendText(response, 200, html, "text/html");
    return;
  }
  if (path === "/dashboard.css" || path === "/dashboard.js") {
    if (method !== "GET") throw new AppError("VALIDATION_ERROR", "Dashboard assets are read-only.");
    const asset = await readFile(resolve(process.cwd(), "public", path.slice(1)), "utf8");
    sendText(response, 200, asset, path.endsWith(".css") ? "text/css" : "application/javascript");
    return;
  }

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
  const aws = new AwsService(db);
  const security = new SecurityAnalysisService(db, undefined, new DefaultAwsReadOnlyDiscoveryClientFactory());
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

  const awsAuthorization = async () => {
    const organizationId = actor.session.activeOrganizationId;
    if (!organizationId) throw new AppError("ORG_NOT_FOUND", "An active organization is required.");
    const organization = await identity.authorizeOrganization(actor, organizationId, "organization.read", correlationId);
    return customerAwsAuthorization({ actorUserId: actor.userId, organizationId: organization.organizationId, role: organization.role });
  };

  const securityAuthorization = async (permission: "findings.read" | "findings.run" | "findings.acknowledge" | "findings.resolve" | "scan.read" | "scan.create" | "scan.cancel" | "scan.dead_letter.replay" | "scan.recovery" | "scan.circuit_breaker.recover") => {
    const organizationId = actor.session.activeOrganizationId;
    if (!organizationId) throw new AppError("ORG_NOT_FOUND", "An active organization is required.");
    const organization = await identity.authorizeOrganization(actor, organizationId, permission, correlationId);
    return customerSecurityAuthorization({
      actorUserId: actor.userId,
      organizationId: organization.organizationId,
      role: organization.role,
      context: organization.context,
    });
  };

  const evidenceAuthorization = async (permission: Extract<Permission, `evidence.${string}`>) => {
    const organizationId = actor.session.activeOrganizationId;
    if (!organizationId) throw new AppError("ORG_NOT_FOUND", "An active organization is required.");
    const organization = await identity.authorizeOrganization(actor, organizationId, permission, correlationId);
    return {
      kind: "customer" as const,
      actorUserId: actor.userId,
      organizationId: organization.organizationId,
      role: organization.role,
    };
  };

  if (path === "/evidence" && method === "POST") {
    await requireCsrf();
    const body = await readJson(request);
    const auth = await evidenceAuthorization("evidence.commit");
    const observedFacts = body.observedFacts === undefined
      ? undefined
      : Array.isArray(body.observedFacts)
        ? body.observedFacts.map((fact, index) => {
          if (!fact || typeof fact !== "object" || Array.isArray(fact)) throw new AppError("VALIDATION_ERROR", `observedFacts[${index}] must be an object.`);
          const record = fact as Record<string, unknown>;
          return {
            provider: requiredString(record.provider, `observedFacts[${index}].provider`),
            resourceKey: requiredString(record.resourceKey, `observedFacts[${index}].resourceKey`),
            observedAt: requiredDate(record.observedAt, `observedFacts[${index}].observedAt`),
            payloadSchema: requiredString(record.payloadSchema, `observedFacts[${index}].payloadSchema`),
            extractedFields: record.extractedFields,
          };
        })
        : (() => { throw new AppError("VALIDATION_ERROR", "observedFacts must be an array."); })();
    const sourceIntegrationId = optionalString(body.sourceIntegrationId, "sourceIntegrationId");
    const scanRunId = optionalString(body.scanRunId, "scanRunId");
    const scanCheckOutcomeId = optionalString(body.scanCheckOutcomeId, "scanCheckOutcomeId");
    const providerRequestId = optionalString(body.providerRequestId, "providerRequestId");
    const sourceEndpoint = optionalString(body.sourceEndpoint, "sourceEndpoint");
    const committed = await evidence.commit(auth, {
      type: evidenceType(body.type),
      provider: requiredString(body.provider, "provider"),
      schemaVersion: requiredString(body.schemaVersion, "schemaVersion"),
      collectedAt: requiredDate(body.collectedAt, "collectedAt"),
      retentionUntil: requiredDate(body.retentionUntil, "retentionUntil"),
      payload: body.payload,
      correlationId,
      ...(sourceIntegrationId !== undefined ? { sourceIntegrationId } : {}),
      ...(scanRunId !== undefined ? { scanRunId } : {}),
      ...(scanCheckOutcomeId !== undefined ? { scanCheckOutcomeId } : {}),
      ...(providerRequestId !== undefined ? { providerRequestId } : {}),
      ...(sourceEndpoint !== undefined ? { sourceEndpoint } : {}),
      ...(observedFacts ? { observedFacts } : {}),
    });
    sendJson(response, 201, { evidence: committed });
    return;
  }

  const legalHoldReleaseMatch = /^\/evidence\/legal-holds\/([^/]+)\/release$/.exec(path);
  if (legalHoldReleaseMatch && method === "POST") {
    await requireCsrf();
    const holdId = legalHoldReleaseMatch[1];
    if (!holdId) throw new AppError("NOT_FOUND", "Route not found.");
    const auth = await evidenceAuthorization("evidence.legal_hold");
    sendJson(response, 200, { legalHold: await evidence.releaseLegalHold({ auth, correlationId }, requiredUuid(holdId, "Legal hold")) });
    return;
  }

  const evidenceMatch = /^\/evidence\/([^/]+)(?:\/(content|verify|legal-hold|supersede))?$/.exec(path);
  if (evidenceMatch) {
    const evidenceId = evidenceMatch[1];
    const action = evidenceMatch[2];
    if (!evidenceId) throw new AppError("NOT_FOUND", "Route not found.");
    const validEvidenceId = requiredUuid(evidenceId, "Evidence");
    if (method === "GET" && !action) {
      const auth = await evidenceAuthorization("evidence.read");
      sendJson(response, 200, { evidence: await evidence.getMetadata({ auth, correlationId }, validEvidenceId) });
      return;
    }
    if (method === "GET" && action === "content") {
      const auth = await evidenceAuthorization("evidence.read");
      const retrieved = await evidence.retrieve({ auth, correlationId }, validEvidenceId);
      sendJson(response, 200, {
        evidence: retrieved.metadata,
        canonicalPayload: Buffer.from(retrieved.bytes).toString("utf8"),
      });
      return;
    }
    if (method === "POST" && action === "verify") {
      await requireCsrf();
      const auth = await evidenceAuthorization("evidence.verify");
      sendJson(response, 200, { evidence: await evidence.verify({ auth, correlationId }, validEvidenceId) });
      return;
    }
    if (method === "POST" && action === "legal-hold") {
      await requireCsrf();
      const body = await readJson(request);
      const auth = await evidenceAuthorization("evidence.legal_hold");
      sendJson(response, 201, { legalHold: await evidence.createLegalHold({ auth, correlationId }, validEvidenceId, requiredString(body.reason, "reason")) });
      return;
    }
    if (method === "POST" && action === "supersede") {
      await requireCsrf();
      const body = await readJson(request);
      const auth = await evidenceAuthorization("evidence.supersede");
      sendJson(response, 201, { evidence: await evidence.supersede({ auth, correlationId }, validEvidenceId, {
        type: evidenceType(body.type),
        provider: requiredString(body.provider, "provider"),
        schemaVersion: requiredString(body.schemaVersion, "schemaVersion"),
        collectedAt: requiredDate(body.collectedAt, "collectedAt"),
        retentionUntil: requiredDate(body.retentionUntil, "retentionUntil"),
        payload: body.payload,
        correlationId,
      }) });
      return;
    }
    if (method === "DELETE" && !action) {
      await requireCsrf();
      const auth = await evidenceAuthorization("evidence.delete");
      await evidence.deleteExpired({ auth, correlationId }, validEvidenceId);
      sendJson(response, 204, null);
      return;
    }
  }

  if (path === "/aws/connections" && method === "GET") {
    const auth = await awsAuthorization();
    sendJson(response, 200, { connections: await aws.listConnections(auth) });
    return;
  }

  if (path === "/aws/connections" && method === "POST") {
    await requireCsrf();
    const body = await readJson(request);
    const auth = await awsAuthorization();
    const connection = await aws.createConnection(auth, {
      name: requiredString(body.name, "name"),
      credentialSource: requiredString(body.credentialSource, "credentialSource"),
      ...(typeof body.roleArn === "string" ? { roleArn: body.roleArn.trim() } : {}),
    }, correlationId);
    sendJson(response, 201, connection);
    return;
  }

  const awsConnectionMatch = /^\/aws\/connections\/([^/]+)(?:\/(verify|revoke))?$/.exec(path);
  if (awsConnectionMatch) {
    const connectionId = awsConnectionMatch[1];
    const action = awsConnectionMatch[2];
    if (!connectionId) throw new AppError("NOT_FOUND", "Route not found.");
    const auth = await awsAuthorization();
    if (method === "GET" && !action) {
      sendJson(response, 200, { connection: await aws.getConnection(auth, connectionId) });
      return;
    }
    if (method === "POST" && action === "verify") {
      await requireCsrf();
      sendJson(response, 200, await aws.verifyConnection(auth, connectionId, correlationId));
      return;
    }
    if (method === "POST" && action === "revoke") {
      await requireCsrf();
      await aws.revokeConnection(auth, connectionId, correlationId);
      sendJson(response, 204, null);
      return;
    }
  }

  if (path === "/aws/accounts" && method === "GET") {
    const auth = await awsAuthorization();
    sendJson(response, 200, { accounts: await aws.listAccounts(auth) });
    return;
  }

  const awsDiscoveryMatch = /^\/aws\/accounts\/([^/]+)\/discovery$/.exec(path);
  if (awsDiscoveryMatch) {
    const accountId = awsDiscoveryMatch[1];
    if (!accountId) throw new AppError("NOT_FOUND", "Route not found.");
    const auth = await awsAuthorization();
    if (method === "GET") {
      sendJson(response, 200, { runs: await aws.listRuns(auth, accountId) });
      return;
    }
    if (method === "POST") {
      await requireCsrf();
      const body = await readJson(request);
      const idempotencyKey = typeof body.idempotencyKey === "string" ? body.idempotencyKey : undefined;
      sendJson(response, 200, { run: await aws.runDiscovery(auth, accountId, correlationId, idempotencyKey) });
      return;
    }
  }

  const awsResourcesMatch = /^\/aws\/accounts\/([^/]+)\/resources$/.exec(path);
  if (awsResourcesMatch && method === "GET") {
    const accountId = awsResourcesMatch[1];
    if (!accountId) throw new AppError("NOT_FOUND", "Route not found.");
    const auth = await awsAuthorization();
    sendJson(response, 200, { resources: await aws.listResources(auth, accountId) });
    return;
  }

  const securityScanMatch = /^\/security\/accounts\/([^/]+)\/scans$/.exec(path);
  if (securityScanMatch) {
    const accountId = securityScanMatch[1];
    if (!accountId) throw new AppError("NOT_FOUND", "Route not found.");
    if (method === "GET") {
      const auth = await securityAuthorization("scan.read");
      const url = new URL(request.url ?? "/", "http://joben.local");
      const parsePositive = (value: string | null, fallback: number, max: number, field: string): number => {
        if (value === null) return fallback;
        const parsed = Number(value);
        if (!Number.isInteger(parsed) || parsed < 1 || parsed > max) throw new AppError("VALIDATION_ERROR", `${field} must be a positive integer within a safe range.`);
        return parsed;
      };
      const status = url.searchParams.get("status") as "QUEUED" | "RUNNING" | "CANCELLING" | "COMPLETED" | "PARTIAL" | "FAILED" | "CANCELLED" | "DEAD_LETTER" | null;
      const validStatuses = ["QUEUED", "RUNNING", "CANCELLING", "COMPLETED", "PARTIAL", "FAILED", "CANCELLED", "DEAD_LETTER"] as const;
      if (status && !validStatuses.includes(status)) throw new AppError("VALIDATION_ERROR", "status is invalid.");
      const from = url.searchParams.get("from");
      const to = url.searchParams.get("to");
      const parseDate = (value: string | null, field: string): Date | undefined => {
        if (!value) return undefined;
        const parsed = new Date(value);
        if (Number.isNaN(parsed.getTime())) throw new AppError("VALIDATION_ERROR", `${field} must be an ISO date.`);
        return parsed;
      };
      const parsedFrom = from ? parseDate(from, "from") : undefined;
      const parsedTo = to ? parseDate(to, "to") : undefined;
      const cursor = url.searchParams.get("cursor");
      sendJson(response, 200, await security.listScans(auth, accountId, {
        ...(cursor ? { cursor } : { page: parsePositive(url.searchParams.get("page"), 1, 1_000_000, "page") }),
        pageSize: parsePositive(url.searchParams.get("pageSize"), 50, 100, "pageSize"),
        ...(status ? { status } : {}),
        ...(parsedFrom ? { from: parsedFrom } : {}),
        ...(parsedTo ? { to: parsedTo } : {}),
      }));
      return;
    }
    if (method === "POST") {
      await requireCsrf();
      const body = await readJson(request);
      const auth = await securityAuthorization("scan.create");
      const idempotencyKey = typeof body.idempotencyKey === "string" ? body.idempotencyKey : undefined;
      sendJson(response, 202, { scan: await security.enqueueScan(auth, accountId, correlationId, idempotencyKey) });
      return;
    }
  }

  if (path === "/security/queue" && method === "GET") {
    const auth = await securityAuthorization("scan.read");
    sendJson(response, 200, { backlog: await security.queueBacklog(auth) });
    return;
  }

  if (path === "/dashboard/summary" && method === "GET") {
    const auth = await securityAuthorization("scan.read");
    sendJson(response, 200, { summary: await security.getDashboardSummary(auth) });
    return;
  }

  if (path === "/security/controls" && method === "GET") {
    const auth = await securityAuthorization("findings.read");
    sendJson(response, 200, {
      controls: [{
        checkId: "AWS-IAM-ROOT-MFA",
        checkVersion: "1",
        provider: "aws",
        service: "IAM",
        operation: "IAM.GetAccountSummary",
        resourceType: "AWS:IAM:root-account",
        requiredPermissions: ["iam:GetAccountSummary"],
        evaluatorVersion: "1",
        statusStates: ["PASS", "FAIL", "ERROR", "NOT_APPLICABLE"],
        source: "src/root-mfa-control.ts",
      }],
      results: await security.listControlResults(auth),
    });
    return;
  }

  const controlResultMatch = /^\/security\/control-results\/([^/]+)$/.exec(path);
  if (controlResultMatch && method === "GET") {
    const auth = await securityAuthorization("findings.read");
    sendJson(response, 200, { result: await security.getControlResult(auth, controlResultMatch[1]!) });
    return;
  }

  const scanControlResultsMatch = /^\/security\/scans\/([^/]+)\/control-results$/.exec(path);
  if (scanControlResultsMatch && method === "GET") {
    const auth = await securityAuthorization("findings.read");
    sendJson(response, 200, { results: await security.listControlResults(auth, scanControlResultsMatch[1]!) });
    return;
  }

  if (path === "/security/schedules" && method === "GET") {
    const auth = await securityAuthorization("scan.read");
    sendJson(response, 200, { schedules: await security.listSchedules(auth) });
    return;
  }

  if (path === "/security/schedules" && method === "POST") {
    await requireCsrf();
    const body = await readJson(request);
    const auth = await securityAuthorization("scan.create");
    sendJson(response, 201, { schedule: await security.createSchedule(auth, {
      accountId: requiredString(body.accountId, "accountId"),
      name: requiredString(body.name, "name"),
      frequency: requiredString(body.frequency, "frequency"),
      localTime: requiredString(body.localTime, "localTime"),
      timezone: requiredString(body.timezone, "timezone"),
    }, correlationId) });
    return;
  }

  const schedulePauseMatch = /^\/security\/schedules\/([^/]+)\/pause$/.exec(path);
  if (schedulePauseMatch && method === "POST") {
    await requireCsrf();
    const body = await readJson(request);
    const auth = await securityAuthorization("scan.create");
    sendJson(response, 200, { schedule: await security.pauseSchedule(auth, schedulePauseMatch[1]!, body.paused === true, correlationId) });
    return;
  }

  const scanDetailMatch = /^\/security\/scans\/([^/]+)$/.exec(path);
  if (scanDetailMatch && method === "GET") {
    const scanId = scanDetailMatch[1];
    if (!scanId) throw new AppError("NOT_FOUND", "Route not found.");
    const auth = await securityAuthorization("findings.read");
    sendJson(response, 200, { scan: await security.getScan(auth, scanId) });
    return;
  }

  const scanProgressMatch = /^\/security\/scans\/([^/]+)\/progress$/.exec(path);
  if (scanProgressMatch && method === "GET") {
    const scanId = scanProgressMatch[1];
    if (!scanId) throw new AppError("NOT_FOUND", "Route not found.");
    const auth = await securityAuthorization("scan.read");
    sendJson(response, 200, { scan: await security.getScanProgress(auth, scanId) });
    return;
  }

  const scanOutcomesMatch = /^\/security\/scans\/([^/]+)\/outcomes$/.exec(path);
  if (scanOutcomesMatch && method === "GET") {
    const auth = await securityAuthorization("scan.read");
    sendJson(response, 200, { outcomes: await security.listScanOutcomes(auth, scanOutcomesMatch[1]!) });
    return;
  }

  const scanCancelMatch = /^\/security\/scans\/([^/]+)\/cancel$/.exec(path);
  if (scanCancelMatch && method === "POST") {
    const scanId = scanCancelMatch[1];
    if (!scanId) throw new AppError("NOT_FOUND", "Route not found.");
    await requireCsrf();
    const auth = await securityAuthorization("scan.cancel");
    sendJson(response, 202, { scan: await security.cancelScan(auth, scanId, correlationId) });
    return;
  }

  const scanReplayMatch = /^\/security\/scans\/([^/]+)\/replay$/.exec(path);
  if (scanReplayMatch && method === "POST") {
    await requireCsrf();
    const auth = await securityAuthorization("scan.dead_letter.replay");
    sendJson(response, 202, { scan: await security.replayDeadLetter(auth, scanReplayMatch[1]!, correlationId) });
    return;
  }

  if (path === "/security/findings" && method === "GET") {
    const url = new URL(request.url ?? "/", "http://joben.local");
    const parsePositive = (value: string | null, fallback: number, max: number, field: string): number => {
      if (value === null) return fallback;
      const parsed = Number(value);
      if (!Number.isInteger(parsed) || parsed < 1 || parsed > max) throw new AppError("VALIDATION_ERROR", `${field} must be a positive integer within a safe range.`);
      return parsed;
    };
    const auth = await securityAuthorization("findings.read");
    const allowed = <T extends string>(value: string | null, values: readonly T[], field: string): T | undefined => {
      if (value === null) return undefined;
      if (!values.includes(value as T)) throw new AppError("VALIDATION_ERROR", `${field} is invalid.`);
      return value as T;
    };
    const severity = allowed(url.searchParams.get("severity"), ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"], "severity");
    const status = allowed(url.searchParams.get("status"), ["OPEN", "ACKNOWLEDGED", "RESOLVED"], "status");
    const ruleId = url.searchParams.get("ruleId")?.trim();
    const resourceType = url.searchParams.get("resourceType")?.trim();
    const awsAccountId = url.searchParams.get("awsAccountId")?.trim();
    const region = url.searchParams.get("region")?.trim();
    sendJson(response, 200, await security.listFindings(auth, {
      ...(severity ? { severity } : {}),
      ...(status ? { status } : {}),
      ...(ruleId ? { ruleId } : {}),
      ...(resourceType ? { resourceType } : {}),
      ...(awsAccountId ? { awsAccountId } : {}),
      ...(region ? { region } : {}),
      page: parsePositive(url.searchParams.get("page"), 1, 1_000_000, "page"),
      pageSize: parsePositive(url.searchParams.get("pageSize"), 50, 100, "pageSize"),
    }));
    return;
  }

  const findingDetailMatch = /^\/security\/findings\/([^/]+)(?:\/(acknowledge|resolve))?$/.exec(path);
  if (findingDetailMatch) {
    const findingId = findingDetailMatch[1];
    const action = findingDetailMatch[2];
    if (!findingId) throw new AppError("NOT_FOUND", "Route not found.");
    if (method === "GET" && !action) {
      const auth = await securityAuthorization("findings.read");
      sendJson(response, 200, { finding: await security.getFinding(auth, findingId) });
      return;
    }
    if (method === "POST" && action === "acknowledge") {
      await requireCsrf();
      const auth = await securityAuthorization("findings.acknowledge");
      sendJson(response, 200, { finding: await security.acknowledgeFinding(auth, findingId, correlationId) });
      return;
    }
    if (method === "POST" && action === "resolve") {
      await requireCsrf();
      const body = await readJson(request);
      const auth = await securityAuthorization("findings.resolve");
      sendJson(response, 200, { finding: await security.resolveFinding(auth, findingId, requiredString(body.reason, "reason"), correlationId) });
      return;
    }
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
  const evidence = new EvidenceService(getPrismaClient());
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
          await route(request, response, config, correlationId, evidence);
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