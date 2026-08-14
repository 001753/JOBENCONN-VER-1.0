import { createHash, randomBytes, randomUUID } from "node:crypto";
import type { Prisma, PrismaClient } from "@prisma/client";
import { AppError } from "./errors.js";

export const SESSION_COOKIE = "joben_session";
export const CSRF_COOKIE = "joben_csrf";

export interface AuthenticatedSession {
  readonly id: string;
  readonly userId: string;
  readonly createdAt: Date;
  readonly expiresAt: Date;
  readonly revokedAt: Date | null;
  readonly activeOrganizationId: string | null;
  readonly version: number;
}

function digest(value: string): string {
  return createHash("sha256").update(value, "utf8").digest("hex");
}

export function parseCookies(header: string | undefined): Record<string, string> {
  const cookies: Record<string, string> = {};
  for (const part of header?.split(";") ?? []) {
    const separator = part.indexOf("=");
    if (separator < 1) continue;
    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();
    if (key) cookies[key] = decodeURIComponent(value);
  }
  return cookies;
}

export function serializeCookie(name: string, value: string, options: { httpOnly?: boolean; secure?: boolean; maxAge?: number; sameSite?: "Lax" | "Strict"; path?: string } = {}): string {
  const parts = [`${name}=${encodeURIComponent(value)}`, `Path=${options.path ?? "/"}`, `SameSite=${options.sameSite ?? "Lax"}`];
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  if (options.maxAge !== undefined) parts.push(`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`);
  return parts.join("; ");
}

function publicSession(row: Prisma.SessionGetPayload<object>): AuthenticatedSession {
  return {
    id: row.id,
    userId: row.userId,
    createdAt: row.createdAt,
    expiresAt: row.expiresAt,
    revokedAt: row.revokedAt,
    activeOrganizationId: row.activeOrganizationId,
    version: row.version,
  };
}

export class SessionManager {
  constructor(
    private readonly db: PrismaClient,
    private readonly ttlSeconds: number,
    private readonly secureCookies: boolean,
  ) {}

  async create(userId: string, activeOrganizationId: string | null = null): Promise<{ session: AuthenticatedSession; sessionToken: string; csrfToken: string }> {
    const sessionToken = randomBytes(32).toString("base64url");
    const csrfToken = randomBytes(32).toString("base64url");
    const now = new Date();
    const row = await this.db.session.create({
      data: {
        id: randomUUID(),
        userId,
        tokenDigest: digest(sessionToken),
        csrfTokenDigest: digest(csrfToken),
        ...(activeOrganizationId ? { activeOrganizationId } : {}),
        createdAt: now,
        expiresAt: new Date(now.getTime() + this.ttlSeconds * 1000),
      },
    });
    return { session: publicSession(row), sessionToken, csrfToken };
  }

  async validate(sessionToken: string | undefined): Promise<AuthenticatedSession> {
    if (!sessionToken) throw new AppError("UNAUTHENTICATED", "Authentication is required.");
    const row = await this.db.session.findUnique({ where: { tokenDigest: digest(sessionToken) } });
    if (!row) throw new AppError("UNAUTHENTICATED", "Authentication is required.");
    if (row.revokedAt) throw new AppError("SESSION_REVOKED", "The session has been revoked.");
    if (row.expiresAt.getTime() <= Date.now()) throw new AppError("SESSION_EXPIRED", "The session has expired.");
    const user = await this.db.user.findUnique({ where: { id: row.userId } });
    if (!user || user.status !== "ACTIVE") throw new AppError("UNAUTHENTICATED", "Authentication is required.");
    await this.db.session.updateMany({ where: { id: row.id, version: row.version, revokedAt: null }, data: { lastUsedAt: new Date() } });
    return publicSession(row);
  }

  async rotate(sessionId: string, expectedVersion: number, userId: string, activeOrganizationId: string | null): Promise<{ session: AuthenticatedSession; sessionToken: string; csrfToken: string }> {
    const result = await this.db.session.updateMany({
      where: { id: sessionId, userId, version: expectedVersion, revokedAt: null },
      data: { revokedAt: new Date(), version: { increment: 1 } },
    });
    if (result.count !== 1) throw new AppError("CONCURRENCY_CONFLICT", "The session was changed or revoked.");
    return this.create(userId, activeOrganizationId);
  }

  async revoke(sessionId: string, userId: string): Promise<void> {
    await this.db.session.updateMany({ where: { id: sessionId, userId, revokedAt: null }, data: { revokedAt: new Date(), version: { increment: 1 } } });
  }

  async revokeAllUserSessions(userId: string): Promise<void> {
    await this.db.session.updateMany({ where: { userId, revokedAt: null }, data: { revokedAt: new Date(), version: { increment: 1 } } });
  }

  async setActiveOrganization(sessionId: string, userId: string, organizationId: string, expectedVersion: number): Promise<AuthenticatedSession> {
    const result = await this.db.session.updateMany({
      where: { id: sessionId, userId, version: expectedVersion, revokedAt: null },
      data: { activeOrganizationId: organizationId, version: { increment: 1 } },
    });
    if (result.count !== 1) throw new AppError("CONCURRENCY_CONFLICT", "The session was changed or revoked.");
    const row = await this.db.session.findUnique({ where: { id: sessionId } });
    if (!row) throw new AppError("UNAUTHENTICATED", "Authentication is required.");
    return publicSession(row);
  }

  async verifyCsrf(sessionToken: string | undefined, csrfToken: string | undefined): Promise<void> {
    const session = await this.validate(sessionToken);
    if (!csrfToken) throw new AppError("FORBIDDEN", "CSRF protection rejected the request.");
    const row = await this.db.session.findUnique({ where: { id: session.id } });
    if (!row || digest(csrfToken) !== row.csrfTokenDigest) throw new AppError("FORBIDDEN", "CSRF protection rejected the request.");
  }

  cookieHeaders(sessionToken: string, csrfToken: string): string[] {
    return [
      serializeCookie(SESSION_COOKIE, sessionToken, { httpOnly: true, secure: this.secureCookies, maxAge: this.ttlSeconds }),
      serializeCookie(CSRF_COOKIE, csrfToken, { secure: this.secureCookies, maxAge: this.ttlSeconds }),
    ];
  }

  clearCookieHeaders(): string[] {
    return [
      serializeCookie(SESSION_COOKIE, "", { httpOnly: true, secure: this.secureCookies, maxAge: 0 }),
      serializeCookie(CSRF_COOKIE, "", { secure: this.secureCookies, maxAge: 0 }),
    ];
  }
}