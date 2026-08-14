import type { IncomingHttpHeaders } from "node:http";
import { AppError } from "./errors.js";

export interface ExternalIdentity {
  readonly provider: string;
  readonly subject: string;
  readonly verified: boolean;
  readonly email?: string;
  readonly displayName?: string;
}

export interface IdentityProvider {
  readonly name: string;
  resolveExternalIdentity(input: { headers: IncomingHttpHeaders }): Promise<ExternalIdentity>;
}

function normalizedEmail(email: string | undefined): string | undefined {
  const value = email?.trim().toLowerCase();
  return value || undefined;
}

/**
 * Deliberately development/test-only. It is a deterministic adapter for
 * exercising the application identity boundary without pretending to be a
 * production identity provider.
 */
export class DevIdentityProvider implements IdentityProvider {
  readonly name = "dev";

  constructor(private readonly enabled: boolean) {}

  async resolveExternalIdentity(input: { headers: IncomingHttpHeaders }): Promise<ExternalIdentity> {
    if (!this.enabled) {
      throw new AppError("AUTHENTICATION_ERROR", "The development identity provider is disabled.");
    }
    const subject = input.headers["x-dev-identity"];
    const email = input.headers["x-dev-email"];
    const subjectValue = Array.isArray(subject) ? subject[0] : subject;
    const emailValue = Array.isArray(email) ? email[0] : email;
    if (!subjectValue?.trim()) {
      throw new AppError("UNAUTHENTICATED", "A verified external identity is required.");
    }
    const normalized = normalizedEmail(emailValue);
    return {
      provider: "dev",
      subject: subjectValue.trim(),
      verified: true,
      ...(normalized ? { email: normalized } : {}),
    };
  }
}

/**
 * Clerk remains behind this boundary until a Clerk verification dependency and
 * verified production connection are explicitly configured. No unverified
 * request is accepted as a Clerk identity.
 */
export class ClerkIdentityProvider implements IdentityProvider {
  readonly name = "clerk";

  constructor(private readonly secretKey: string | undefined) {}

  async resolveExternalIdentity(_input: { headers: IncomingHttpHeaders }): Promise<ExternalIdentity> {
    if (!this.secretKey) {
      throw new AppError("AUTHENTICATION_ERROR", "Clerk identity verification is not configured.", { expose: false });
    }
    throw new AppError("NOT_IMPLEMENTED", "Clerk verification requires the configured Clerk SDK adapter.");
  }
}

export class StaticIdentityProvider implements IdentityProvider {
  readonly name = "test";

  constructor(private readonly identity: ExternalIdentity) {}

  async resolveExternalIdentity(): Promise<ExternalIdentity> {
    return this.identity;
  }
}

export function externalIdentityRef(identity: ExternalIdentity): string {
  const provider = identity.provider.trim();
  const subject = identity.subject.trim();
  if (!provider || !subject || provider.length > 80 || subject.length > 240) {
    throw new AppError("AUTHENTICATION_ERROR", "External identity reference is invalid.");
  }
  return `${provider}:${subject}`;
}

export function normalizeIdentityEmail(email: string | undefined): string | undefined {
  return normalizedEmail(email);
}