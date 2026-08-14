export type ErrorCode =
  | "VALIDATION_ERROR"
  | "AUTHENTICATION_ERROR"
  | "AUTHORIZATION_ERROR"
  | "UNAUTHENTICATED"
  | "SESSION_EXPIRED"
  | "SESSION_REVOKED"
  | "FORBIDDEN"
  | "ORG_NOT_FOUND"
  | "NOT_A_MEMBER"
  | "MEMBERSHIP_SUSPENDED"
  | "ROLE_INSUFFICIENT"
  | "INVITATION_EXPIRED"
  | "INVITATION_REVOKED"
  | "INVITATION_ALREADY_USED"
  | "LAST_OWNER_PROTECTED"
  | "CONCURRENCY_CONFLICT"
  | "NOT_FOUND"
  | "CONFLICT"
  | "CONFIGURATION_ERROR"
  | "DEPENDENCY_ERROR"
  | "AWS_ERROR"
  | "NOT_IMPLEMENTED"
  | "INTERNAL_ERROR";

const statusByCode: Record<ErrorCode, number> = {
  VALIDATION_ERROR: 400,
  AUTHENTICATION_ERROR: 401,
  AUTHORIZATION_ERROR: 403,
  UNAUTHENTICATED: 401,
  SESSION_EXPIRED: 401,
  SESSION_REVOKED: 401,
  FORBIDDEN: 403,
  ORG_NOT_FOUND: 404,
  NOT_A_MEMBER: 403,
  MEMBERSHIP_SUSPENDED: 403,
  ROLE_INSUFFICIENT: 403,
  INVITATION_EXPIRED: 410,
  INVITATION_REVOKED: 410,
  INVITATION_ALREADY_USED: 409,
  LAST_OWNER_PROTECTED: 409,
  CONCURRENCY_CONFLICT: 409,
  NOT_FOUND: 404,
  CONFLICT: 409,
  CONFIGURATION_ERROR: 500,
  DEPENDENCY_ERROR: 503,
  AWS_ERROR: 502,
  NOT_IMPLEMENTED: 501,
  INTERNAL_ERROR: 500,
};

export class AppError extends Error {
  readonly code: ErrorCode;
  readonly statusCode: number;
  readonly expose: boolean;

  constructor(code: ErrorCode, message: string, options: { cause?: unknown; expose?: boolean } = {}) {
    super(message, { cause: options.cause });
    this.name = "AppError";
    this.code = code;
    this.statusCode = statusByCode[code];
    this.expose = options.expose ?? (code !== "INTERNAL_ERROR" && code !== "CONFIGURATION_ERROR");
  }
}

export function errorResponse(error: unknown, correlationId?: string): {
  error: { code: ErrorCode; message: string };
  correlationId?: string;
} {
  if (error instanceof AppError && error.expose) {
    return { error: { code: error.code, message: error.message }, ...(correlationId ? { correlationId } : {}) };
  }
  return {
    error: {
      code: "INTERNAL_ERROR",
      message: "An unexpected error occurred.",
    },
    ...(correlationId ? { correlationId } : {}),
  };
}