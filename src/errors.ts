export type ErrorCode =
  | "VALIDATION_ERROR"
  | "AUTHENTICATION_ERROR"
  | "AUTHORIZATION_ERROR"
  | "NOT_FOUND"
  | "CONFLICT"
  | "CONFIGURATION_ERROR"
  | "DEPENDENCY_ERROR"
  | "NOT_IMPLEMENTED"
  | "INTERNAL_ERROR";

const statusByCode: Record<ErrorCode, number> = {
  VALIDATION_ERROR: 400,
  AUTHENTICATION_ERROR: 401,
  AUTHORIZATION_ERROR: 403,
  NOT_FOUND: 404,
  CONFLICT: 409,
  CONFIGURATION_ERROR: 500,
  DEPENDENCY_ERROR: 503,
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

export function errorResponse(error: unknown): {
  error: { code: ErrorCode; message: string };
} {
  if (error instanceof AppError && error.expose) {
    return { error: { code: error.code, message: error.message } };
  }
  return {
    error: {
      code: "INTERNAL_ERROR",
      message: "An unexpected error occurred.",
    },
  };
}