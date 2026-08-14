import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AppConfig } from "./config.js";
import { AppError, errorResponse } from "./errors.js";
import { StructuredLogger } from "./logger.js";

const MAX_REQUEST_BYTES = 1_048_576;

function sendJson(response: ServerResponse, statusCode: number, payload: unknown): void {
  const body = JSON.stringify(payload);
  response.statusCode = statusCode;
  response.setHeader("Content-Type", "application/json; charset=utf-8");
  response.setHeader("Content-Length", Buffer.byteLength(body));
  response.end(body);
}

function applySecurityHeaders(response: ServerResponse): void {
  response.setHeader("X-Content-Type-Options", "nosniff");
  response.setHeader("X-Frame-Options", "DENY");
  response.setHeader("Referrer-Policy", "no-referrer");
  response.setHeader("Cache-Control", "no-store");
}

function route(request: IncomingMessage, response: ServerResponse, config: AppConfig): void {
  const method = request.method ?? "GET";
  const path = new URL(request.url ?? "/", "http://joben.local").pathname;

  if (method !== "GET") {
    throw new AppError("VALIDATION_ERROR", "Only GET requests are supported by the P0 foundation.");
  }

  if (path === "/health/live") {
    sendJson(response, 200, { status: "ok", endpoint: "liveness", capabilityState: "IMPLEMENTED" });
    return;
  }
  if (path === "/health/ready") {
    sendJson(response, 200, {
      status: "ready",
      endpoint: "readiness",
      checks: { configuration: "pass" },
      note: "No external dependency is required by the current P0 foundation.",
    });
    return;
  }

  void config;
  throw new AppError("NOT_FOUND", "Route not found.");
}

export function createAppServer(config: AppConfig, logger: StructuredLogger): Server {
  return createHttpServer((request, response) => {
    applySecurityHeaders(response);
    const startedAt = Date.now();
    try {
      const contentLength = Number(request.headers["content-length"] ?? 0);
      if (Number.isFinite(contentLength) && contentLength > MAX_REQUEST_BYTES) {
        throw new AppError("VALIDATION_ERROR", "Request body exceeds the 1 MiB limit.");
      }
      route(request, response, config);
      logger.info("http.request.completed", {
        method: request.method,
        path: request.url,
        statusCode: response.statusCode,
        durationMs: Date.now() - startedAt,
      });
    } catch (error) {
      const appError = error instanceof AppError ? error : new AppError("INTERNAL_ERROR", "Unhandled request error.", { cause: error });
      const payload = errorResponse(appError);
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
  });
}