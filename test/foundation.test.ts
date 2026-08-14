import assert from "node:assert/strict";
import { once } from "node:events";
import { request } from "node:http";
import test from "node:test";
import { loadConfig } from "../src/config.js";
import { errorResponse } from "../src/errors.js";
import { redactSensitive, StructuredLogger } from "../src/logger.js";
import { createAppServer } from "../src/server.js";

test("development configuration is deterministic without secrets", () => {
  const config = loadConfig({ NODE_ENV: "development" });
  assert.equal(config.environment, "development");
  assert.equal(config.port, 5000);
  assert.equal(config.databaseUrl, undefined);
});

test("production configuration fails when durable database configuration is absent", () => {
  assert.throws(
    () => loadConfig({ NODE_ENV: "production" }),
    /Required production configuration is missing: DATABASE_URL/,
  );
});

test("liveness and readiness are distinct foundation endpoints", async (t) => {
  const config = loadConfig({ NODE_ENV: "test" });
  const server = createAppServer(config, new StructuredLogger("error", () => undefined));
  t.after(() => server.close());
  server.listen(0);
  await once(server, "listening");
  const address = server.address();
  assert.ok(address && typeof address !== "string");

  const get = (path: string) =>
    new Promise<{ statusCode: number; body: string }>((resolve, reject) => {
      const req = request({ port: address.port, path, method: "GET" }, (response) => {
        let body = "";
        response.setEncoding("utf8");
        response.on("data", (chunk) => (body += chunk));
        response.on("end", () => resolve({ statusCode: response.statusCode ?? 0, body }));
      });
      req.on("error", reject);
      req.end();
    });

  const live = await get("/health/live");
  const ready = await get("/health/ready");
  assert.equal(live.statusCode, 200);
  assert.equal(JSON.parse(live.body).endpoint, "liveness");
  assert.equal(ready.statusCode, 200);
  assert.equal(JSON.parse(ready.body).endpoint, "readiness");
});

test("unknown routes use the safe error boundary", async () => {
  const response = errorResponse({ unexpected: "internal detail" });
  assert.deepEqual(response, { error: { code: "INTERNAL_ERROR", message: "An unexpected error occurred." } });
});

test("structured logs redact sensitive fields", () => {
  const lines: string[] = [];
  const logger = new StructuredLogger("info", (line) => lines.push(line));
  logger.info("test.event", { password: "do-not-print", nested: { authorization: "secret-token" }, safe: "visible" });
  assert.equal(lines.length, 1);
  assert.doesNotMatch(lines[0] ?? "", /do-not-print|secret-token/);
  assert.match(lines[0] ?? "", /\[REDACTED\]/);
  assert.deepEqual(redactSensitive({ apiKey: "x", value: "y" }), { apiKey: "[REDACTED]", value: "y" });
});