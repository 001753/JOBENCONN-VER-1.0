import { loadConfig } from "./config.js";
import { disconnectPrisma } from "./database.js";
import { getPrismaClient } from "./database.js";
import { StructuredLogger } from "./logger.js";
import { createAppServer } from "./server.js";
import { SecurityAnalysisService } from "./security-service.js";
import { DefaultAwsReadOnlyDiscoveryClientFactory } from "./aws-service.js";
import { ScanWorker } from "./scan-worker.js";
import { randomUUID } from "node:crypto";

try {
  const config = loadConfig();
  const logger = new StructuredLogger(config.logLevel);
  const server = createAppServer(config, logger);
  const db = getPrismaClient();
  const security = new SecurityAnalysisService(db, undefined, new DefaultAwsReadOnlyDiscoveryClientFactory());
  const worker = new ScanWorker(db, {
    execute: async (job, scan) => security.executeQueuedRun(scan.id, job.attempt),
  }, `scan-worker-${randomUUID()}`);
  const workerTimer = setInterval(() => {
    void worker.runOnce().catch((error: unknown) => logger.error("scan.worker.loop.failed", {
      errorType: error instanceof Error ? error.name : typeof error,
    }));
  }, 500);
  workerTimer.unref();
  const scheduleTimer = setInterval(() => {
    void security.processDueSchedules().catch((error: unknown) => logger.error("scan.schedule.loop.failed", {
      errorType: error instanceof Error ? error.name : typeof error,
    }));
  }, 60_000);
  scheduleTimer.unref();
  server.listen(config.port, config.host, () => {
    logger.info("application.started", {
      host: config.host,
      port: config.port,
      environment: config.environment,
    });
  });
  const shutdown = (signal: string) => {
    logger.info("application.shutdown.requested", { signal });
    server.close(() => {
      clearInterval(workerTimer);
      clearInterval(scheduleTimer);
      void disconnectPrisma().finally(() => process.exit(0));
    });
  };
  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown configuration failure.";
  process.stderr.write(`CONFIGURATION_ERROR: ${message}\n`);
  process.exitCode = 1;
}