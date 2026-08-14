import { loadConfig } from "./config.js";
import { StructuredLogger } from "./logger.js";
import { createAppServer } from "./server.js";

try {
  const config = loadConfig();
  const logger = new StructuredLogger(config.logLevel);
  const server = createAppServer(config, logger);
  server.listen(config.port, config.host, () => {
    logger.info("application.started", {
      host: config.host,
      port: config.port,
      environment: config.environment,
    });
  });
  const shutdown = (signal: string) => {
    logger.info("application.shutdown.requested", { signal });
    server.close(() => process.exit(0));
  };
  process.once("SIGTERM", () => shutdown("SIGTERM"));
  process.once("SIGINT", () => shutdown("SIGINT"));
} catch (error) {
  const message = error instanceof Error ? error.message : "Unknown configuration failure.";
  process.stderr.write(`CONFIGURATION_ERROR: ${message}\n`);
  process.exitCode = 1;
}