import { AppError } from "./errors.js";

export type RuntimeEnvironment = "development" | "test" | "production";
export type LogLevel = "debug" | "info" | "warn" | "error";

export interface AppConfig {
  readonly environment: RuntimeEnvironment;
  readonly port: number;
  readonly host: string;
  readonly logLevel: LogLevel;
  readonly databaseUrl: string | undefined;
  readonly sessionSecret: string | undefined;
}

const validEnvironments: RuntimeEnvironment[] = ["development", "test", "production"];
const validLogLevels: LogLevel[] = ["debug", "info", "warn", "error"];

function requiredProductionValue(name: string, value: string | undefined, environment: RuntimeEnvironment): string | undefined {
  if (environment === "production" && !value) {
    throw new AppError("CONFIGURATION_ERROR", `Required production configuration is missing: ${name}`, {
      expose: false,
    });
  }
  return value;
}

function parsePort(value: string | undefined): number {
  const port = Number(value ?? "5000");
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new AppError("CONFIGURATION_ERROR", "PORT must be an integer between 1 and 65535.", { expose: false });
  }
  return port;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): AppConfig {
  const environmentValue = env.NODE_ENV ?? "development";
  if (!validEnvironments.includes(environmentValue as RuntimeEnvironment)) {
    throw new AppError("CONFIGURATION_ERROR", "NODE_ENV must be development, test, or production.", { expose: false });
  }
  const environment = environmentValue as RuntimeEnvironment;
  const logLevelValue = env.LOG_LEVEL ?? "info";
  if (!validLogLevels.includes(logLevelValue as LogLevel)) {
    throw new AppError("CONFIGURATION_ERROR", "LOG_LEVEL must be debug, info, warn, or error.", { expose: false });
  }

  return {
    environment,
    port: parsePort(env.PORT),
    host: env.HOST ?? "0.0.0.0",
    logLevel: logLevelValue as LogLevel,
    databaseUrl: requiredProductionValue("DATABASE_URL", env.DATABASE_URL, environment),
    sessionSecret: env.SESSION_SECRET,
  };
}