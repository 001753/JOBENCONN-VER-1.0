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
  readonly authProvider: "dev" | "clerk";
  readonly clerkSecretKey: string | undefined;
  readonly sessionTtlSeconds: number;
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

function parsePositiveInteger(value: string | undefined, fallback: number, name: string): number {
  const parsed = Number(value ?? fallback);
  if (!Number.isInteger(parsed) || parsed < 1 || parsed > 31_536_000) {
    throw new AppError("CONFIGURATION_ERROR", `${name} must be a positive integer within a safe range.`, { expose: false });
  }
  return parsed;
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
  const authProviderValue = env.AUTH_PROVIDER ?? "dev";
  if (authProviderValue !== "dev" && authProviderValue !== "clerk") {
    throw new AppError("CONFIGURATION_ERROR", "AUTH_PROVIDER must be dev or clerk.", { expose: false });
  }
  const databaseUrl = requiredProductionValue("DATABASE_URL", env.DATABASE_URL, environment);
  const sessionSecret = requiredProductionValue("SESSION_SECRET", env.SESSION_SECRET, environment);
  const clerkSecretKey = authProviderValue === "clerk"
    ? requiredProductionValue("CLERK_SECRET_KEY", env.CLERK_SECRET_KEY, environment)
    : env.CLERK_SECRET_KEY;

  return {
    environment,
    port: parsePort(env.PORT),
    host: env.HOST ?? "0.0.0.0",
    logLevel: logLevelValue as LogLevel,
    databaseUrl,
    sessionSecret,
    authProvider: authProviderValue,
    clerkSecretKey,
    sessionTtlSeconds: parsePositiveInteger(env.SESSION_TTL_SECONDS, 60 * 60 * 8, "SESSION_TTL_SECONDS"),
  };
}