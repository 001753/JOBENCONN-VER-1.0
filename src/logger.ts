export type LogLevel = "debug" | "info" | "warn" | "error";
type LogWriter = (line: string) => void;
type LogContext = Record<string, unknown>;

const sensitiveKeyPattern = /password|secret|token|api[-_]?key|authorization|cookie|credential|databaseurl/i;

export function redactSensitive(value: unknown, key?: string): unknown {
  if (key && sensitiveKeyPattern.test(key)) return "[REDACTED]";
  if (Array.isArray(value)) return value.map((item) => redactSensitive(item));
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([entryKey, entryValue]) => [entryKey, redactSensitive(entryValue, entryKey)]),
    );
  }
  return value;
}

export class StructuredLogger {
  constructor(
    private readonly minimumLevel: LogLevel = "info",
    private readonly writer: LogWriter = (line) => process.stdout.write(`${line}\n`),
  ) {}

  log(level: LogLevel, event: string, context: LogContext = {}): void {
    if (this.levelRank(level) < this.levelRank(this.minimumLevel)) return;
    const redactedContext = redactSensitive(context) as LogContext;
    const record = {
      timestamp: new Date().toISOString(),
      level,
      event,
      ...redactedContext,
    };
    this.writer(JSON.stringify(record));
  }

  debug(event: string, context?: LogContext): void {
    this.log("debug", event, context);
  }
  info(event: string, context?: LogContext): void {
    this.log("info", event, context);
  }
  warn(event: string, context?: LogContext): void {
    this.log("warn", event, context);
  }
  error(event: string, context?: LogContext): void {
    this.log("error", event, context);
  }

  private levelRank(level: LogLevel): number {
    return { debug: 10, info: 20, warn: 30, error: 40 }[level];
  }
}