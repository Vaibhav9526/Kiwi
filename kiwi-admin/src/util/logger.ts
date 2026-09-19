/**
 * Minimal structured logger. SECURITY.md rule 6: never log secrets. Callers
 * must pass metadata objects with only non-sensitive fields.
 */
export type LogLevel = "debug" | "info" | "warn" | "error";

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

export interface Logger {
  debug(message: string, meta?: Record<string, unknown>): void;
  info(message: string, meta?: Record<string, unknown>): void;
  warn(message: string, meta?: Record<string, unknown>): void;
  error(message: string, meta?: Record<string, unknown>): void;
}

export function createConsoleLogger(minLevel: LogLevel = "info"): Logger {
  const threshold = LEVEL_ORDER[minLevel];
  const write = (stream: "stdout" | "stderr", level: LogLevel, message: string, meta?: Record<string, unknown>) => {
    if (LEVEL_ORDER[level] < threshold) return;
    const line = JSON.stringify({ ts: new Date().toISOString(), level, message, ...(meta ? { meta } : {}) });
    if (stream === "stderr") process.stderr.write(line + "\n");
    else process.stdout.write(line + "\n");
  };
  return {
    debug: (m, meta) => write("stdout", "debug", m, meta),
    info: (m, meta) => write("stdout", "info", m, meta),
    warn: (m, meta) => write("stderr", "warn", m, meta),
    error: (m, meta) => write("stderr", "error", m, meta),
  };
}
