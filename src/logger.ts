export type LogLevel = "debug" | "info" | "warn" | "error" | "off";

const LEVEL_WEIGHT: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
  off: 100,
};

type Fields = Record<string, unknown>;

export class Logger {
  #level: LogLevel;
  #bindings: Fields;

  constructor(level: LogLevel, bindings: Fields = {}) {
    this.#level = level;
    this.#bindings = bindings;
  }

  child(bindings: Fields): Logger {
    return new Logger(this.#level, { ...this.#bindings, ...bindings });
  }

  #emit(level: LogLevel, event: string, fields?: Fields): void {
    if (LEVEL_WEIGHT[level] < LEVEL_WEIGHT[this.#level]) return;
    const line = JSON.stringify({
      ts: new Date().toISOString(),
      level,
      event,
      ...this.#bindings,
      ...fields,
    });
    if (level === "error" || level === "warn") console[level](line);
    else console.log(line);
  }

  debug(event: string, fields?: Fields): void {
    this.#emit("debug", event, fields);
  }

  info(event: string, fields?: Fields): void {
    this.#emit("info", event, fields);
  }

  warn(event: string, fields?: Fields): void {
    this.#emit("warn", event, fields);
  }

  error(event: string, fields?: Fields): void {
    this.#emit("error", event, fields);
  }
}

const LOG_LEVELS: readonly LogLevel[] = ["debug", "info", "warn", "error", "off"];

export const parseLogLevel = (value: string | undefined): LogLevel => {
  const normalized = (value ?? "info").toLowerCase().trim();
  if (normalized === "trace") return "debug";
  if (normalized === "silent" || normalized === "none") return "off";
  return LOG_LEVELS.find((level) => level === normalized) ?? "info";
};
