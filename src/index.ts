import { ConfigError, loadConfig, redactedConfig } from "./config.ts";
import { GoogleIdTokenVerifier } from "./jwt.ts";
import { Logger } from "./logger.ts";
import { createHandler } from "./server.ts";

let config;
try {
  config = loadConfig();
} catch (error) {
  if (error instanceof ConfigError) {
    console.error(JSON.stringify({ ts: new Date().toISOString(), level: "error", event: "config_error", error: error.message }));
    process.exit(1);
  }
  throw error;
}

const log = new Logger(config.logLevel);
const verifier = new GoogleIdTokenVerifier(log);
const handler = createHandler({ config, log, verifier, fetchImpl: fetch });

const server = Bun.serve({
  port: config.port,
  hostname: config.hostname,
  idleTimeout: 60,
  development: false,
  fetch: handler,
  error(error: Error) {
    log.error("server_error", { error: error.message, name: error.name });
    return new Response("Internal Server Error", { status: 500 });
  },
});

log.info("listening", { ...redactedConfig(config), url: server.url.href });

let closing = false;
const shutdown = (signal: string): void => {
  if (closing) return;
  closing = true;
  log.info("shutdown", { signal });
  setTimeout(() => process.exit(1), 10_000).unref();
  void server.stop(true).then(() => process.exit(0));
};

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
