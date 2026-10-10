import type { LogLevel } from "./logger.ts";
import { parseLogLevel } from "./logger.ts";
import { normalizeAudience } from "./jwt.ts";

export type SignatureScheme = "v2" | "standard" | "github" | "none";
export type ForwardMode = "decoded" | "raw";

export interface PubSubConfig {
  project: string;
  subscription: string;
  serviceAccountEmail: string;
  audiences: string[];
  maxAgeSeconds: number;
  skewSeconds: number;
}

export interface HermesConfig {
  url: string;
  secret: string;
  scheme: SignatureScheme;
  route: string;
  timeoutMs: number;
  mode: ForwardMode;
  retryOn4xx: boolean;
}

export interface Config {
  port: number;
  hostname: string;
  publicUrl: string | null;
  logLevel: LogLevel;
  maxBodyBytes: number;
  insecureSkipJwt: boolean;
  pubsub: PubSubConfig;
  hermes: HermesConfig;
}

export class ConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ConfigError";
  }
}

const LOOPBACK = new Set(["127.0.0.1", "localhost", "::1", "[::1]"]);

const str = (env: Record<string, string | undefined>, key: string, fallback = ""): string => {
  const value = env[key];
  return value === undefined || value === "" ? fallback : value.trim();
};

const num = (
  env: Record<string, string | undefined>,
  key: string,
  fallback: number,
  bounds: { min: number; max: number },
): number => {
  const raw = str(env, key);
  if (raw === "") return fallback;
  const parsed = Number(raw);
  if (!Number.isFinite(parsed)) throw new ConfigError(`${key} must be a number, got "${raw}"`);
  if (parsed < bounds.min || parsed > bounds.max) {
    throw new ConfigError(`${key} must be between ${bounds.min} and ${bounds.max}, got ${parsed}`);
  }
  return Math.trunc(parsed);
};

const bool = (env: Record<string, string | undefined>, key: string, fallback: boolean): boolean => {
  const raw = str(env, key).toLowerCase();
  if (raw === "") return fallback;
  if (["1", "true", "yes", "on"].includes(raw)) return true;
  if (["0", "false", "no", "off"].includes(raw)) return false;
  throw new ConfigError(`${key} must be a boolean, got "${raw}"`);
};

const oneOf = <T extends string>(
  env: Record<string, string | undefined>,
  key: string,
  fallback: T,
  allowed: readonly T[],
): T => {
  const raw = str(env, key).toLowerCase();
  if (raw === "") return fallback;
  if (!allowed.includes(raw as T)) {
    throw new ConfigError(`${key} must be one of ${allowed.join(", ")}, got "${raw}"`);
  }
  return raw as T;
};

const parseAudiences = (env: Record<string, string | undefined>): string[] =>
  str(env, "PUBSUB_AUDIENCE")
    .split(",")
    .map(normalizeAudience)
    .filter((value) => value.length > 0);

const routeFromUrl = (url: string): string => {
  const segments = new URL(url).pathname.split("/").filter(Boolean);
  return segments.length > 0 ? (segments.at(-1) as string) : "pubsub";
};

export const loadConfig = (env: Record<string, string | undefined> = process.env): Config => {
  const hostname = str(env, "HOSTNAME", "0.0.0.0");
  const insecureSkipJwt = bool(env, "INSECURE_SKIP_JWT", false);
  if (insecureSkipJwt && !LOOPBACK.has(hostname.toLowerCase())) {
    throw new ConfigError(
      `INSECURE_SKIP_JWT is only allowed when HOSTNAME is a loopback address (got "${hostname}")`,
    );
  }

  const hermesUrl = str(env, "HERMES_WEBHOOK_URL");
  if (hermesUrl === "") throw new ConfigError("HERMES_WEBHOOK_URL is required");
  let parsedHermes: URL;
  try {
    parsedHermes = new URL(hermesUrl);
  } catch {
    throw new ConfigError(`HERMES_WEBHOOK_URL is not a valid URL: "${hermesUrl}"`);
  }
  if (parsedHermes.protocol !== "https:" && parsedHermes.protocol !== "http:") {
    throw new ConfigError(`HERMES_WEBHOOK_URL must be http(s), got "${parsedHermes.protocol}"`);
  }
  if (parsedHermes.protocol === "http:" && !insecureSkipJwt) {
    throw new ConfigError("HERMES_WEBHOOK_URL must use https outside of local testing");
  }

  const scheme = oneOf(env, "HERMES_SIGNATURE_SCHEME", "v2", [
    "v2",
    "standard",
    "github",
    "none",
  ] as const);
  const secret = str(env, "HERMES_WEBHOOK_SECRET");
  if (secret === "" && scheme !== "none") {
    throw new ConfigError(
      `HERMES_WEBHOOK_SECRET is required when HERMES_SIGNATURE_SCHEME=${scheme}; set the scheme to "none" only for local testing`,
    );
  }

  const project = str(env, "PUBSUB_PROJECT", "hermes-agent-1234");
  const subscription = str(env, "PUBSUB_SUBSCRIPTION", "hermes");
  const serviceAccountEmail = str(
    env,
    "PUBSUB_SERVICE_ACCOUNT_EMAIL",
    "hermes-agent@hermes-agent-1234.iam.gserviceaccount.com",
  ).toLowerCase();
  if (!/@|^projects\//.test(serviceAccountEmail)) {
    throw new ConfigError(`PUBSUB_SERVICE_ACCOUNT_EMAIL looks invalid: "${serviceAccountEmail}"`);
  }

  const publicUrlRaw = str(env, "PUBLIC_URL");
  let publicUrl: string | null = null;
  if (publicUrlRaw !== "") {
    try {
      publicUrl = new URL(publicUrlRaw).href;
    } catch {
      throw new ConfigError(`PUBLIC_URL is not a valid URL: "${publicUrlRaw}"`);
    }
  }

  return {
    port: num(env, "PORT", 8080, { min: 1, max: 65535 }),
    hostname,
    publicUrl,
    logLevel: parseLogLevel(str(env, "LOG_LEVEL") || undefined),
    maxBodyBytes: num(env, "MAX_BODY_BYTES", 5 * 1024 * 1024, {
      min: 1024,
      max: 20 * 1024 * 1024,
    }),
    insecureSkipJwt,
    pubsub: {
      project,
      subscription,
      serviceAccountEmail,
      audiences: parseAudiences(env),
      maxAgeSeconds: num(env, "JWT_MAX_AGE_SECONDS", 3600, { min: 60, max: 86_400 }),
      skewSeconds: num(env, "JWT_SKEW_SECONDS", 60, { min: 0, max: 600 }),
    },
    hermes: {
      url: parsedHermes.href,
      secret,
      scheme,
      route: str(env, "HERMES_ROUTE") || routeFromUrl(parsedHermes.href),
      timeoutMs: num(env, "HERMES_TIMEOUT_MS", 8000, { min: 250, max: 120_000 }),
      mode: oneOf(env, "FORWARD_MODE", "decoded", ["decoded", "raw"] as const),
      retryOn4xx: bool(env, "RETRY_ON_4XX", false),
    },
  };
};

export const redactedConfig = (config: Config): Record<string, unknown> => ({
  port: config.port,
  hostname: config.hostname,
  publicUrl: config.publicUrl,
  logLevel: config.logLevel,
  maxBodyBytes: config.maxBodyBytes,
  insecureSkipJwt: config.insecureSkipJwt,
  pubsub: {
    project: config.pubsub.project,
    subscription: config.pubsub.subscription,
    serviceAccountEmail: config.pubsub.serviceAccountEmail,
    audiences: config.pubsub.audiences,
    maxAgeSeconds: config.pubsub.maxAgeSeconds,
  },
  hermes: {
    url: config.hermes.url,
    scheme: config.hermes.scheme,
    route: config.hermes.route,
    mode: config.hermes.mode,
    timeoutMs: config.hermes.timeoutMs,
    retryOn4xx: config.hermes.retryOn4xx,
    secretConfigured: config.hermes.secret.length > 0,
  },
});
