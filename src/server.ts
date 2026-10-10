import type { Config } from "./config.ts";
import type { FetchLike } from "./fetch-like.ts";
import type { Logger } from "./logger.ts";
import type { GoogleIdTokenVerifier } from "./jwt.ts";
import { JwtError, extractBearerToken } from "./jwt.ts";
import { EnvelopeError, buildForwardBody, forwardToHermes, parseEnvelope } from "./hermes.ts";

export interface Context {
  config: Config;
  log: Logger;
  verifier: GoogleIdTokenVerifier;
  fetchImpl: FetchLike;
}

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

const ack = (): Response => new Response(null, { status: 204 });

export const expectedSubscriptionPath = (config: Config): string =>
  `projects/${config.pubsub.project}/subscriptions/${config.pubsub.subscription}`;

export const audienceCandidates = (config: Config, req: Request): string[] => {
  if (config.pubsub.audiences.length > 0) return config.pubsub.audiences;
  const url = new URL(req.url);
  const host = req.headers.get("host") ?? url.host;
  const scheme = url.protocol.replace(":", "");
  return [`${scheme}://${host}`, host, `${scheme}://${host}${url.pathname}`];
};

const readBoundedBody = async (req: Request, maxBytes: number): Promise<string | null> => {
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > maxBytes) return null;
  const raw = await req.text();
  if (raw.length > maxBytes) return null;
  return raw;
};

const handlePush = async (ctx: Context, req: Request): Promise<Response> => {
  const { config, log } = ctx;
  const requestLog = log.child({ path: new URL(req.url).pathname });

  let raw: string | null;
  try {
    raw = await readBoundedBody(req, config.maxBodyBytes);
  } catch (error) {
    requestLog.warn("body_read_failed", { error: (error as Error).message });
    return json(400, { error: "unreadable_body" });
  }
  if (raw === null) {
    requestLog.warn("payload_too_large", { maxBodyBytes: config.maxBodyBytes });
    return json(413, { error: "payload_too_large" });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return json(400, { error: "invalid_json" });
  }

  let envelope;
  try {
    envelope = parseEnvelope(parsed);
  } catch (error) {
    if (!(error instanceof EnvelopeError)) throw error;
    requestLog.warn("bad_envelope", { error: error.message });
    return json(400, { error: "bad_envelope", reason: error.message });
  }

  const message = envelope.message ?? {};
  const messageId = message.messageId ?? message.message_id ?? crypto.randomUUID();
  const logFields = {
    messageId,
    subscription: envelope.subscription ?? null,
    deliveryAttempt: envelope.deliveryAttempt ?? null,
  };

  const expectedSubscription = expectedSubscriptionPath(config);
  if (envelope.subscription !== expectedSubscription) {
    requestLog.warn("subscription_mismatch", { ...logFields, expected: expectedSubscription });
    return json(403, { error: "subscription_mismatch" });
  }

  if (!config.insecureSkipJwt) {
    const token = extractBearerToken(req.headers.get("authorization"));
    if (token === null) {
      requestLog.warn("missing_token", logFields);
      return json(401, { error: "missing_bearer_token" });
    }
    try {
      await ctx.verifier.verify(token, {
        expectedEmail: config.pubsub.serviceAccountEmail,
        allowedAudiences: audienceCandidates(config, req),
        maxAgeSeconds: config.pubsub.maxAgeSeconds,
        skewSeconds: config.pubsub.skewSeconds,
      });
    } catch (error) {
      if (error instanceof JwtError) {
        requestLog.warn("invalid_token", { ...logFields, reason: error.message });
        return json(error.status, { error: "invalid_token", reason: error.message });
      }
      requestLog.error("token_verification_crashed", { ...logFields, error: (error as Error).message });
      return json(401, { error: "invalid_token" });
    }
  }

  let body: string;
  try {
    body = buildForwardBody(config, envelope);
  } catch (error) {
    if (!(error instanceof EnvelopeError)) throw error;
    requestLog.warn("undecodable_data", { ...logFields, error: error.message });
    return json(400, { error: "undecodable_data", reason: error.message });
  }

  const result = await forwardToHermes(config, body, messageId, ctx.fetchImpl);
  if (result.ok) {
    requestLog.info("delivered", { ...logFields, hermesStatus: result.status, bytes: body.length });
    return ack();
  }

  if (result.retryable) {
    requestLog.warn("delivery_retry", { ...logFields, hermesStatus: result.status, detail: result.detail });
    return json(503, { error: "upstream_unavailable", detail: result.detail });
  }

  requestLog.error("delivery_dropped", { ...logFields, hermesStatus: result.status, detail: result.detail });
  return ack();
};

const STATIC_PUSH_PATHS = ["/", "/webhook", "/pubsub", "/push"];

export const pushPathsFor = (config: Config): string[] => {
  const route = config.hermes.route.replace(/^\/+|\/+$/g, "");
  const paths = new Set(STATIC_PUSH_PATHS);
  if (route !== "") {
    paths.add(`/${route}`);
    paths.add(`/webhook/${route}`);
    paths.add(`/webhooks/${route}`);
  }
  return [...paths];
};

const rejectMethod = (log: Logger): Response => {
  log.warn("method_not_allowed", { expected: "POST" });
  return json(405, { error: "method_not_allowed", expected: "POST" });
};

const unknownPath = (log: Logger, pushPaths: string[]): Response => {
  log.info("unmatched_path", { pushPaths });
  return json(404, { error: "not_found", pushPaths });
};

export const createHandler = (ctx: Context) => {
  const pushPaths = pushPathsFor(ctx.config);
  const pushSet = new Set(pushPaths);

  return async (req: Request): Promise<Response> => {
    const url = new URL(req.url);
    const path = url.pathname.length > 1 ? url.pathname.replace(/\/+$/, "") : "/";
    const isPushPath = pushSet.has(path);
    const log = ctx.log.child({ method: req.method, path });

    if (req.method === "GET" || req.method === "HEAD") {
      if (path === "/health" || path === "/healthz") {
        return json(200, { status: "ok", platform: "pubsub-push-proxy", route: ctx.config.hermes.route });
      }
      if (path === "/") {
        return json(200, {
          name: "pubsub-hermes-webhook-proxy",
          accept: pushPaths.map((entry) => `POST ${entry}`),
          route: ctx.config.hermes.route,
          jwtValidation: ctx.config.insecureSkipJwt ? "disabled" : "enabled",
          forwardMode: ctx.config.hermes.mode,
        });
      }
      return isPushPath ? rejectMethod(log) : unknownPath(log, pushPaths);
    }

    if (req.method !== "POST") {
      return isPushPath ? rejectMethod(log) : unknownPath(log, pushPaths);
    }

    if (isPushPath) return handlePush(ctx, req);
    return unknownPath(log, pushPaths);
  };
};
