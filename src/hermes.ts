import type { Config, SignatureScheme } from "./config.ts";
import type { FetchLike } from "./fetch-like.ts";
import { base64ToBytes, bytesToUtf8, toBase64, toHex, utf8 } from "./encoding.ts";

export interface PubSubMessage {
  attributes?: Record<string, string>;
  data?: string;
  messageId?: string;
  message_id?: string;
  publishTime?: string;
  publish_time?: string;
  orderingKey?: string;
}

export interface PubSubEnvelope {
  message?: PubSubMessage;
  subscription?: string;
  deliveryAttempt?: number;
}

export class EnvelopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EnvelopeError";
  }
}

const pick = (primary: string | undefined, secondary: string | undefined): string | undefined =>
  primary ?? secondary;

export const parseEnvelope = (raw: unknown): PubSubEnvelope => {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new EnvelopeError("body must be a JSON object");
  }
  const envelope = raw as PubSubEnvelope;
  if (typeof envelope.message !== "object" || envelope.message === null) {
    throw new EnvelopeError("body is missing the message object");
  }
  return envelope;
};

export const decodeData = (data: string | undefined): unknown => {
  if (data === undefined || data === "") return null;
  let text: string;
  try {
    text = utf8(base64ToBytes(data));
  } catch {
    throw new EnvelopeError("message.data is not valid base64");
  }
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
};

export const buildForwardBody = (config: Config, envelope: PubSubEnvelope): string => {
  if (config.hermes.mode === "raw") return JSON.stringify(envelope);

  const message = envelope.message ?? {};
  const metadata = {
    messageId: pick(message.messageId, message.message_id) ?? null,
    publishTime: pick(message.publishTime, message.publish_time) ?? null,
    subscription: envelope.subscription ?? null,
    deliveryAttempt: envelope.deliveryAttempt ?? null,
    attributes: message.attributes ?? {},
  };

  const decoded = decodeData(message.data);
  if (decoded !== null && typeof decoded === "object" && !Array.isArray(decoded)) {
    return JSON.stringify({ ...(decoded as Record<string, unknown>), _pubsub: metadata });
  }
  return JSON.stringify({ payload: decoded, _pubsub: metadata });
};

const importSecret = (secret: string): Promise<CryptoKey> =>
  crypto.subtle.importKey(
    "raw",
    bytesToUtf8(secret) as unknown as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

const hmac = async (secret: string, message: string): Promise<Uint8Array> => {
  const key = await importSecret(secret);
  const signature = await crypto.subtle.sign("HMAC", key, bytesToUtf8(message) as unknown as BufferSource);
  return new Uint8Array(signature);
};

export interface SignatureHeaders {
  [name: string]: string;
}

export const signPayload = async (
  scheme: SignatureScheme,
  secret: string,
  body: string,
  eventId: string,
  timestampSeconds: number,
): Promise<SignatureHeaders> => {
  if (scheme === "none" || secret === "") return {};

  if (scheme === "v2") {
    const digest = await hmac(secret, `${timestampSeconds}.${body}`);
    return {
      "X-Webhook-Signature-V2": toHex(digest),
      "X-Webhook-Timestamp": String(timestampSeconds),
    };
  }

  if (scheme === "standard") {
    const digest = await hmac(secret, `${eventId}.${timestampSeconds}.${body}`);
    return {
      "webhook-id": eventId,
      "webhook-timestamp": String(timestampSeconds),
      "webhook-signature": `v1,${toBase64(digest)}`,
    };
  }

  const digest = await hmac(secret, body);
  return { "X-Hub-Signature-256": `sha256=${toHex(digest)}` };
};

export interface ForwardResult {
  ok: boolean;
  status: number;
  retryable: boolean;
  detail: string;
}

const classifyStatus = (status: number, retryOn4xx: boolean): { ok: boolean; retryable: boolean } => {
  if (status >= 200 && status < 300) return { ok: true, retryable: false };
  if (status === 408 || status === 425 || status === 429 || status >= 500) {
    return { ok: false, retryable: true };
  }
  return { ok: false, retryable: retryOn4xx };
};

export const forwardToHermes = async (
  config: Config,
  body: string,
  eventId: string,
  fetchImpl: FetchLike,
): Promise<ForwardResult> => {
  const timestampSeconds = Math.floor(Date.now() / 1000);
  const headers: SignatureHeaders = {
    "content-type": "application/json",
    "user-agent": "pubsub-hermes-webhook-proxy/1.0",
    "X-Request-ID": eventId,
    ...(await signPayload(config.hermes.scheme, config.hermes.secret, body, eventId, timestampSeconds)),
  };

  let response: Response;
  try {
    response = await fetchImpl(config.hermes.url, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(config.hermes.timeoutMs),
    });
  } catch (error) {
    const name = error instanceof Error ? error.name : "Error";
    return { ok: false, status: 0, retryable: true, detail: `${name}: ${(error as Error).message}` };
  }

  const snippet = (await response.text()).slice(0, 512);
  const { ok, retryable } = classifyStatus(response.status, config.hermes.retryOn4xx);
  return {
    ok,
    status: response.status,
    retryable,
    detail: snippet || response.statusText || "no response body",
  };
};
