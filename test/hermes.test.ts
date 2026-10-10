import { describe, expect, test } from "bun:test";
import { loadConfig } from "../src/config.ts";
import { EnvelopeError, buildForwardBody, forwardToHermes, parseEnvelope, signPayload } from "../src/hermes.ts";
import { base64ToBytes, toBase64, toHex, utf8 } from "../src/encoding.ts";
import type { FetchLike } from "../src/fetch-like.ts";

const baseEnv = {
  HERMES_WEBHOOK_URL: "https://hermes.example.railway.app/webhooks/gmail",
  HERMES_WEBHOOK_SECRET: "route-secret",
  BIND_HOST: "127.0.0.1",
};

const gmailData = (inner: unknown): string =>
  btoa(JSON.stringify(inner)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

describe("parseEnvelope", () => {
  test("accepts a wrapped push body", () => {
    const envelope = parseEnvelope({
      message: { data: "aGk=", messageId: "1", publishTime: "2026-01-01T00:00:00Z" },
      subscription: "projects/p/subscriptions/s",
      deliveryAttempt: 2,
    });
    expect(envelope.message?.messageId).toBe("1");
    expect(envelope.deliveryAttempt).toBe(2);
  });

  test("rejects non-object bodies", () => {
    expect(() => parseEnvelope(null)).toThrow(EnvelopeError);
    expect(() => parseEnvelope([])).toThrow(EnvelopeError);
    expect(() => parseEnvelope("hello")).toThrow(EnvelopeError);
    expect(() => parseEnvelope({ subscription: "projects/p/subscriptions/s" })).toThrow(EnvelopeError);
  });
});

describe("buildForwardBody", () => {
  test("unwraps base64 JSON data and attaches metadata", () => {
    const config = loadConfig(baseEnv);
    const body = buildForwardBody(config, {
      message: {
        attributes: { "X-Gmail-Topic": "inbox" },
        data: gmailData({ message: { threadId: "18f2", labelIds: ["INBOX"] } }),
        messageId: "2070443601311540",
        publishTime: "2026-02-26T19:13:55.749Z",
      },
      subscription: "projects/hermes-agent-511204/subscriptions/hermes",
      deliveryAttempt: 1,
    });
    const parsed = JSON.parse(body) as Record<string, unknown>;
    expect(parsed.message).toEqual({ threadId: "18f2", labelIds: ["INBOX"] });
    expect(parsed._pubsub).toEqual({
      messageId: "2070443601311540",
      publishTime: "2026-02-26T19:13:55.749Z",
      subscription: "projects/hermes-agent-511204/subscriptions/hermes",
      deliveryAttempt: 1,
      attributes: { "X-Gmail-Topic": "inbox" },
    });
  });

  test("keeps non-JSON data as a string payload", () => {
    const config = loadConfig(baseEnv);
    const body = buildForwardBody(config, {
      message: { data: btoa("plain text body"), messageId: "7" },
      subscription: "projects/hermes-agent-511204/subscriptions/hermes",
    });
    const parsed = JSON.parse(body) as Record<string, unknown>;
    expect(parsed.payload).toBe("plain text body");
    expect((parsed._pubsub as Record<string, unknown>).messageId).toBe("7");
  });

  test("handles a missing data field", () => {
    const config = loadConfig(baseEnv);
    const body = buildForwardBody(config, {
      message: { messageId: "8" },
      subscription: "projects/hermes-agent-511204/subscriptions/hermes",
    });
    expect(JSON.parse(body)).toMatchObject({ payload: null });
  });

  test("supports snake_case ids and raw passthrough", () => {
    const envelope = {
      message: { data: btoa("{}"), message_id: "9", publish_time: "2026-01-01T00:00:00Z" },
      subscription: "projects/hermes-agent-511204/subscriptions/hermes",
    };
    const decoded = JSON.parse(buildForwardBody(loadConfig(baseEnv), envelope)) as Record<string, unknown>;
    expect((decoded._pubsub as Record<string, unknown>).messageId).toBe("9");

    const rawConfig = loadConfig({ ...baseEnv, FORWARD_MODE: "raw" });
    expect(JSON.parse(buildForwardBody(rawConfig, envelope))).toEqual(envelope);
  });

  test("rejects undecodable data", () => {
    const config = loadConfig(baseEnv);
    expect(() =>
      buildForwardBody(config, {
        message: { data: "not base64 !!", messageId: "1" },
        subscription: "projects/hermes-agent-511204/subscriptions/hermes",
      }),
    ).toThrow(EnvelopeError);
  });
});

describe("signPayload", () => {
  const body = '{"a":1}';
  const eventId = "msg_123";
  const timestamp = 1767225600;

  test("v2 signs <timestamp>.<body> as hex", async () => {
    const headers = await signPayload("v2", "secret", body, eventId, timestamp);
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode("secret"),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const expected = toHex(
      new Uint8Array(
        await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${timestamp}.${body}`)),
      ),
    );
    expect(headers["X-Webhook-Signature-V2"]).toBe(expected);
    expect(headers["X-Webhook-Timestamp"]).toBe(String(timestamp));
  });

  test("standard signs <id>.<timestamp>.<body> as base64 with a v1 prefix", async () => {
    const headers = await signPayload("standard", "secret", body, eventId, timestamp);
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode("secret"),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const expected = toBase64(
      new Uint8Array(
        await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${eventId}.${timestamp}.${body}`)),
      ),
    );
    expect(headers["webhook-id"]).toBe(eventId);
    expect(headers["webhook-timestamp"]).toBe(String(timestamp));
    expect(headers["webhook-signature"]).toBe(`v1,${expected}`);
  });

  test("github signs the bare body", async () => {
    const headers = await signPayload("github", "secret", body, eventId, timestamp);
    expect(headers["X-Hub-Signature-256"]).toMatch(/^sha256=[0-9a-f]{64}$/);
  });

  test("none emits no headers", async () => {
    expect(await signPayload("none", "secret", body, eventId, timestamp)).toEqual({});
    expect(await signPayload("v2", "", body, eventId, timestamp)).toEqual({});
  });
});

describe("forwardToHermes", () => {
  test("posts a signed body with an idempotency id", async () => {
    const config = loadConfig(baseEnv);
    let seen: { url: string; headers: Headers; body: string } | null = null;
    const fetchImpl: FetchLike = async (input, init) => {
      seen = {
        url: String(input),
        headers: new Headers(init?.headers),
        body: String(init?.body),
      };
      return Response.json({ status: "accepted" });
    };
    const result = await forwardToHermes(config, '{"a":1}', "msg-1", fetchImpl);
    expect(result).toMatchObject({ ok: true, status: 200, retryable: false });
    expect(seen).not.toBeNull();
    const captured = seen as unknown as { url: string; headers: Headers; body: string };
    expect(captured.url).toBe("https://hermes.example.railway.app/webhooks/gmail");
    expect(captured.headers.get("X-Request-ID")).toBe("msg-1");
    expect(captured.headers.get("X-Webhook-Signature-V2")).toBeTruthy();
    expect(captured.headers.get("content-type")).toBe("application/json");
    expect(captured.body).toBe('{"a":1}');
  });

  test("treats 202 and 204 as success", async () => {
    const config = loadConfig(baseEnv);
    for (const status of [200, 202, 204]) {
      const result = await forwardToHermes(config, "{}", "id", async () => new Response(null, { status }));
      expect(result.ok).toBe(true);
    }
  });

  test("classifies transient and permanent failures", async () => {
    const config = loadConfig(baseEnv);
    for (const status of [408, 429, 500, 502, 503]) {
      const result = await forwardToHermes(config, "{}", "id", async () => new Response("busy", { status }));
      expect([status, result.retryable]).toEqual([status, true]);
      expect(result.ok).toBe(false);
    }
    for (const status of [400, 401, 404, 413]) {
      const result = await forwardToHermes(config, "{}", "id", async () => new Response("nope", { status }));
      expect([status, result.retryable, result.detail]).toEqual([status, false, "nope"]);
    }
  });

  test("honours RETRY_ON_4XX", async () => {
    const config = loadConfig({ ...baseEnv, RETRY_ON_4XX: "true" });
    const result = await forwardToHermes(config, "{}", "id", async () => new Response("nope", { status: 404 }));
    expect(result.retryable).toBe(true);
  });

  test("treats timeouts and network errors as retryable", async () => {
    const config = loadConfig(baseEnv);
    const result = await forwardToHermes(config, "{}", "id", async () => {
      throw new DOMException("aborted", "TimeoutError");
    });
    expect(result).toMatchObject({ ok: false, status: 0, retryable: true });
    expect(result.detail).toContain("TimeoutError");
  });
});

describe("encoding helpers", () => {
  const standardBase64 = (input: string): string => {
    const bytes = new TextEncoder().encode(input);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  };

  test("decodes standard and url-safe base64 payloads", () => {
    for (const source of ["héllo", "a", "{}", 'eyJlbWFpbEFkZHJlc3MiOiJ4In0=']) {
      const standard = standardBase64(source);
      const urlSafe = standard.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
      expect(utf8(base64ToBytes(standard))).toBe(source);
      expect(utf8(base64ToBytes(urlSafe))).toBe(source);
    }
  });

  test("rejects values that are not base64", () => {
    expect(() => base64ToBytes("not base64 !!")).toThrow();
  });
});
