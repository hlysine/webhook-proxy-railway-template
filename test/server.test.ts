import { describe, expect, test } from "bun:test";
import { loadConfig } from "../src/config.ts";
import { GoogleIdTokenVerifier } from "../src/jwt.ts";
import { createHandler } from "../src/server.ts";
import type { Context } from "../src/server.ts";
import type { FetchLike } from "../src/fetch-like.ts";
import { SUBSCRIPTION, generateKeys, jwksFetch, jwtClaims, pubsubPushBody, signJwt, testLog } from "./helpers.ts";

const PROXY_URL = "https://webhook-proxy.up.railway.app/";

interface Captured {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string;
}

const headerRecord = (init?: RequestInit): Record<string, string> => {
  const headers: Record<string, string> = {};
  new Headers(init?.headers).forEach((value, key) => {
    headers[key] = value;
  });
  return headers;
};

const recorder =
  (respond: () => Response, sink: { calls: Captured[] }): FetchLike =>
  async (input, init) => {
    sink.calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      headers: headerRecord(init),
      body: String(init?.body ?? ""),
    });
    return respond();
  };

const env = {
  HERMES_WEBHOOK_URL: "https://hermes.internal.railway.app/webhooks/gmail",
  HERMES_WEBHOOK_SECRET: "route-secret",
  HOSTNAME: "127.0.0.1",
};

const buildContext = (
  keys: { privateKey: CryptoKey; jwk: Record<string, string> },
  hermesFetch: FetchLike,
  overrides: Record<string, string> = {},
): Context => {
  const config = loadConfig({ ...env, ...overrides });
  return {
    config,
    log: testLog,
    verifier: new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys)),
    fetchImpl: hermesFetch,
  };
};

const pushRequest = (token: string | null, body: string, path = "/"): Request =>
  new Request(`https://webhook-proxy.up.railway.app${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body,
  });

describe("push endpoint", () => {
  test("validates the JWT and forwards the unwrapped message", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const ctx = buildContext(keys, recorder(() => Response.json({ status: "accepted" }), sink));
    const handler = createHandler(ctx);

    const response = await handler(pushRequest(await signJwt(keys, jwtClaims()), pubsubPushBody({ message: { threadId: "18f2", labelIds: ["INBOX"] } })));

    expect(response.status).toBe(204);
    expect(sink.calls).toHaveLength(1);
    const call = sink.calls[0] as Captured;
    expect(call.url).toBe("https://hermes.internal.railway.app/webhooks/gmail");
    expect(call.method).toBe("POST");
    expect(call.headers["x-request-id"]).toBe("2070443601311540");
    expect(call.headers["content-type"]).toBe("application/json");
    expect(call.headers["x-webhook-signature-v2"]).toMatch(/^[0-9a-f]{64}$/);
    expect(call.headers["x-webhook-timestamp"]).toMatch(/^\d+$/);
    expect(JSON.parse(call.body)).toEqual({
      message: { threadId: "18f2", labelIds: ["INBOX"] },
      _pubsub: {
        messageId: "2070443601311540",
        publishTime: "2026-02-26T19:13:55.749Z",
        subscription: SUBSCRIPTION,
        deliveryAttempt: 1,
        attributes: { "X-Gmail-Topic": "inbox" },
      },
    });
  });

  test("accepts the route name as an alternate push path", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(buildContext(keys, recorder(() => new Response(null, { status: 202 }), sink)));
    const response = await handler(pushRequest(await signJwt(keys, jwtClaims()), pubsubPushBody({ ok: true }), "/gmail"));
    expect(response.status).toBe(204);
    expect(sink.calls).toHaveLength(1);
  });

  test("rejects a request with no bearer token", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(buildContext(keys, recorder(() => Response.json({}), sink)));
    const response = await handler(pushRequest(null, pubsubPushBody({ ok: true })));
    expect(response.status).toBe(401);
    expect(sink.calls).toHaveLength(0);
  });

  test("rejects a token from a different service account", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(buildContext(keys, recorder(() => Response.json({}), sink)));
    const token = await signJwt(keys, jwtClaims({ email: "mallory@hermes-agent-511204.iam.gserviceaccount.com" }));
    const response = await handler(pushRequest(token, pubsubPushBody({ ok: true })));
    expect(response.status).toBe(403);
    expect(sink.calls).toHaveLength(0);
  });

  test("rejects a token minted for another audience", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(buildContext(keys, recorder(() => Response.json({}), sink)));
    const token = await signJwt(keys, jwtClaims({ aud: "https://evil.example.com" }));
    const response = await handler(pushRequest(token, pubsubPushBody({ ok: true })));
    expect(response.status).toBe(403);
  });

  test("honours an explicit PUBSUB_AUDIENCE", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(
      buildContext(keys, recorder(() => new Response(null, { status: 204 }), sink), {
        PUBSUB_AUDIENCE: "https://custom-audience.example.com",
      }),
    );
    const good = await handler(pushRequest(await signJwt(keys, jwtClaims({ aud: "https://custom-audience.example.com" })), pubsubPushBody({ ok: true })));
    expect(good.status).toBe(204);
    const bad = await handler(pushRequest(await signJwt(keys, jwtClaims()), pubsubPushBody({ ok: true })));
    expect(bad.status).toBe(403);
  });

  test("rejects a message from another subscription", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(buildContext(keys, recorder(() => Response.json({}), sink)));
    const body = pubsubPushBody({ ok: true }, { subscription: "projects/hermes-agent-511204/subscriptions/other" });
    const response = await handler(pushRequest(await signJwt(keys, jwtClaims()), body));
    expect(response.status).toBe(403);
    expect(sink.calls).toHaveLength(0);
  });

  test("rejects a malformed envelope", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(buildContext(keys, recorder(() => Response.json({}), sink)));
    const token = await signJwt(keys, jwtClaims());
    expect((await handler(pushRequest(token, JSON.stringify({ hello: "world" })))).status).toBe(400);
    expect((await handler(pushRequest(token, "not json"))).status).toBe(400);
    expect(sink.calls).toHaveLength(0);
  });

  test("rejects an oversized body", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(
      buildContext(keys, recorder(() => Response.json({}), sink), { MAX_BODY_BYTES: "1024" }),
    );
    const body = pubsubPushBody({ blob: "x".repeat(4000) });
    const response = await handler(pushRequest(await signJwt(keys, jwtClaims()), body));
    expect(response.status).toBe(413);
  });

  test("returns 503 so Pub/Sub redelivers when Hermes is unavailable", async () => {
    const keys = await generateKeys();
    const handler = createHandler(buildContext(keys, async () => new Response("boom", { status: 503 })));
    const response = await handler(pushRequest(await signJwt(keys, jwtClaims()), pubsubPushBody({ ok: true })));
    expect(response.status).toBe(503);
    expect(((await response.json()) as Record<string, unknown>).error).toBe("upstream_unavailable");
  });

  test("acks a permanent Hermes rejection by default", async () => {
    const keys = await generateKeys();
    const handler = createHandler(buildContext(keys, async () => new Response("unknown route", { status: 404 })));
    const response = await handler(pushRequest(await signJwt(keys, jwtClaims()), pubsubPushBody({ ok: true })));
    expect(response.status).toBe(204);
  });

  test("redelivers instead of dropping when RETRY_ON_4XX is set", async () => {
    const keys = await generateKeys();
    const handler = createHandler(
      buildContext(keys, async () => new Response("unknown route", { status: 404 }), { RETRY_ON_4XX: "true" }),
    );
    const response = await handler(pushRequest(await signJwt(keys, jwtClaims()), pubsubPushBody({ ok: true })));
    expect(response.status).toBe(503);
  });

  test("forwards the original envelope in raw mode", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(
      buildContext(keys, recorder(() => new Response(null, { status: 200 }), sink), { FORWARD_MODE: "raw" }),
    );
    const body = pubsubPushBody({ ok: true });
    await handler(pushRequest(await signJwt(keys, jwtClaims()), body));
    expect(JSON.parse((sink.calls[0] as Captured).body)).toEqual(JSON.parse(body));
  });

  test("sends no signature headers when the scheme is none", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(
      buildContext(keys, recorder(() => new Response(null, { status: 200 }), sink), {
        HERMES_SIGNATURE_SCHEME: "none",
      }),
    );
    await handler(pushRequest(await signJwt(keys, jwtClaims()), pubsubPushBody({ ok: true })));
    const headers = (sink.calls[0] as Captured).headers;
    expect(headers["x-webhook-signature-v2"]).toBeUndefined();
    expect(headers["webhook-signature"]).toBeUndefined();
    expect(headers["x-hub-signature-256"]).toBeUndefined();
    expect(headers["x-request-id"]).toBe("2070443601311540");
  });

  test("signs with the standard-webhooks scheme when configured", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(
      buildContext(keys, recorder(() => new Response(null, { status: 200 }), sink), {
        HERMES_SIGNATURE_SCHEME: "standard",
      }),
    );
    await handler(pushRequest(await signJwt(keys, jwtClaims()), pubsubPushBody({ ok: true })));
    const headers = (sink.calls[0] as Captured).headers;
    expect(headers["webhook-id"]).toBe("2070443601311540");
    expect(headers["webhook-signature"]).toMatch(/^v1,[A-Za-z0-9+/]+=*$/);
  });

  test("skips JWT validation only in loopback mode", async () => {
    const keys = await generateKeys();
    const sink: { calls: Captured[] } = { calls: [] };
    const handler = createHandler(
      buildContext(keys, recorder(() => new Response(null, { status: 200 }), sink), {
        INSECURE_SKIP_JWT: "true",
      }),
    );
    const response = await handler(pushRequest(null, pubsubPushBody({ ok: true })));
    expect(response.status).toBe(204);
    expect(sink.calls).toHaveLength(1);
  });
});

describe("operational routes", () => {
  test("serves health and discovery", async () => {
    const keys = await generateKeys();
    const handler = createHandler(buildContext(keys, async () => new Response(null, { status: 200 })));

    const health = await handler(new Request("https://webhook-proxy.up.railway.app/health"));
    expect(health.status).toBe(200);
    expect(await health.json()).toEqual({ status: "ok", platform: "pubsub-push-proxy", route: "gmail" });

    const root = await handler(new Request(PROXY_URL));
    expect(root.status).toBe(200);
    const info = (await root.json()) as Record<string, unknown>;
    expect(info.forwardMode).toBe("decoded");
    expect(info.jwtValidation).toBe("enabled");
  });

  test("rejects unknown paths and non-POST methods", async () => {
    const keys = await generateKeys();
    const handler = createHandler(buildContext(keys, async () => new Response(null, { status: 200 })));

    expect((await handler(new Request("https://webhook-proxy.up.railway.app/nope"))).status).toBe(404);
    expect(
      (await handler(new Request("https://webhook-proxy.up.railway.app/webhook", { method: "DELETE" }))).status,
    ).toBe(405);
    expect(
      (await handler(new Request("https://webhook-proxy.up.railway.app/webhook", { method: "GET" }))).status,
    ).toBe(405);
  });
});
