import { describe, expect, test } from "bun:test";
import { ConfigError, loadConfig } from "../src/config.ts";

const base = {
  HERMES_WEBHOOK_URL: "https://hermes.example.railway.app/webhooks/gmail",
  HERMES_WEBHOOK_SECRET: "route-secret",
  HOSTNAME: "127.0.0.1",
};

describe("loadConfig", () => {
  test("applies the hermes project defaults", () => {
    const config = loadConfig(base);
    expect(config.pubsub.project).toBe("hermes-agent-511204");
    expect(config.pubsub.subscription).toBe("hermes");
    expect(config.pubsub.serviceAccountEmail).toBe(
      "hermes-agent@hermes-agent-511204.iam.gserviceaccount.com",
    );
    expect(config.hermes.scheme).toBe("v2");
    expect(config.hermes.mode).toBe("decoded");
    expect(config.hermes.route).toBe("gmail");
    expect(config.hermes.retryOn4xx).toBe(false);
  });

  test("requires a hermes target url", () => {
    const { HERMES_WEBHOOK_URL: _drop, ...rest } = base;
    expect(() => loadConfig(rest)).toThrow(ConfigError);
  });

  test("rejects a non-http url", () => {
    expect(() => loadConfig({ ...base, HERMES_WEBHOOK_URL: "ftp://hermes.example/webhooks/gmail" })).toThrow(
      ConfigError,
    );
  });

  test("requires a secret unless the scheme is none", () => {
    const { HERMES_WEBHOOK_SECRET: _drop, ...rest } = base;
    expect(() => loadConfig(rest)).toThrow(ConfigError);
    expect(() => loadConfig({ ...rest, HERMES_SIGNATURE_SCHEME: "none" })).not.toThrow();
  });

  test("rejects an unknown scheme", () => {
    expect(() => loadConfig({ ...base, HERMES_SIGNATURE_SCHEME: "sha1" })).toThrow(ConfigError);
  });

  test("rejects an invalid url", () => {
    expect(() => loadConfig({ ...base, HERMES_WEBHOOK_URL: "not a url" })).toThrow(ConfigError);
  });

  test("only allows jwt bypass on loopback", () => {
    expect(() => loadConfig({ ...base, INSECURE_SKIP_JWT: "true" })).not.toThrow();
    expect(() =>
      loadConfig({ ...base, INSECURE_SKIP_JWT: "true", HOSTNAME: "0.0.0.0" }),
    ).toThrow(ConfigError);
  });

  test("parses a comma separated audience list", () => {
    const config = loadConfig({ ...base, PUBSUB_AUDIENCE: "https://a.example.com , b.example.com," });
    expect(config.pubsub.audiences).toEqual(["a.example.com", "b.example.com"]);
  });

  test("validates numeric bounds", () => {
    expect(() => loadConfig({ ...base, HERMES_TIMEOUT_MS: "0" })).toThrow(ConfigError);
    expect(() => loadConfig({ ...base, HERMES_TIMEOUT_MS: "abc" })).toThrow(ConfigError);
    expect(loadConfig({ ...base, PORT: "3000" }).port).toBe(3000);
  });

  test("accepts http targets when jwt bypass is explicit", () => {
    const config = loadConfig({
      ...base,
      HERMES_WEBHOOK_URL: "http://127.0.0.1:8644/webhooks/gmail",
      INSECURE_SKIP_JWT: "true",
    });
    expect(config.hermes.url).toBe("http://127.0.0.1:8644/webhooks/gmail");
  });
});
