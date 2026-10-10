import { describe, expect, test } from "bun:test";
import { ConfigError, loadConfig } from "../src/config.ts";

const base = {
  HERMES_WEBHOOK_URL: "https://hermes.example.railway.app/webhooks/gmail",
  HERMES_WEBHOOK_SECRET: "route-secret",
  BIND_HOST: "127.0.0.1",
};

describe("loadConfig", () => {
  test("applies the placeholder pubsub defaults", () => {
    const config = loadConfig(base);
    expect(config.pubsub.project).toBe("hermes-agent-1234");
    expect(config.pubsub.subscription).toBe("hermes");
    expect(config.pubsub.serviceAccountEmail).toBe(
      "hermes-agent@hermes-agent-1234.iam.gserviceaccount.com",
    );
    expect(config.hermes.scheme).toBe("v2");
    expect(config.hermes.mode).toBe("decoded");
    expect(config.hermes.route).toBe("gmail");
    expect(config.hermes.retryOn4xx).toBe(false);
    expect(config.bindHost).toBe("127.0.0.1");
  });

  test("reads the pubsub identity from the environment", () => {
    const config = loadConfig({
      ...base,
      PUBSUB_PROJECT: "hermes-agent-511204",
      PUBSUB_SERVICE_ACCOUNT_EMAIL: "hermes-agent@hermes-agent-511204.iam.gserviceaccount.com",
    });
    expect(config.pubsub.project).toBe("hermes-agent-511204");
    expect(config.pubsub.serviceAccountEmail).toBe(
      "hermes-agent@hermes-agent-511204.iam.gserviceaccount.com",
    );
  });

  test("binds from BIND_HOST and never reads HOSTNAME", () => {
    expect(loadConfig(base).bindHost).toBe("127.0.0.1");
    expect(loadConfig({ ...base, BIND_HOST: "" }).bindHost).toBe("0.0.0.0");
    expect(loadConfig({ ...base, BIND_HOST: "::" }).bindHost).toBe("::");
    expect(
      loadConfig({ ...base, HOSTNAME: "webhook-proxy-7d9f4c8b51-x2rkq" }).bindHost,
    ).toBe("127.0.0.1");
  });

  test("restricts the jwt bypass to a loopback BIND_HOST", () => {
    expect(() =>
      loadConfig({ ...base, BIND_HOST: "0.0.0.0", INSECURE_SKIP_JWT: "true" }),
    ).toThrow(ConfigError);
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
      loadConfig({ ...base, INSECURE_SKIP_JWT: "true", BIND_HOST: "0.0.0.0" }),
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
