import { Logger } from "../src/logger.ts";
import type { FetchLike } from "../src/fetch-like.ts";
import type { GoogleIdTokenVerifier } from "../src/jwt.ts";

export const KID = "test-kid-1";
export const SERVICE_ACCOUNT = "hermes-agent@hermes-agent-511204.iam.gserviceaccount.com";
export const AUDIENCE_HOST = "webhook-proxy.up.railway.app";
export const SUBSCRIPTION = "projects/hermes-agent-511204/subscriptions/hermes";

export const testLog = new Logger("off");
export const encoder = new TextEncoder();

export const bytesToB64Url = (bytes: Uint8Array): string => {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

export interface TestKeys {
  privateKey: CryptoKey;
  jwk: Record<string, string>;
}

export const generateKeys = async (): Promise<TestKeys> => {
  const pair = (await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const exported = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Record<string, string>;
  return { privateKey: pair.privateKey, jwk: exported };
};

export const signJwt = async (
  keys: TestKeys,
  claims: Record<string, unknown>,
  headerOverrides: Record<string, unknown> = {},
): Promise<string> => {
  const header = { alg: "RS256", typ: "JWT", kid: KID, ...headerOverrides };
  const encodedHeader = bytesToB64Url(encoder.encode(JSON.stringify(header)));
  const encodedClaims = bytesToB64Url(encoder.encode(JSON.stringify(claims)));
  const payload = `${encodedHeader}.${encodedClaims}`;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", keys.privateKey, encoder.encode(payload));
  return `${payload}.${bytesToB64Url(new Uint8Array(signature))}`;
};

export const jwtClaims = (overrides: Record<string, unknown> = {}): Record<string, unknown> => {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: "https://accounts.google.com",
    aud: `https://${AUDIENCE_HOST}`,
    sub: "113774264463038321964",
    azp: "113774264463038321964",
    email: SERVICE_ACCOUNT,
    email_verified: true,
    iat: now,
    exp: now + 300,
    ...overrides,
  };
};

export const jwksFetch =
  (keys: TestKeys, counter: { count: number } = { count: 0 }): FetchLike =>
  async () => {
    counter.count += 1;
    return Response.json({ keys: [{ kid: KID, ...keys.jwk }] });
  };

export const verifyOptions = (
  overrides: Partial<Parameters<GoogleIdTokenVerifier["verify"]>[1]> = {},
) => ({
  expectedEmail: SERVICE_ACCOUNT,
  allowedAudiences: [AUDIENCE_HOST],
  maxAgeSeconds: 3600,
  skewSeconds: 60,
  ...overrides,
});

export const pubsubPushBody = (
  data: unknown,
  overrides: Record<string, unknown> = {},
): string =>
  JSON.stringify({
    message: {
      attributes: { "X-Gmail-Topic": "inbox" },
      data: typeof data === "string" ? data : btoa(JSON.stringify(data)),
      messageId: "2070443601311540",
      publishTime: "2026-02-26T19:13:55.749Z",
    },
    subscription: SUBSCRIPTION,
    deliveryAttempt: 1,
    ...overrides,
  });
