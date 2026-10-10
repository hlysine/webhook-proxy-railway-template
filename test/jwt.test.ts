import { describe, expect, test } from "bun:test";
import { GoogleIdTokenVerifier, JwtError, extractBearerToken } from "../src/jwt.ts";
import { b64urlToBytes, toHex, utf8 } from "../src/encoding.ts";
import type { FetchLike } from "../src/fetch-like.ts";
import {
  AUDIENCE_HOST,
  SERVICE_ACCOUNT,
  generateKeys,
  jwksFetch,
  jwtClaims,
  signJwt,
  testLog,
  verifyOptions,
} from "./helpers.ts";

describe("GoogleIdTokenVerifier", () => {
  test("accepts a token signed by the advertised key", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const payload = await verifier.verify(await signJwt(keys, jwtClaims()), verifyOptions());
    expect(payload.email).toBe(SERVICE_ACCOUNT);
  });

  test("accepts scheme-less and trailing-slash audience forms", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    for (const aud of [AUDIENCE_HOST, `https://${AUDIENCE_HOST}/`, `http://${AUDIENCE_HOST}`]) {
      const token = await signJwt(keys, jwtClaims({ aud }));
      await expect(verifier.verify(token, verifyOptions())).resolves.toBeTruthy();
    }
  });

  test("rejects a tampered payload", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const token = await signJwt(keys, jwtClaims());
    const [h, , s] = token.split(".");
    const forged = Buffer.from(JSON.stringify(jwtClaims({ email: "attacker@example.com" }))).toString("base64url");
    await expect(verifier.verify(`${h}.${forged}.${s}`, verifyOptions())).rejects.toBeInstanceOf(JwtError);
  });

  test("rejects a token signed by an unknown key", async () => {
    const keys = await generateKeys();
    const other = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const token = await signJwt(other, jwtClaims());
    await expect(verifier.verify(token, verifyOptions())).rejects.toThrow(/signature is invalid/);
  });

  test("rejects an expired token", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(keys, jwtClaims({ iat: now - 7200, exp: now - 3600 }));
    await expect(verifier.verify(token, verifyOptions())).rejects.toThrow(/expired|maximum age/);
  });

  test("rejects a token older than the maximum age", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(keys, jwtClaims({ iat: now - 7200, exp: now + 7200 }));
    await expect(verifier.verify(token, verifyOptions())).rejects.toThrow(/maximum age/);
  });

  test("rejects a future iat", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const now = Math.floor(Date.now() / 1000);
    const token = await signJwt(keys, jwtClaims({ iat: now + 600, exp: now + 3600 }));
    await expect(verifier.verify(token, verifyOptions())).rejects.toThrow(/future/);
  });

  test("rejects a wrong issuer", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const token = await signJwt(keys, jwtClaims({ iss: "https://evil.example.com" }));
    await expect(verifier.verify(token, verifyOptions())).rejects.toThrow(/issuer/);
  });

  test("accepts the accounts.google.com issuer without scheme", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const token = await signJwt(keys, jwtClaims({ iss: "accounts.google.com" }));
    await expect(verifier.verify(token, verifyOptions())).resolves.toBeTruthy();
  });

  test("rejects a wrong signer email", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const token = await signJwt(keys, jwtClaims({ email: "other@hermes-agent-511204.iam.gserviceaccount.com" }));
    await expect(verifier.verify(token, verifyOptions())).rejects.toThrow(/signer email/);
  });

  test("rejects an unverified email claim", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    await expect(
      verifier.verify(await signJwt(keys, jwtClaims({ email_verified: false })), verifyOptions()),
    ).rejects.toThrow(/not verified/);
  });

  test("accepts the string email_verified form", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const token = await signJwt(keys, jwtClaims({ email_verified: "true" }));
    await expect(verifier.verify(token, verifyOptions())).resolves.toBeTruthy();
  });

  test("rejects an unexpected audience", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const token = await signJwt(keys, jwtClaims({ aud: "https://someone-else.example.com" }));
    await expect(verifier.verify(token, verifyOptions())).rejects.toThrow(/audience/);
  });

  test("skips audience matching when no audience is configured", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const token = await signJwt(keys, jwtClaims({ aud: "https://anything.example.com" }));
    await expect(verifier.verify(token, verifyOptions({ allowedAudiences: [] }))).resolves.toBeTruthy();
  });

  test("rejects a missing audience when one is configured", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const { aud: _drop, ...rest } = jwtClaims();
    await expect(verifier.verify(await signJwt(keys, rest), verifyOptions())).rejects.toThrow(/audience/);
  });

  test("rejects a non-RS256 algorithm", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const token = await signJwt(keys, jwtClaims(), { alg: "HS256" });
    await expect(verifier.verify(token, verifyOptions())).rejects.toThrow(/unsupported alg/);
  });

  test("rejects a token with no kid", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    const token = await signJwt(keys, jwtClaims(), { kid: undefined });
    await expect(verifier.verify(token, verifyOptions())).rejects.toThrow(/missing kid/);
  });

  test("rejects malformed tokens", async () => {
    const keys = await generateKeys();
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys));
    await expect(verifier.verify("not-a-jwt", verifyOptions())).rejects.toThrow(/malformed/);
  });

  test("caches the jwks across verifications", async () => {
    const keys = await generateKeys();
    const calls = { count: 0 };
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, jwksFetch(keys, calls));
    for (let i = 0; i < 3; i++) {
      await verifier.verify(await signJwt(keys, jwtClaims()), verifyOptions());
    }
    expect(calls.count).toBe(1);
  });

  test("refetches the jwks once when an unseen kid appears", async () => {
    const rotated = await generateKeys();
    const calls = { count: 0 };
    const fetchImpl: FetchLike = async () => {
      calls.count += 1;
      const kid = calls.count === 1 ? "old-kid" : "test-kid-1";
      return Response.json({ keys: [{ kid, ...rotated.jwk }] });
    };
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, fetchImpl);
    await expect(verifier.verify(await signJwt(rotated, jwtClaims()), verifyOptions())).resolves.toBeTruthy();
    expect(calls.count).toBe(2);
  });

  test("does not hammer Google when a kid stays unknown", async () => {
    const keys = await generateKeys();
    const calls = { count: 0 };
    const fetchImpl: FetchLike = async () => {
      calls.count += 1;
      return Response.json({ keys: [{ kid: "some-other-kid", ...keys.jwk }] });
    };
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, fetchImpl);
    const token = await signJwt(keys, jwtClaims());
    await expect(verifier.verify(token, verifyOptions())).rejects.toThrow(/unknown signing key/);
    expect(calls.count).toBe(2);
    await expect(verifier.verify(token, verifyOptions())).rejects.toThrow(/unknown signing key/);
    expect(calls.count).toBe(2);
  });

  test("surfaces a JWKS outage when no keys are cached", async () => {
    const keys = await generateKeys();
    const failing: FetchLike = async () => {
      throw new Error("network down");
    };
    const verifier = new GoogleIdTokenVerifier(testLog, 3600, failing);
    await expect(verifier.verify(await signJwt(keys, jwtClaims()), verifyOptions())).rejects.toThrow(
      /unable to load Google signing keys/,
    );
  });
});

describe("extractBearerToken", () => {
  test("parses a bearer header", () => {
    expect(extractBearerToken("Bearer abc.def.ghi")).toBe("abc.def.ghi");
    expect(extractBearerToken("bearer  abc ")).toBe("abc");
  });

  test("rejects other shapes", () => {
    expect(extractBearerToken(null)).toBeNull();
    expect(extractBearerToken("Basic abc")).toBeNull();
    expect(extractBearerToken("Bearer   ")).toBeNull();
  });
});

describe("encoding", () => {
  test("decodes standard and url-safe base64", () => {
    const source = new Uint8Array([0, 1, 250, 255, 128, 62, 63, 45, 95]);
    const standard = btoa(String.fromCharCode(...source));
    const urlSafe = standard.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    expect(toHex(b64urlToBytes(standard))).toBe(toHex(source));
    expect(toHex(b64urlToBytes(urlSafe))).toBe(toHex(source));
    expect(utf8(b64urlToBytes(standard))).toBe(new TextDecoder().decode(source));
  });
});
