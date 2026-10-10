import type { Logger } from "./logger.ts";
import type { FetchLike } from "./fetch-like.ts";
import { b64urlToBytes, utf8 } from "./encoding.ts";

const JWKS_URL = "https://www.googleapis.com/oauth2/v3/certs";
const ALLOWED_ISSUERS = new Set(["https://accounts.google.com", "accounts.google.com"]);
const FORCED_REFRESH_COOLDOWN_MS = 60_000;

export class JwtError extends Error {
  readonly status: number;

  constructor(message: string, status = 401) {
    super(message);
    this.name = "JwtError";
    this.status = status;
  }
}

interface Jwk {
  kid?: string;
  kty?: string;
  n?: string;
  e?: string;
  alg?: string;
  use?: string;
}

export interface GoogleClaims {
  iss?: string;
  aud?: string | string[];
  sub?: string;
  azp?: string;
  email?: string;
  email_verified?: boolean | string;
  exp?: number;
  iat?: number;
}

export interface VerifyOptions {
  expectedEmail: string;
  allowedAudiences: string[];
  maxAgeSeconds: number;
  skewSeconds: number;
}

export const normalizeAudience = (value: string): string =>
  value
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/[./]+$/, "")
    .toLowerCase();

const claimAudiences = (aud: string | string[] | undefined): string[] => {
  if (aud === undefined) return [];
  const list = Array.isArray(aud) ? aud : [aud];
  return list.filter((entry) => typeof entry === "string").map(normalizeAudience);
};

export class GoogleIdTokenVerifier {
  #log: Logger;
  #jwks = new Map<string, Jwk>();
  #keys = new Map<string, CryptoKey>();
  #fetchedAt = 0;
  #forcedAt = 0;
  #inflight: Promise<boolean> | null = null;
  #ttlMs: number;
  #fetchImpl: FetchLike;

  constructor(log: Logger, ttlSeconds = 3600, fetchImpl: FetchLike = globalThis.fetch) {
    this.#log = log.child({ component: "jwt" });
    this.#ttlMs = ttlSeconds * 1000;
    this.#fetchImpl = fetchImpl;
  }

  async verify(token: string, options: VerifyOptions): Promise<GoogleClaims> {
    const parts = token.split(".");
    if (parts.length !== 3) throw new JwtError("malformed token");

    let header: { alg?: string; kid?: string; typ?: string };
    let claims: GoogleClaims;
    try {
      header = JSON.parse(utf8(b64urlToBytes(parts[0] as string))) as typeof header;
      claims = JSON.parse(utf8(b64urlToBytes(parts[1] as string))) as GoogleClaims;
    } catch {
      throw new JwtError("token segments are not valid base64url JSON");
    }

    if (header.alg !== "RS256") throw new JwtError(`unsupported alg "${header.alg}"`);
    if (!header.kid) throw new JwtError("token header is missing kid");

    const key = await this.#resolveKey(header.kid);
    const signatureValid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      b64urlToBytes(parts[2] as string) as unknown as ArrayBuffer,
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`),
    );
    if (!signatureValid) throw new JwtError("token signature is invalid");

    this.#checkClaims(claims, options);
    return claims;
  }

  #checkClaims(claims: GoogleClaims, options: VerifyOptions): void {
    const now = Math.floor(Date.now() / 1000);

    if (typeof claims.iss !== "string" || !ALLOWED_ISSUERS.has(claims.iss)) {
      throw new JwtError(`unexpected issuer "${claims.iss}"`, 403);
    }

    if (typeof claims.exp !== "number" || now > claims.exp + options.skewSeconds) {
      throw new JwtError("token is expired", 403);
    }

    if (typeof claims.iat !== "number") {
      throw new JwtError("token is missing iat", 403);
    }
    if (claims.iat > now + options.skewSeconds) {
      throw new JwtError("token iat is in the future", 403);
    }
    if (now - claims.iat > options.maxAgeSeconds + options.skewSeconds) {
      throw new JwtError("token is older than the accepted maximum age", 403);
    }

    const allowed = options.allowedAudiences.map(normalizeAudience).filter((entry) => entry !== "");
    if (allowed.length > 0) {
      const presented = claimAudiences(claims.aud);
      if (presented.length === 0 || !presented.some((entry) => allowed.includes(entry))) {
        throw new JwtError(`unexpected audience "${claims.aud}"`, 403);
      }
    }

    if (typeof claims.email !== "string" || claims.email.toLowerCase() !== options.expectedEmail) {
      throw new JwtError(`unexpected signer email "${claims.email}"`, 403);
    }

    const verified = claims.email_verified;
    if (verified !== true && verified !== "true") {
      throw new JwtError("signer email is not verified", 403);
    }
  }

  async #resolveKey(kid: string): Promise<CryptoKey> {
    const cached = this.#keys.get(kid);
    if (cached) return cached;

    if (Date.now() >= this.#fetchedAt) await this.#refreshJwks(false);
    const afterTtl = this.#keys.get(kid);
    if (afterTtl) return afterTtl;

    if (Date.now() - this.#forcedAt >= FORCED_REFRESH_COOLDOWN_MS) {
      await this.#refreshJwks(true);
      const afterForced = this.#keys.get(kid);
      if (afterForced) return afterForced;
    }

    throw new JwtError(`unknown signing key "${kid}"`);
  }

  async #refreshJwks(forced: boolean): Promise<boolean> {
    if (this.#inflight) return this.#inflight;
    this.#inflight = this.#fetchJwks(forced).finally(() => {
      this.#inflight = null;
    });
    return this.#inflight;
  }

  async #fetchJwks(forced: boolean): Promise<boolean> {
    if (forced) this.#forcedAt = Date.now();
    let response: Response;
    try {
      response = await this.#fetchImpl(JWKS_URL, {
        signal: AbortSignal.timeout(5000),
        headers: { accept: "application/json" },
      });
    } catch (error) {
      this.#log.warn("jwks_fetch_failed", { forced, error: (error as Error).message });
      if (this.#jwks.size === 0) throw new JwtError("unable to load Google signing keys");
      this.#fetchedAt = Date.now() + 30_000;
      return false;
    }

    if (!response.ok) {
      this.#log.warn("jwks_bad_status", { forced, status: response.status });
      if (this.#jwks.size === 0) throw new JwtError("unable to load Google signing keys");
      this.#fetchedAt = Date.now() + 30_000;
      return false;
    }

    const body = (await response.json()) as { keys?: Jwk[] };
    const keys = body.keys ?? [];
    if (keys.length === 0) {
      if (this.#jwks.size === 0) throw new JwtError("Google returned no signing keys");
      this.#fetchedAt = Date.now() + 30_000;
      return false;
    }

    const nextJwks = new Map<string, Jwk>();
    const nextKeys = new Map<string, CryptoKey>();
    for (const jwk of keys) {
      if (!jwk.kid || jwk.kty !== "RSA" || !jwk.n || !jwk.e) continue;
      nextJwks.set(jwk.kid, jwk);
      try {
        nextKeys.set(
          jwk.kid,
          await crypto.subtle.importKey(
            "jwk",
            { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", use: "sig" },
            { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
            false,
            ["verify"],
          ),
        );
      } catch {
        this.#log.warn("jwk_import_failed", { kid: jwk.kid });
      }
    }

    this.#jwks = nextJwks;
    this.#keys = nextKeys;
    this.#fetchedAt = Date.now() + this.#ttlMs;
    this.#log.debug("jwks_refreshed", { forced, kids: nextKeys.size });
    return true;
  }
}

export const extractBearerToken = (authorization: string | null): string | null => {
  if (!authorization) return null;
  const match = /^Bearer\s+(.+)$/i.exec(authorization.trim());
  return match?.[1]?.trim() || null;
};
