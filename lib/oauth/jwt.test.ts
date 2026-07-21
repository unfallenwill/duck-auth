/**
 * Unit tests for lib/oauth/jwt.ts.
 *
 * Strategy: mock @/lib/oauth/keys so loadKeys() returns a pre-generated
 * in-memory RSA key pair — no filesystem needed.
 *
 * Because vi.mock() is hoisted above all imports and our key generation
 * requires async jose functions, we use vi.doMock() + dynamic import()
 * inside beforeAll() instead.
 */
import { describe, it, expect, vi, beforeAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";

// ── Generate fixed PEM key pairs synchronously at module level ───────────

const pair1 = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const pair2 = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const KID = "key-1";

// ── Resolved in beforeAll after async key import ─────────────────────────

let signAccessToken: typeof import("@/lib/oauth/jwt")["signAccessToken"];
let signIdToken: typeof import("@/lib/oauth/jwt")["signIdToken"];
let verifyAccessToken: typeof import("@/lib/oauth/jwt")["verifyAccessToken"];
let getJwks: typeof import("@/lib/oauth/jwt")["getJwks"];
let ISSUER: string;
let publicKey: CryptoKey;
let otherPrivKey: CryptoKey;

beforeAll(async () => {
  const { importPKCS8, importSPKI } = await import("jose");

  const privateKey = await importPKCS8(pair1.privateKey, "RS256");
  publicKey = await importSPKI(pair1.publicKey, "RS256");
  otherPrivKey = await importPKCS8(pair2.privateKey, "RS256");

  vi.doMock("@/lib/oauth/keys", () => ({
    loadKeys: vi.fn().mockResolvedValue({ privateKey, publicKey }),
    KID,
  }));

  // Dynamically import AFTER doMock so the mock is in effect
  const jwtMod = await import("@/lib/oauth/jwt");
  signAccessToken = jwtMod.signAccessToken;
  signIdToken = jwtMod.signIdToken;
  verifyAccessToken = jwtMod.verifyAccessToken;
  getJwks = jwtMod.getJwks;

  const { ISSUER: issuer } = await import("@/lib/oauth/discovery");
  ISSUER = issuer;
});

// ── Helpers ─────────────────────────────────────────────────────────────

function decodeHeader(token: string) {
  return JSON.parse(
    Buffer.from(token.split(".")[0], "base64url").toString("utf8"),
  );
}

function decodePayload(token: string) {
  return JSON.parse(
    Buffer.from(token.split(".")[1], "base64url").toString("utf8"),
  );
}

// ── Tests ───────────────────────────────────────────────────────────────

describe("signAccessToken", () => {
  it("round-trips through verifyAccessToken", async () => {
    const { token } = await signAccessToken({
      sub: "user-123",
      clientId: "client-abc",
      scopes: "openid profile email",
      ttlSeconds: 3600,
    });

    const claims = await verifyAccessToken(token);
    expect(claims.sub).toBe("user-123");
    expect(claims.client_id).toBe("client-abc");
    expect(claims.scope).toBe("openid profile email");
    expect(claims.iss).toBe(ISSUER);
    expect(claims.jti).toBeTruthy();
  });

  it("has typ: 'at+jwt' in the header", async () => {
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: 60,
    });
    expect(decodeHeader(token).typ).toBe("at+jwt");
  });

  it("has alg: 'RS256' in the header", async () => {
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: 60,
    });
    expect(decodeHeader(token).alg).toBe("RS256");
  });

  it("has kid header matching KID", async () => {
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: 60,
    });
    expect(decodeHeader(token).kid).toBe(KID);
  });

  it("has aud claim equal to clientId", async () => {
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "my-client",
      scopes: "openid",
      ttlSeconds: 60,
    });

    const claims = await verifyAccessToken(token);
    expect(claims.aud).toBe("my-client");
  });

  it("has iat and exp claims with correct TTL", async () => {
    const before = Math.floor(Date.now() / 1000);
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: 600,
    });
    const after = Math.floor(Date.now() / 1000);

    const claims = await verifyAccessToken(token);
    expect(claims.iat).toBeGreaterThanOrEqual(before);
    expect(claims.iat).toBeLessThanOrEqual(after);
    expect(claims.exp - claims.iat).toBe(600);
  });

  it("returns expiresAt as a Date matching exp", async () => {
    const { token, expiresAt } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: 3600,
    });
    const claims = await verifyAccessToken(token);
    expect(expiresAt).toBeInstanceOf(Date);
    expect(Math.floor(expiresAt.getTime() / 1000)).toBe(claims.exp);
  });
});

describe("signIdToken", () => {
  it("has typ: 'JWT' in the header", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      clientId: "c1",
      ttlSeconds: 3600,
    });
    expect(decodeHeader(token).typ).toBe("JWT");
  });

  it("has alg: 'RS256' in the header", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      clientId: "c1",
      ttlSeconds: 3600,
    });
    expect(decodeHeader(token).alg).toBe("RS256");
  });

  it("has aud claim equal to clientId", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      email: "test@example.com",
      clientId: "client-xyz",
      ttlSeconds: 3600,
    });
    expect(decodePayload(token).aud).toBe("client-xyz");
  });

  it("includes email and name claims when provided", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      email: "user@test.com",
      name: "Test User",
      clientId: "c1",
      ttlSeconds: 3600,
    });

    const claims = decodePayload(token);
    expect(claims.email).toBe("user@test.com");
    expect(claims.name).toBe("Test User");
  });

  it("omits email and name when not provided", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      clientId: "c1",
      ttlSeconds: 3600,
    });

    const claims = decodePayload(token);
    expect(claims.email).toBeUndefined();
    expect(claims.name).toBeUndefined();
  });

  it("has kid header matching KID", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      clientId: "c1",
      ttlSeconds: 3600,
    });
    expect(decodeHeader(token).kid).toBe(KID);
  });
});

describe("verifyAccessToken", () => {
  it("rejects a token signed with a different key", async () => {
    const { SignJWT } = await import("jose");
    const forgedToken = await new SignJWT({ sub: "evil" })
      .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: KID })
      .setIssuer(ISSUER)
      .setAudience("c1")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
      .sign(otherPrivKey);

    await expect(verifyAccessToken(forgedToken)).rejects.toThrow();
  });

  it("rejects an expired token", async () => {
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: -10, // already expired
    });

    await expect(verifyAccessToken(token)).rejects.toThrow();
  });

  it("token iss claim matches ISSUER", async () => {
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: 3600,
    });

    const claims = await verifyAccessToken(token);
    expect(claims.iss).toBe(ISSUER);
  });
});

describe("getJwks", () => {
  it("returns keys array with correct structure", async () => {
    const jwks = await getJwks();

    expect(jwks).toHaveProperty("keys");
    expect(Array.isArray(jwks.keys)).toBe(true);
    expect(jwks.keys).toHaveLength(1);
  });

  it("includes kid, use, alg in the key", async () => {
    const jwks = await getJwks();
    const key = jwks.keys[0];

    expect(key.kid).toBe(KID);
    expect(key.use).toBe("sig");
    expect(key.alg).toBe("RS256");
  });

  it("includes kty and n/e (RSA public key components)", async () => {
    const jwks = await getJwks();
    const key = jwks.keys[0];

    expect(key.kty).toBe("RSA");
    expect(typeof key.n).toBe("string");
    expect(key.n!.length).toBeGreaterThan(0);
    expect(typeof key.e).toBe("string");
  });

  it("returns a key that matches the signing public key", async () => {
    const { exportJWK } = await import("jose");
    const jwks = await getJwks();
    const key = jwks.keys[0];

    const expectedJwk = await exportJWK(publicKey);
    expect(key.n).toBe(expectedJwk.n);
    expect(key.e).toBe(expectedJwk.e);
  });
});
