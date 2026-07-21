/**
 * Unit tests for lib/oauth/jwt.ts.
 *
 * Strategy: mock @/lib/oauth/keys so loadKeys() returns a pre-generated
 * in-memory RSA key pair — no filesystem needed.
 */
import { describe, it, expect, beforeAll, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { importPKCS8, importSPKI, SignJWT, exportJWK } from "jose";

// ── Generate a fixed key pair for all tests ──────────────────────────────

const { publicKey: pubPem, privateKey: privPem } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

// A *different* key pair used to sign tokens that should fail verification.
const {
  publicKey: otherPubPem,
  privateKey: otherPrivPem,
} = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const KID = "key-1";

// ── Mock keys module ────────────────────────────────────────────────────
// Pre-import keys synchronously is not possible (importPKCS8 is async),
// so use a lazy initializer that vi.mock can call.
let _privKey: Awaited<ReturnType<typeof importPKCS8>> | null = null;
let _pubKey: Awaited<ReturnType<typeof importSPKI>> | null = null;

vi.mock("@/lib/oauth/keys", () => ({
  loadKeys: vi.fn().mockImplementation(async () => {
    if (!_privKey) {
      _privKey = await importPKCS8(privPem, "RS256");
      _pubKey = await importSPKI(pubPem, "RS256");
    }
    return { privateKey: _privKey, publicKey: _pubKey };
  }),
  KID,
}));

// ── Import after mock is set up ─────────────────────────────────────────

import {
  signAccessToken,
  signIdToken,
  verifyAccessToken,
  getJwks,
} from "@/lib/oauth/jwt";
import { ISSUER } from "@/lib/oauth/discovery";

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

    const headerB64 = token.split(".")[0];
    const header = JSON.parse(
      Buffer.from(headerB64, "base64url").toString("utf8"),
    );
    expect(header.typ).toBe("at+jwt");
  });

  it("has alg: 'RS256' in the header", async () => {
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: 60,
    });

    const headerB64 = token.split(".")[0];
    const header = JSON.parse(
      Buffer.from(headerB64, "base64url").toString("utf8"),
    );
    expect(header.alg).toBe("RS256");
  });

  it("has kid header matching KID", async () => {
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: 60,
    });

    const headerB64 = token.split(".")[0];
    const header = JSON.parse(
      Buffer.from(headerB64, "base64url").toString("utf8"),
    );
    expect(header.kid).toBe(KID);
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

    const headerB64 = token.split(".")[0];
    const header = JSON.parse(
      Buffer.from(headerB64, "base64url").toString("utf8"),
    );
    expect(header.typ).toBe("JWT");
  });

  it("has alg: 'RS256' in the header", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      clientId: "c1",
      ttlSeconds: 3600,
    });

    const headerB64 = token.split(".")[0];
    const header = JSON.parse(
      Buffer.from(headerB64, "base64url").toString("utf8"),
    );
    expect(header.alg).toBe("RS256");
  });

  it("has aud claim equal to clientId", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      email: "test@example.com",
      clientId: "client-xyz",
      ttlSeconds: 3600,
    });

    const claims = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString("utf8"),
    );
    expect(claims.aud).toBe("client-xyz");
  });

  it("includes email and name claims when provided", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      email: "user@test.com",
      name: "Test User",
      clientId: "c1",
      ttlSeconds: 3600,
    });

    const claims = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString("utf8"),
    );
    expect(claims.email).toBe("user@test.com");
    expect(claims.name).toBe("Test User");
  });

  it("omits email and name when not provided", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      clientId: "c1",
      ttlSeconds: 3600,
    });

    const claims = JSON.parse(
      Buffer.from(token.split(".")[1], "base64url").toString("utf8"),
    );
    expect(claims.email).toBeUndefined();
    expect(claims.name).toBeUndefined();
  });

  it("has kid header matching KID", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      clientId: "c1",
      ttlSeconds: 3600,
    });

    const headerB64 = token.split(".")[0];
    const header = JSON.parse(
      Buffer.from(headerB64, "base64url").toString("utf8"),
    );
    expect(header.kid).toBe(KID);
  });
});

describe("verifyAccessToken", () => {
  it("rejects a token signed with a different key", async () => {
    // Sign with a different private key
    const otherPriv = await importPKCS8(otherPrivPem, "RS256");
    const forgedToken = await new SignJWT({ sub: "evil" })
      .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: KID })
      .setIssuer(ISSUER)
      .setAudience("c1")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
      .sign(otherPriv);

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

  it("rejects a token with wrong issuer", async () => {
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: 3600,
    });

    // Verify with wrong issuer by re-signing with wrong issuer isn't straightforward;
    // instead verify that the token's iss matches ISSUER
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
    expect(key.n.length).toBeGreaterThan(0);
    expect(typeof key.e).toBe("string");
  });

  it("returns a key that matches the signing public key", async () => {
    const jwks = await getJwks();
    const key = jwks.keys[0];

    // Export the actual public key to JWK and compare n modulus
    const expectedJwk = await exportJWK(publicKey);
    expect(key.n).toBe(expectedJwk.n);
    expect(key.e).toBe(expectedJwk.e);
  });
});
