/**
 * Unit tests for lib/oauth/jwt.ts.
 *
 * Strategy: mock @/lib/oauth/keys so loadKeys() returns pre-generated
 * in-memory RSA key pairs — no filesystem needed.
 *
 * Verifies the new multi-key flow (issue #31):
 *   - signAccessToken / signIdToken use the primary kid
 *   - verifyAccessToken reads kid from header and looks up the matching key
 *     in verificationKeys (primary + retired)
 *   - getJwks returns all keys with kid/use/alg/kty/n/e set
 */
import { describe, it, expect, vi, beforeAll } from "vitest";
import { generateKeyPairSync } from "node:crypto";

// ── Generate fixed PEM key pairs at module load ─────────────────────────

const pairPrimary = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const pairRetired = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});
const pairAttacker = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const PRIMARY_KID = "kid-primary-test";
const RETIRED_KID = "kid-retired-test";

// ── Resolved in beforeAll after async key import ─────────────────────────

let signAccessToken: typeof import("@/lib/oauth/jwt")["signAccessToken"];
let signIdToken: typeof import("@/lib/oauth/jwt")["signIdToken"];
let verifyAccessToken: typeof import("@/lib/oauth/jwt")["verifyAccessToken"];
let getJwks: typeof import("@/lib/oauth/jwt")["getJwks"];
let ISSUER: string;

beforeAll(async () => {
  const { importPKCS8, importSPKI, exportJWK } = await import("jose");

  const primaryPrivKey = await importPKCS8(pairPrimary.privateKey, "RS256");
  const primaryPubKey = await importSPKI(pairPrimary.publicKey, "RS256");
  const retiredPubKey = await importSPKI(pairRetired.publicKey, "RS256");

  const verificationKeys = new Map<string, unknown>();
  verificationKeys.set(PRIMARY_KID, primaryPubKey);
  verificationKeys.set(RETIRED_KID, retiredPubKey);

  // Build JWKS for both keys (matches what real loadKeys() returns).
  const primaryJwk = await exportJWK(primaryPubKey);
  const retiredJwk = await exportJWK(retiredPubKey);

  vi.doMock("@/lib/oauth/keys", () => ({
    loadKeys: vi.fn().mockResolvedValue({
      primaryKid: PRIMARY_KID,
      signingKey: primaryPrivKey,
      verificationKeys,
      jwks: [
        { ...primaryJwk, kid: PRIMARY_KID, use: "sig", alg: "RS256" },
        { ...retiredJwk, kid: RETIRED_KID, use: "sig", alg: "RS256" },
      ],
      primary: {
        kid: PRIMARY_KID,
        publicKey: pairPrimary.publicKey,
        privateKey: pairPrimary.privateKey,
        createdAt: new Date().toISOString(),
      },
      retired: [
        {
          kid: RETIRED_KID,
          publicKey: pairRetired.publicKey,
          privateKey: pairRetired.privateKey,
          createdAt: new Date().toISOString(),
          retiredAt: new Date(Date.now() + 86400_000).toISOString(),
        },
      ],
    }),
  }));

  const jwtMod = await import("@/lib/oauth/jwt");
  signAccessToken = jwtMod.signAccessToken;
  signIdToken = jwtMod.signIdToken;
  verifyAccessToken = jwtMod.verifyAccessToken;
  getJwks = jwtMod.getJwks;

  const { ISSUER: issuer } = await import("@/lib/oauth/discovery");
  ISSUER = issuer;

  // Pre-resolve the attacker's private key for the rejection test.
  vi.stubGlobal("__attackerPrivKey", await importPKCS8(pairAttacker.privateKey, "RS256"));
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

  it("sets kid in header to the current primaryKid", async () => {
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: 60,
    });
    expect(decodeHeader(token).kid).toBe(PRIMARY_KID);
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

  it("sets kid in header to the current primaryKid", async () => {
    const { token } = await signIdToken({
      sub: "u1",
      clientId: "c1",
      ttlSeconds: 3600,
    });
    expect(decodeHeader(token).kid).toBe(PRIMARY_KID);
  });
});

describe("verifyAccessToken — kid-based lookup (issue #31)", () => {
  it("verifies a token signed with the primary key", async () => {
    const { token } = await signAccessToken({
      sub: "u1",
      clientId: "c1",
      scopes: "openid",
      ttlSeconds: 3600,
    });
    const claims = await verifyAccessToken(token);
    expect(claims.sub).toBe("u1");
  });

  it("verifies a token signed with a RETIRED key (kid lookup)", async () => {
    // Simulate a token issued before a rotation: signed with the retired
    // private key, kid in header = RETIRED_KID.
    const { SignJWT } = await import("jose");
    const retiredPrivKey = await import("@/lib/oauth/keys").then(() => null).catch(() => null);
    // We don't have a direct import path to the retired key, so re-create
    // it from PEM via the same importPKCS8 path the production code uses.
    const { importPKCS8 } = await import("jose");
    const retiredPriv = await importPKCS8(pairRetired.privateKey, "RS256");
    const oldToken = await new SignJWT({
      client_id: "c1",
      scope: "openid",
      jti: "old-jti",
    })
      .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: RETIRED_KID })
      .setIssuer(ISSUER)
      .setSubject("user-from-old-token")
      .setAudience("c1")
      .setJti("old-jti")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
      .sign(retiredPriv);

    const claims = await verifyAccessToken(oldToken);
    expect(claims.sub).toBe("user-from-old-token");
    expect(claims.jti).toBe("old-jti");
    // Suppress unused-var warning from retiredPrivKey alternative path.
    void retiredPrivKey;
  });

  it("rejects a token with an unknown kid", async () => {
    const { SignJWT } = await import("jose");
    const { importPKCS8 } = await import("jose");
    const someKey = await importPKCS8(pairAttacker.privateKey, "RS256");
    const forged = await new SignJWT({ sub: "evil" })
      .setProtectedHeader({
        alg: "RS256",
        typ: "at+jwt",
        kid: "kid-does-not-exist",
      })
      .setIssuer(ISSUER)
      .setAudience("c1")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
      .sign(someKey);

    await expect(verifyAccessToken(forged)).rejects.toThrow(/unknown signing key kid/i);
  });

  it("rejects a token signed with the wrong key but claiming the primary kid", async () => {
    const { SignJWT, importPKCS8 } = await import("jose");
    const attackerKey = await importPKCS8(pairAttacker.privateKey, "RS256");
    const forged = await new SignJWT({ sub: "evil" })
      .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: PRIMARY_KID })
      .setIssuer(ISSUER)
      .setAudience("c1")
      .setIssuedAt()
      .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
      .sign(attackerKey);

    await expect(verifyAccessToken(forged)).rejects.toThrow();
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
    // Both primary + retired are present (no JWKS caching concerns at this layer).
    expect(jwks.keys).toHaveLength(2);
  });

  it("includes primary first, then retired", async () => {
    const jwks = await getJwks();
    expect(jwks.keys[0]?.kid).toBe(PRIMARY_KID);
    expect(jwks.keys[1]?.kid).toBe(RETIRED_KID);
  });

  it("every key has kid, use, alg set", async () => {
    const jwks = await getJwks();
    for (const key of jwks.keys) {
      expect(key.kid).toBeTruthy();
      expect(key.use).toBe("sig");
      expect(key.alg).toBe("RS256");
    }
  });

  it("every key has kty and n/e (RSA public key components)", async () => {
    const jwks = await getJwks();
    for (const key of jwks.keys) {
      expect(key.kty).toBe("RSA");
      expect(typeof key.n).toBe("string");
      expect(key.n!.length).toBeGreaterThan(0);
      expect(typeof key.e).toBe("string");
    }
  });

  it("primary JWKS entry matches the signing public key", async () => {
    const { exportJWK, importSPKI } = await import("jose");
    const jwks = await getJwks();
    const primaryJwksEntry = jwks.keys.find((k) => k.kid === PRIMARY_KID);
    expect(primaryJwksEntry).toBeDefined();
    const expectedJwk = await exportJWK(await importSPKI(pairPrimary.publicKey, "RS256"));
    expect(primaryJwksEntry!.n).toBe(expectedJwk.n);
    expect(primaryJwksEntry!.e).toBe(expectedJwk.e);
  });
});
