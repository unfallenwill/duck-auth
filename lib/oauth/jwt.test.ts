/**
 * Unit tests for lib/oauth/jwt.ts.
 * keys.ts is mocked with an in-memory RSA key pair.
 */
import { describe, it, expect, vi } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import { importPKCS8, importSPKI, decodeJwt, decodeProtectedHeader } from "jose";

const { publicKey: pubPem, privateKey: privPem } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const { publicKey: otherPub, privateKey: otherPriv } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const hoisted = vi.hoisted(() => ({ keysReady: false as boolean }));

vi.mock("@/lib/oauth/keys", () => ({
  KID: "key-1",
  loadKeys: vi.fn().mockImplementation(async () => {
    return {
      privateKey: await importPKCS8(privPem, "RS256"),
      publicKey: await importSPKI(pubPem, "RS256"),
    };
  }),
}));

vi.mock("@/lib/oauth/discovery", () => ({ ISSUER: "http://test-issuer" }));

import { signAccessToken, signIdToken, verifyAccessToken, getJwks } from "@/lib/oauth/jwt";

describe("signAccessToken / verifyAccessToken", () => {
  it("round-trips a valid token", async () => {
    const { token } = await signAccessToken({
      sub: "user-1", clientId: "client-1", scopes: "openid profile", ttlSeconds: 3600,
    });
    const claims = await verifyAccessToken(token);
    expect(claims.sub).toBe("user-1");
    expect(claims.aud).toBe("client-1");
    expect(claims.scope).toBe("openid profile");
    expect(claims.iss).toBe("http://test-issuer");
  });

  it("sets typ=at+jwt and kid", async () => {
    const { token } = await signAccessToken({
      sub: "u", clientId: "c", scopes: "openid", ttlSeconds: 60,
    });
    const h = decodeProtectedHeader(token);
    expect(h.typ).toBe("at+jwt");
    expect(h.kid).toBe("key-1");
  });

  it("includes jti in claims", async () => {
    const { token, jti } = await signAccessToken({
      sub: "u", clientId: "c", scopes: "openid", ttlSeconds: 60,
    });
    expect(decodeJwt(token).jti).toBe(jti);
  });

  it("rejects tampered token", async () => {
    const { token } = await signAccessToken({
      sub: "u", clientId: "c", scopes: "openid", ttlSeconds: 60,
    });
    await expect(verifyAccessToken(token.slice(0, -5) + "XXXXX")).rejects.toThrow();
  });
});

describe("signIdToken", () => {
  it("sets typ=JWT and aud=clientId", async () => {
    const { token } = await signIdToken({
      sub: "u", email: "a@b.c", clientId: "my-client", ttlSeconds: 60,
    });
    const h = decodeProtectedHeader(token);
    const c = decodeJwt(token);
    expect(h.typ).toBe("JWT");
    expect(c.aud).toBe("my-client");
  });

  it("includes email and name when provided", async () => {
    const { token } = await signIdToken({
      sub: "u", email: "a@b.c", name: "Alice", clientId: "c", ttlSeconds: 60,
    });
    const c = decodeJwt(token);
    expect(c.email).toBe("a@b.c");
    expect(c.name).toBe("Alice");
  });

  it("omits name when not provided", async () => {
    const { token } = await signIdToken({
      sub: "u", email: "a@b.c", clientId: "c", ttlSeconds: 60,
    });
    expect(decodeJwt(token).name).toBeUndefined();
  });
});

describe("getJwks", () => {
  it("returns key array with metadata", async () => {
    const jwks = await getJwks();
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0].kid).toBe("key-1");
    expect(jwks.keys[0].use).toBe("sig");
    expect(jwks.keys[0].alg).toBe("RS256");
  });
});