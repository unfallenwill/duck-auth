/**
 * Unit tests for lib/oauth/crypto.ts.
 */
import { describe, it, expect } from "vitest";
import {
  hashPassword,
  verifyPassword,
  hashClientSecret,
  verifyClientSecret,
  randomToken,
  uuid,
  verifyPkceS256,
  generateCodeVerifier,
  codeChallengeS256,
} from "@/lib/oauth/crypto";

describe("hashPassword / verifyPassword", () => {
  it("hashes a password and verifies it back", () => {
    const hash = hashPassword("correct horse battery staple");
    expect(hash).toMatch(/^scrypt\$\d+\$\d+\$\d+\$[0-9a-f]+\$[0-9a-f]+$/);
    expect(verifyPassword("correct horse battery staple", hash)).toBe(true);
  });

  it("rejects wrong password", () => {
    const hash = hashPassword("right");
    expect(verifyPassword("wrong", hash)).toBe(false);
  });

  it("returns false for malformed stored hash", () => {
    expect(verifyPassword("x", "garbage")).toBe(false);
    // 6 segments but salt/hash too short to derive a 64-byte key
    expect(verifyPassword("x", "scrypt$16384$8$1$aaaa$bbbb")).toBe(false);
    // empty hash segment is caught by falsy guard
    expect(verifyPassword("x", "scrypt$16384$8$1$$")).toBe(false);
  });

  it("uses different salts each time (no deterministic output)", () => {
    const a = hashPassword("same");
    const b = hashPassword("same");
    expect(a).not.toBe(b);
    // Both still verify the password:
    expect(verifyPassword("same", a)).toBe(true);
    expect(verifyPassword("same", b)).toBe(true);
  });
});

describe("hashClientSecret / verifyClientSecret", () => {
  it("delegates to password hash (current implementation)", () => {
    const secret = "demo-secret-change-me";
    const hash = hashClientSecret(secret);
    expect(hash).toMatch(/^scrypt\$/);
    expect(verifyClientSecret(secret, hash)).toBe(true);
    expect(verifyClientSecret("wrong", hash)).toBe(false);
  });
});

describe("randomToken", () => {
  it("returns base64url-safe string of expected length", () => {
    const t = randomToken(32);
    expect(t).toMatch(/^[A-Za-z0-9_-]+$/);
    // 32 bytes → 43 base64url chars (no padding)
    expect(t.length).toBe(43);
  });

  it("produces different values on each call", () => {
    const a = randomToken(32);
    const b = randomToken(32);
    expect(a).not.toBe(b);
  });

  it("rejects non-base64url characters", () => {
    for (let i = 0; i < 10; i++) {
      const t = randomToken(32);
      expect(t).not.toMatch(/[+/=]/);
    }
  });
});

describe("uuid", () => {
  it("returns a valid v4 UUID string", () => {
    const id = uuid();
    expect(id).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
    );
  });

  it("returns unique values", () => {
    const set = new Set(Array.from({ length: 100 }, () => uuid()));
    expect(set.size).toBe(100);
  });
});

describe("PKCE (S256 only)", () => {
  it("verifies a matching verifier + challenge pair", () => {
    const verifier = generateCodeVerifier();
    const challenge = codeChallengeS256(verifier);
    expect(verifyPkceS256(verifier, challenge)).toBe(true);
  });

  it("rejects a wrong verifier", () => {
    const verifier = generateCodeVerifier();
    const challenge = codeChallengeS256(verifier);
    expect(verifyPkceS256(generateCodeVerifier(), challenge)).toBe(false);
  });

  it("verifier length is 43 chars (32 bytes base64url)", () => {
    const v = generateCodeVerifier();
    expect(v.length).toBe(43);
  });

  it("verifier chars are in RFC 7636 alphabet", () => {
    // 43 chars is the minimum from 32 bytes. All should be in [A-Z][a-z][0-9]-._~
    const v = generateCodeVerifier(96); // 128 chars max
    expect(v).toMatch(/^[A-Za-z0-9\-._~]+$/);
    expect(v.length).toBeGreaterThanOrEqual(43);
    expect(v.length).toBeLessThanOrEqual(128);
  });
});