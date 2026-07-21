/**
 * Unit tests for lib/oauth/session.ts.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

vi.mock("@/lib/config", () => ({
  config: { sessionSecret: "test-secret-32-bytes-please-please!!" },
  SESSION_COOKIE_DEV_FALLBACK: "test-secret-32-bytes-please-please!!",
}));

import { signSessionCookie, verifySessionCookie } from "@/lib/oauth/session";

describe("signSessionCookie / verifySessionCookie", () => {
  it("round-trips a valid session", async () => {
    const { value } = await signSessionCookie("user-123");
    const session = await verifySessionCookie(value);
    expect(session).toEqual({ uid: "user-123" });
  });

  it("produces different cookies for different users", async () => {
    const a = await signSessionCookie("alice");
    const b = await signSessionCookie("bob");
    expect(a.value).not.toBe(b.value);
  });

  it("returns null for garbage input", async () => {
    expect(await verifySessionCookie("not-a-jwt")).toBeNull();
  });

  it("returns null for empty string", async () => {
    expect(await verifySessionCookie("")).toBeNull();
  });

  it("returns null for JWT without uid claim", async () => {
    // Sign a JWT with the right secret but no uid
    const { SignJWT } = await import("jose");
    const secret = new TextEncoder().encode("test-secret-32-bytes-please-please!!");
    const token = await new SignJWT({ foo: "bar" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(secret);
    expect(await verifySessionCookie(token)).toBeNull();
  });

  it("returns null for JWT signed with wrong secret", async () => {
    const { SignJWT } = await import("jose");
    const wrongSecret = new TextEncoder().encode("wrong-secret-32-bytes-here-here!!");
    const token = await new SignJWT({ uid: "evil" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(wrongSecret);
    expect(await verifySessionCookie(token)).toBeNull();
  });

  it("default TTL is 2 hours", async () => {
    const now = Date.now();
    const { expiresAt } = await signSessionCookie("u1");
    const ttl = (expiresAt.getTime() - now) / 1000;
    expect(ttl).toBeGreaterThan(7190);
    expect(ttl).toBeLessThan(7210);
  });
});