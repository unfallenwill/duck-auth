/**
 * Unit tests for lib/oauth/cookies.ts.
 *
 * Strategy: mock @/lib/oauth/discovery so ISSUER is deterministic.
 */
import { describe, it, expect, vi } from "vitest";

// We need to test both https and http ISSUER, so we use vi.hoisted
// to control the value. We'll mock with https first and re-mock for http test.
vi.mock("@/lib/oauth/discovery", () => ({
  get ISSUER() {
    return currentIssuer;
  },
}));

// Mutable issuer value — tests can change it.
let currentIssuer = "https://auth.example.com";

// Import AFTER mock.
import { secureCookie, cookieDefaults } from "@/lib/oauth/cookies";

describe("secureCookie", () => {
  it("returns true when ISSUER is https", () => {
    currentIssuer = "https://auth.example.com";
    expect(secureCookie()).toBe(true);
  });

  it("returns false when ISSUER is http", () => {
    currentIssuer = "http://localhost:3000";
    expect(secureCookie()).toBe(false);
  });
});

describe("cookieDefaults", () => {
  it("returns httpOnly, sameSite=lax, secure, and path=/", () => {
    currentIssuer = "https://auth.example.com";
    const defaults = cookieDefaults();
    expect(defaults.httpOnly).toBe(true);
    expect(defaults.sameSite).toBe("lax");
    expect(defaults.secure).toBe(true);
    expect(defaults.path).toBe("/");
  });

  it("secure is false for http issuer", () => {
    currentIssuer = "http://localhost:3000";
    const defaults = cookieDefaults();
    expect(defaults.secure).toBe(false);
    // Other fields still the same.
    expect(defaults.httpOnly).toBe(true);
    expect(defaults.sameSite).toBe("lax");
    expect(defaults.path).toBe("/");
  });
});
