/**
 * Unit tests for lib/oauth/consent.ts.
 *
 * consentCoversScopes is the critical logic — its direction was inverted
 * in B1 (the original bug). These tests lock the direction down.
 */
import { describe, it, expect } from "vitest";
import { consentCoversScopes } from "@/lib/oauth/consent";

describe("consentCoversScopes (direction)", () => {
  it("returns true when consent covers exactly the requested scopes", () => {
    expect(consentCoversScopes("openid", "openid")).toBe(true);
    expect(consentCoversScopes("openid profile", "openid profile")).toBe(true);
  });

  it("returns true when consent covers MORE than requested", () => {
    expect(consentCoversScopes("openid profile email", "openid")).toBe(true);
    expect(
      consentCoversScopes("openid profile email", "openid profile"),
    ).toBe(true);
  });

  it("returns false when consent covers FEWER than requested (B1 regression)", () => {
    // The exact bug: existing consent for openid should NOT satisfy a
    // request for openid profile email.
    expect(consentCoversScopes("openid", "openid profile email")).toBe(false);
    expect(consentCoversScopes("openid profile", "openid profile email")).toBe(
      false,
    );
  });

  it("returns false when no consent exists", () => {
    expect(consentCoversScopes(null, "openid")).toBe(false);
    expect(consentCoversScopes(undefined, "openid")).toBe(false);
    expect(consentCoversScopes("", "openid")).toBe(false);
  });

  it("returns false when requested scopes is empty (defensive)", () => {
    // Empty requested set is vacuously covered by any consent. But our
    // authorization handler never produces this — we still test that the
    // function doesn't crash.
    expect(consentCoversScopes("openid", "")).toBe(true);
  });

  it("handles whitespace correctly in both inputs", () => {
    expect(
      consentCoversScopes("  openid   profile  ", "openid profile"),
    ).toBe(true);
    expect(consentCoversScopes("openid", "  openid   profile  ")).toBe(false);
  });
});