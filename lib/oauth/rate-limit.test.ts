/**
 * Unit tests for lib/oauth/rate-limit.ts.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { tokenRateLimit, revokeRateLimit, _resetRateLimit } from "@/lib/oauth/rate-limit";

function makeReq(ip: string, headers: Record<string, string> = {}): Request {
  return new Request("http://x/test", {
    headers: { "x-forwarded-for": ip, ...headers },
  });
}

function makeForm(data: Record<string, string>): URLSearchParams {
  return new URLSearchParams(data);
}

describe("tokenRateLimit", () => {
  beforeEach(() => _resetRateLimit());

  it("allows capacity requests before blocking", () => {
    const req = makeReq("1.2.3.4");
    const form = makeForm({ client_id: "alice" });
    for (let i = 0; i < 20; i++) {
      expect(tokenRateLimit(req, form)).toBe(true);
    }
  });

  it("blocks once bucket is empty", () => {
    const req = makeReq("1.2.3.4");
    const form = makeForm({ client_id: "alice" });
    for (let i = 0; i < 20; i++) {
      tokenRateLimit(req, form);
    }
    expect(tokenRateLimit(req, form)).toBe(false);
  });

  it("isolates buckets per (ip, client_id) tuple", () => {
    const req1 = makeReq("1.2.3.4");
    const req2 = makeReq("5.6.7.8");
    const formA = makeForm({ client_id: "alice" });
    const formB = makeForm({ client_id: "bob" });

    for (let i = 0; i < 20; i++) tokenRateLimit(req1, formA);
    expect(tokenRateLimit(req1, formA)).toBe(false);

    // Different IP — fresh bucket
    expect(tokenRateLimit(req2, formA)).toBe(true);
    // Different client — fresh bucket (same IP)
    expect(tokenRateLimit(req1, formB)).toBe(true);
  });

  it("refills tokens over time", () => {
    vi.useFakeTimers();
    try {
      const req = makeReq("1.2.3.4");
      const form = makeForm({ client_id: "alice" });
      for (let i = 0; i < 20; i++) tokenRateLimit(req, form);
      expect(tokenRateLimit(req, form)).toBe(false);

      // Advance 60 seconds → bucket should be fully refilled
      // (refill rate is 20 tokens / 60_000 ms = 0.000333 per ms,
      //  so 60000ms × 0.000333 = 20 tokens)
      vi.advanceTimersByTime(60_000);
      expect(tokenRateLimit(req, form)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });

  it("falls back to 'unknown' ip when no x-forwarded-for", () => {
    const req = new Request("http://x/test");
    const form = makeForm({ client_id: "alice" });
    // Should not throw and should allow requests
    expect(tokenRateLimit(req, form)).toBe(true);
  });
});

describe("revokeRateLimit", () => {
  beforeEach(() => _resetRateLimit());

  it("has higher capacity than token (30 vs 20)", () => {
    const req = makeReq("1.2.3.4");
    for (let i = 0; i < 30; i++) {
      expect(revokeRateLimit(req)).toBe(true);
    }
    expect(revokeRateLimit(req)).toBe(false);
  });

  it("uses ip only, not client_id", () => {
    const req1 = makeReq("1.2.3.4");
    const req2 = makeReq("1.2.3.4"); // same ip
    for (let i = 0; i < 30; i++) revokeRateLimit(req1);
    expect(revokeRateLimit(req2)).toBe(false); // shared bucket
  });
});