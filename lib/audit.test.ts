/**
 * Unit tests for lib/audit.ts. Capture console.log output to verify the
 * structured JSON line shape.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { audit } from "@/lib/audit";

describe("audit", () => {
  let logSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    logSpy = vi.spyOn(console, "log").mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
  });

  it("emits a single JSON line containing ts, actor, action, target", () => {
    audit({
      actor: "env-token",
      action: "admin.sessions.revoke_all",
      target: "user-123",
      metadata: { revoked: 3 },
    });
    expect(logSpy).toHaveBeenCalledTimes(1);
    const line = logSpy.mock.calls[0]![0] as string;
    const parsed = JSON.parse(line) as {
      audit: {
        ts: string;
        actor: string;
        action: string;
        target: string;
        metadata?: Record<string, unknown>;
      };
    };
    expect(parsed.audit.actor).toBe("env-token");
    expect(parsed.audit.action).toBe("admin.sessions.revoke_all");
    expect(parsed.audit.target).toBe("user-123");
    expect(parsed.audit.metadata).toEqual({ revoked: 3 });
    // ISO 8601 with Z suffix
    expect(parsed.audit.ts).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
  });

  it("omits metadata key entirely when not provided", () => {
    audit({ actor: "admin", action: "test", target: "x" });
    const line = logSpy.mock.calls[0]![0] as string;
    const parsed = JSON.parse(line) as { audit: Record<string, unknown> };
    expect("metadata" in parsed.audit).toBe(false);
  });

  it("includes metadata when provided", () => {
    audit({
      actor: "admin",
      action: "test",
      target: "x",
      metadata: { a: 1, b: "two" },
    });
    const line = logSpy.mock.calls[0]![0] as string;
    const parsed = JSON.parse(line) as { audit: { metadata?: unknown } };
    expect(parsed.audit.metadata).toEqual({ a: 1, b: "two" });
  });

  it("never throws on primitive metadata values", () => {
    expect(() =>
      audit({
        actor: "x",
        action: "x",
        target: "x",
        metadata: { count: 0, ok: true, name: null, list: [1, 2] },
      }),
    ).not.toThrow();
  });
});
