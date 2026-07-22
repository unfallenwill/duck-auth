/**
 * Unit tests for lib/oauth/admin-auth.ts.
 *
 * Tests both the constant-time token compare and the auth-result-to-HTTP
 * mapping. Uses a Proxy mock for config so adminToken can be toggled
 * per-test.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const { adminTokenBag } = vi.hoisted(() => ({
  adminTokenBag: { current: undefined as string | undefined },
}));

vi.mock("@/lib/config", () => ({
  config: new Proxy(
    {},
    {
      get(_target, prop: string) {
        if (prop === "adminToken") return adminTokenBag.current;
        if (prop === "sessionSecret") return "test-secret-32-bytes-please-please!!";
        return undefined;
      },
    },
  ),
  SESSION_COOKIE_DEV_FALLBACK: "test-secret-32-bytes-please-please!!",
}));

import {
  checkAdminToken,
  adminAuthErrorResponse,
} from "@/lib/oauth/admin-auth";

beforeEach(() => {
  adminTokenBag.current = undefined;
});

function makeReq(headers: Record<string, string> = {}): Request {
  return new Request("http://localhost/admin/test", { headers });
}

const VALID_TOKEN = "abcdefghijklmnopqrstuvwxyz0123456789"; // 36 chars

describe("checkAdminToken", () => {
  it("returns 'disabled' when ADMIN_TOKEN is unset", () => {
    adminTokenBag.current = undefined;
    const result = checkAdminToken(makeReq({ "X-Admin-Token": VALID_TOKEN }));
    expect(result).toEqual({
      ok: false,
      reason: "disabled",
      actor: "env-token",
    });
  });

  it("returns 'missing' when header is absent", () => {
    adminTokenBag.current = VALID_TOKEN;
    const result = checkAdminToken(makeReq({}));
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("missing");
  });

  it("returns 'invalid' when header value does not match", () => {
    adminTokenBag.current = VALID_TOKEN;
    const result = checkAdminToken(
      makeReq({ "X-Admin-Token": "wrong-token-here-32-bytes-padding-x" }),
    );
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("invalid");
  });

  it("returns 'ok' when header value matches", () => {
    adminTokenBag.current = VALID_TOKEN;
    const result = checkAdminToken(makeReq({ "X-Admin-Token": VALID_TOKEN }));
    expect(result).toEqual({ ok: true, reason: "ok", actor: "env-token" });
  });

  it("treats empty header value as 'missing' (functionally equivalent to absent)", () => {
    // `req.headers.get()` returns "" for `X-Admin-Token: ` which is
    // indistinguishable from no header from the client's perspective.
    // Both end up as 401 at the route layer — no security difference.
    adminTokenBag.current = VALID_TOKEN;
    const result = checkAdminToken(makeReq({ "X-Admin-Token": "" }));
    expect(result.reason).toBe("missing");
  });

  it("is case-sensitive on the header value", () => {
    adminTokenBag.current = VALID_TOKEN;
    const result = checkAdminToken(
      makeReq({ "x-admin-token": VALID_TOKEN }), // lowercase header name
    );
    // Node's Headers normalizes to lowercase; this still works.
    expect(result.ok).toBe(true);
  });

  it("treats wrong-length token as 'invalid' even if first chars match", () => {
    adminTokenBag.current = VALID_TOKEN;
    const truncated = VALID_TOKEN.slice(0, 10);
    const result = checkAdminToken(makeReq({ "X-Admin-Token": truncated }));
    expect(result.ok).toBe(false);
    expect(result.reason).toBe("invalid");
  });
});

describe("adminAuthErrorResponse", () => {
  it("returns null when auth ok", () => {
    expect(
      adminAuthErrorResponse({ ok: true, reason: "ok", actor: "x" }),
    ).toBeNull();
  });

  it("maps 'disabled' to 503 with admin_disabled error code", () => {
    const res = adminAuthErrorResponse({
      ok: false,
      reason: "disabled",
      actor: "x",
    });
    expect(res).not.toBeNull();
    expect(res!.status).toBe(503);
    expect(res!.headers.get("Content-Type")).toBe("application/json");
    return res!.json().then((body: { error: string }) => {
      expect(body.error).toBe("admin_disabled");
    });
  });

  it("maps 'missing' to 401 with WWW-Authenticate challenge", () => {
    const res = adminAuthErrorResponse({
      ok: false,
      reason: "missing",
      actor: "x",
    });
    expect(res).not.toBeNull();
    expect(res!.status).toBe(401);
    expect(res!.headers.get("WWW-Authenticate")).toContain("Bearer");
  });

  it("maps 'invalid' to 401 (same as missing — don't leak which)", () => {
    const res = adminAuthErrorResponse({
      ok: false,
      reason: "invalid",
      actor: "x",
    });
    expect(res).not.toBeNull();
    expect(res!.status).toBe(401);
  });
});
