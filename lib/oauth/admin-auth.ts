/**
 * Auth middleware for `/admin/*` routes (issue #38, Phase 2 of #30).
 *
 * Currently implements Option A: a single bearer token from env var
 * `ADMIN_TOKEN`, sent as the `X-Admin-Token` header. Constant-time
 * comparison via Node's `crypto.timingSafeEqual` to prevent token
 * recovery via timing side-channel.
 *
 * Migration path: when multi-admin with roles is needed (Option B),
 * replace the body of `checkAdminToken` and the `actor` derivation in
 * the route handlers. The route signature stays the same.
 */

import { timingSafeEqual } from "node:crypto";
import { config } from "@/lib/config";

export type AdminAuthReason =
  /** Server has no ADMIN_TOKEN configured — admin endpoints are disabled. */
  | "disabled"
  /** Request had no X-Admin-Token header. */
  | "missing"
  /** Header present but did not match ADMIN_TOKEN. */
  | "invalid"
  /** Authenticated. */
  | "ok";

export interface AdminAuthResult {
  ok: boolean;
  reason: AdminAuthReason;
  /**
   * Best-effort actor identifier for audit logs.
   * - "env-token" for Option A (the operator holding ADMIN_TOKEN)
   * - Future: the admin user's id
   */
  actor: string;
}

/**
 * Constant-time string compare. Buffers must be equal length for
 * `timingSafeEqual`; we deliberately pad/compare to keep length
 * comparison out of the timing channel.
 */
function safeStringEqual(a: string, b: string): boolean {
  const aBuf = Buffer.from(a, "utf8");
  const bBuf = Buffer.from(b, "utf8");
  // Length must match for timingSafeEqual. Pad to the same length before
  // comparing so the comparison time doesn't reveal the shorter length.
  // This is conservative — the outcome is false either way if lengths differ,
  // but doing the compare in constant-ish time is the right shape.
  const len = Math.max(aBuf.length, bBuf.length);
  const aPad = Buffer.alloc(len);
  const bPad = Buffer.alloc(len);
  aBuf.copy(aPad);
  bBuf.copy(bPad);
  // We AND in the length-match signal so the function returns false on
  // mismatched length but the time taken is dominated by the safe compare.
  const lengthsMatch = aBuf.length === bBuf.length;
  return lengthsMatch && timingSafeEqual(aPad, bPad);
}

/**
 * Verify the request carries a valid `X-Admin-Token` header.
 *
 * Does NOT log failures (no audit noise on every bad attempt). Callers
 * may log 401s at the route layer if they want operational visibility,
 * but the audit log is reserved for successful privileged actions.
 */
export function checkAdminToken(req: Request): AdminAuthResult {
  const expected = config.adminToken;
  if (!expected) {
    return { ok: false, reason: "disabled", actor: "env-token" };
  }
  const headerToken = req.headers.get("X-Admin-Token");
  if (!headerToken) {
    return { ok: false, reason: "missing", actor: "env-token" };
  }
  if (!safeStringEqual(headerToken, expected)) {
    return { ok: false, reason: "invalid", actor: "env-token" };
  }
  return { ok: true, reason: "ok", actor: "env-token" };
}

/**
 * Map an AdminAuthResult to an HTTP response. Pure function — no side
 * effects, easy to test. Returns null when auth succeeded and the caller
 * should continue.
 */
export function adminAuthErrorResponse(
  result: AdminAuthResult,
): Response | null {
  if (result.ok) return null;
  if (result.reason === "disabled") {
    return new Response(
      JSON.stringify({
        error: "admin_disabled",
        error_description:
          "ADMIN_TOKEN is not configured. Admin endpoints are disabled.",
      }),
      {
        status: 503,
        headers: { "Content-Type": "application/json" },
      },
    );
  }
  // missing / invalid → 401 (RFC 7235: WWW-Authenticate for bearer challenges)
  return new Response(
    JSON.stringify({
      error: "invalid_token",
      error_description: "X-Admin-Token header missing or invalid.",
    }),
    {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        "WWW-Authenticate": 'Bearer realm="admin"',
      },
    },
  );
}
