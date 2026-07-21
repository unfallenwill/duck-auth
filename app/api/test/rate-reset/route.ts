/**
 * POST /api/test/rate-reset — resets the in-memory rate-limit buckets.
 *
 * **Guarded**: only responds when ALL of the following are true:
 *   1. `NODE_ENV !== "production"` — never available in production builds
 *   2. Request comes from localhost (127.0.0.1, ::1, or IPv4-mapped IPv6)
 *
 * In production this endpoint returns 404, giving no indication it exists.
 * For defense-in-depth, also block this path at the reverse-proxy layer.
 */
import { NextResponse } from "next/server";
import { _resetRateLimit } from "@/lib/oauth/rate-limit";

const LOCALHOST_IPS = new Set([
  "127.0.0.1",
  "::1",
  "::ffff:127.0.0.1",
  "localhost",
]);

export async function POST(req: Request) {
  // Guard: only allow localhost callers. In a real production deployment
  // this endpoint should also be blocked at the reverse-proxy layer.
  const ip =
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    req.headers.get("x-real-ip") ||
    "";

  if (!LOCALHOST_IPS.has(ip)) {
    return new NextResponse(null, { status: 404 });
  }

  _resetRateLimit();
  return NextResponse.json({ ok: true });
}