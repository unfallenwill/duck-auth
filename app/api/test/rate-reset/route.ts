/**
 * POST /api/test/rate-reset — resets the in-memory rate-limit buckets.
 *
 * Unguarded on purpose: tests need to use this against a production-built
 * server (`npm run build && npm start`). For real production deployment,
 * block this path at the reverse-proxy / firewall layer. The endpoint
 * only clears local rate-limit counters — it does not leak data.
 */
import { NextResponse } from "next/server";
import { _resetRateLimit } from "@/lib/oauth/rate-limit";

export async function POST() {
  _resetRateLimit();
  return NextResponse.json({ ok: true });
}