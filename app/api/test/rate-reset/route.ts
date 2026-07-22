/**
 * POST /api/test/rate-reset — resets the in-memory rate-limit buckets.
 *
 * **Hardened** (issue #32):
 *
 * 1. **NODE_ENV guard**: in production this endpoint always returns 404,
 *    regardless of other auth state. The "test tooling shouldn't ship"
 *    contract is enforced at the application layer instead of relying on
 *    deployment config alone. README still recommends blocking at the
 *    reverse-proxy layer as belt-and-suspenders.
 *
 * 2. **ADMIN_TOKEN**: reuses the same bearer-token scheme as `/admin/*`
 *    (Phase 2 of issue #30). `X-Admin-Token: $ADMIN_TOKEN` header must
 *    match the configured token. Missing → 401, wrong → 401. When
 *    `ADMIN_TOKEN` is unset entirely → 503 (feature disabled).
 *
 * Why we don't move this to a CLI script:
 *
 *   Playwright (`e2e/playwright/full-flow.spec.ts`) calls this endpoint
 *   to reset rate-limit buckets in the running dev server before each
 *   test. The buckets live in the dev-server process's `globalThis`, so
 *   a CLI script running in a separate Node process can't reach them.
 *   Keeping the HTTP endpoint (auth-hardened) is the only way to expose
 *   this to Playwright without restarting the dev server per test.
 *
 * Operators who want a CLI alternative can use:
 *
 *   # One-shot, calls the same function the HTTP route calls:
 *   npx tsx -e "import { _resetRateLimit } from './lib/oauth/rate-limit'; _resetRateLimit()"
 */
import { NextResponse } from "next/server";
import { _resetRateLimit } from "@/lib/oauth/rate-limit";
import {
  checkAdminToken,
  adminAuthErrorResponse,
} from "@/lib/oauth/admin-auth";

export async function POST(req: Request) {
  // Hard guard #1: production deployments never expose this, period.
  // README still recommends reverse-proxy blocking as defense-in-depth.
  if (process.env["NODE_ENV"] === "production") {
    return new NextResponse(null, { status: 404 });
  }

  // Hard guard #2: ADMIN_TOKEN must be present and match the header.
  const auth = checkAdminToken(req);
  const err = adminAuthErrorResponse(auth);
  if (err) return err;

  _resetRateLimit();
  return NextResponse.json({ ok: true });
}
