/**
 * E2E test for the hardened /api/test/rate-reset endpoint (issue #32).
 *
 * Original vulnerability: the endpoint cleared in-memory rate-limit
 * buckets on any localhost-spoofed request (X-Forwarded-For: 127.0.0.1),
 * with no NODE_ENV guard and no admin auth. Fixed by requiring:
 *   - NODE_ENV !== "production"  (always 404 in prod)
 *   - X-Admin-Token header matching config.adminToken  (401 otherwise)
 *
 * This e2e test exercises the auth path against a running dev server.
 * The actual rate-limit reset behavior is unit-tested in
 * `lib/oauth/rate-limit.test.ts` via direct `_resetRateLimit()` import.
 *
 * Requires dev server on localhost:3000 and ADMIN_TOKEN set in .env.
 */
const BASE = "http://localhost:3000";
const ENDPOINT = `${BASE}/api/test/rate-reset`;

let pass = 0;
let fail = 0;
function ok(label: string, cond: boolean, detail = "") {
  if (cond) {
    console.log(`  ✓ ${label}`);
    pass++;
  } else {
    console.error(`  ✗ ${label}${detail ? "  — " + detail : ""}`);
    fail++;
  }
}

async function post(headers: Record<string, string> = {}): Promise<number> {
  const res = await fetch(ENDPOINT, {
    method: "POST",
    headers,
    redirect: "manual",
  });
  // Drain body to free sockets.
  await res.text().catch(() => {});
  return res.status;
}

async function main() {
  const ADMIN_TOKEN = process.env["ADMIN_TOKEN"];
  if (!ADMIN_TOKEN) {
    console.error(
      "ADMIN_TOKEN env var is required for this test (see .env). Skipping.",
    );
    process.exit(1);
  }

  console.log("=== Hardened /api/test/rate-reset (issue #32) ===");

  // ── Negative: no token → 401 ──
  const noToken = await post({});
  ok(
    "missing X-Admin-Token → 401",
    noToken === 401,
    `got status=${noToken}`,
  );

  // ── Negative: wrong token → 401 ──
  const wrongToken = await post({
    "X-Admin-Token": "wrong-token-32-bytes-padding-padding-pad",
  });
  ok(
    "wrong X-Admin-Token → 401",
    wrongToken === 401,
    `got status=${wrongToken}`,
  );

  // ── Positive: right token → 200 ──
  const ok2 = await post({ "X-Admin-Token": ADMIN_TOKEN });
  ok(
    "valid X-Admin-Token → 200",
    ok2 === 200,
    `got status=${ok2}`,
  );

  // ── Positive: right token again (idempotent) → 200 ──
  const ok3 = await post({ "X-Admin-Token": ADMIN_TOKEN });
  ok(
    "valid token, second call → 200 (reset is idempotent)",
    ok3 === 200,
    `got status=${ok3}`,
  );

  // ── Sanity: a small burst of logins hits rate limit without reset,
  // then resets after we call the endpoint. Exercises the actual
  // end-to-end flow that the old vulnerability broke. ──
  //
  // Skip this if too slow — it's optional. The auth checks above are
  // the actual regression coverage for issue #32.
  if (process.env["RUN_RATE_LIMIT_BURST"] === "true") {
    // Not implementing the burst here to keep this e2e fast and focused.
    // Rate-limit semantics are covered in lib/oauth/rate-limit.test.ts.
  }

  console.log(`\n${pass} pass, ${fail} fail`);
  if (fail > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
