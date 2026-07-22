/**
 * Admin force-logout e2e test (issue #38, Phase 2 of #30).
 *
 * Proves the end-to-end flow:
 *   1. Create a real Session row + JWT cookie for alice (via createSessionCookie).
 *   2. Confirm /oauth/authorize accepts it (302 to callback with code).
 *   3. Call POST /admin/users/:id/sessions/revoke-all with valid X-Admin-Token.
 *   4. Same cookie value must now fail /oauth/authorize (302 to /login).
 *   5. Call GET /admin/users/:id/sessions — must return empty list after revoke.
 *   6. Call POST /admin/users/:id/tokens/revoke-all — must succeed.
 *   7. Negative cases:
 *      - 401 when X-Admin-Token header is missing
 *      - 401 when token is wrong
 *      - 404 when target userId does not exist
 *
 * Requires the dev server running on localhost:3000 and ADMIN_TOKEN set
 * in the environment (see .env). Server picks it up via Next.js dotenv.
 */
import { PrismaClient } from "../lib/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { createHash, randomBytes } from "node:crypto";
import { createSessionCookie } from "./lib/session-cookie";

const BASE = "http://localhost:3000";
const REDIRECT_URI = "http://localhost:3000/api/auth/callback";
const SCOPES = "openid profile email";

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

function codeVerifier(): string {
  return randomBytes(32).toString("base64url");
}
function codeChallenge(v: string): string {
  return createHash("sha256").update(v).digest("base64url");
}

async function authorizeWithCookie(
  cookie: string,
): Promise<{ status: number; location: string | null }> {
  const u = new URL(`${BASE}/oauth/authorize`);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", "demo-client");
  u.searchParams.set("redirect_uri", REDIRECT_URI);
  u.searchParams.set("scope", SCOPES);
  u.searchParams.set("state", "admin-revoke-test");
  u.searchParams.set("code_challenge", codeChallenge(codeVerifier()));
  u.searchParams.set("code_challenge_method", "S256");

  const res = await fetch(u, {
    headers: { Cookie: `oauth_session=${cookie}` },
    redirect: "manual",
  });
  return { status: res.status, location: res.headers.get("location") };
}

async function adminCall(
  method: "GET" | "POST",
  path: string,
  opts: { token?: string | null } = {},
): Promise<{ status: number; body: unknown }> {
  const headers: Record<string, string> = {};
  if (opts.token !== null && opts.token !== undefined) {
    headers["X-Admin-Token"] = opts.token;
  }
  const res = await fetch(`${BASE}${path}`, {
    method,
    headers,
    redirect: "manual",
  });
  let body: unknown = null;
  const ct = res.headers.get("Content-Type") ?? "";
  if (ct.includes("application/json")) {
    body = await res.json().catch(() => null);
  }
  return { status: res.status, body };
}

async function main() {
  const ADMIN_TOKEN = process.env["ADMIN_TOKEN"];
  if (!ADMIN_TOKEN) {
    console.error(
      "ADMIN_TOKEN env var is required for this test (see .env). Skipping.",
    );
    process.exit(1);
  }

  const prisma = new PrismaClient({
    adapter: new PrismaLibSql({
      url: process.env["DATABASE_URL"] ?? "file:./dev.db",
    }),
  });
  const alice = await prisma.user.findUnique({
    where: { email: "alice@example.com" },
  });
  if (!alice) {
    console.error("Seed alice missing — run npm run db:seed");
    process.exit(1);
  }

  console.log("=== Admin Force-Logout (issue #38 Phase 2) ===");

  // ── Happy path: sessions/revoke-all ──

  // Capture current session count BEFORE issuing ours — the test must not
  // depend on DB state from previous runs.
  const sessionsBefore = await prisma.session.count({
    where: { userId: alice.id, revokedAt: null },
  });

  const cookie1 = await createSessionCookie(alice.id);
  const before1 = await authorizeWithCookie(cookie1);
  ok(
    "step 1: valid cookie → 302 to callback with code",
    before1.status === 302 &&
      before1.location?.includes("/api/auth/callback") === true,
    `got status=${before1.status} location=${before1.location}`,
  );

  const revokeSessions = await adminCall(
    "POST",
    `/admin/users/${alice.id}/sessions/revoke-all`,
    { token: ADMIN_TOKEN },
  );
  ok(
    "step 2: POST /admin/.../sessions/revoke-all with valid token → 200",
    revokeSessions.status === 200,
    `got status=${revokeSessions.status}`,
  );
  const revokeBody = revokeSessions.body as { revoked?: number } | null;
  // After revoke, the count returned should equal what was active before
  // PLUS the one we just created (sessionsBefore + 1).
  ok(
    `step 2a: response includes { revoked: ${sessionsBefore + 1} } (active count + our new session)`,
    revokeBody?.revoked === sessionsBefore + 1,
    `got revoked=${revokeBody?.revoked}, expected ${sessionsBefore + 1}`,
  );

  const after1 = await authorizeWithCookie(cookie1);
  ok(
    "step 3: revoked cookie → 302 to /login (no longer accepted)",
    after1.status === 302 && after1.location?.includes("/login") === true,
    `got status=${after1.status} location=${after1.location}`,
  );

  // ── List endpoint: now-empty ──

  const listEmpty = await adminCall(
    "GET",
    `/admin/users/${alice.id}/sessions`,
    { token: ADMIN_TOKEN },
  );
  ok(
    "step 4: GET /admin/.../sessions after revoke → 200 with empty list",
    listEmpty.status === 200 &&
      Array.isArray((listEmpty.body as { sessions?: unknown[] })?.sessions) &&
      ((listEmpty.body as { sessions: unknown[] }).sessions.length === 0),
    `got status=${listEmpty.status}`,
  );

  // ── Tokens/revoke-all: works on a fresh session ──

  // Re-create a session so the tokens endpoint has something to revoke
  // (we'd need to mint real OAuth tokens here to exercise the token path,
  // but the route's correctness is covered by unit tests; this just
  // verifies the route doesn't 500 with a valid token).
  const cookie2 = await createSessionCookie(alice.id);
  const revokeTokens = await adminCall(
    "POST",
    `/admin/users/${alice.id}/tokens/revoke-all`,
    { token: ADMIN_TOKEN },
  );
  ok(
    "step 5: POST /admin/.../tokens/revoke-all → 200",
    revokeTokens.status === 200,
    `got status=${revokeTokens.status}`,
  );
  const tokensBody = revokeTokens.body as {
    revoked_access?: number;
    revoked_refresh?: number;
  } | null;
  ok(
    "step 5a: response includes revoked_access + revoked_refresh counts",
    typeof tokensBody?.revoked_access === "number" &&
      typeof tokensBody?.revoked_refresh === "number",
    `body=${JSON.stringify(tokensBody)}`,
  );

  // ── Negative cases ──

  const noToken = await adminCall(
    "GET",
    `/admin/users/${alice.id}/sessions`,
    { token: null },
  );
  ok(
    "negative 1: missing X-Admin-Token → 401",
    noToken.status === 401,
    `got status=${noToken.status}`,
  );

  const wrongToken = await adminCall(
    "GET",
    `/admin/users/${alice.id}/sessions`,
    { token: "wrong-token-32-bytes-padding-padding-pad" },
  );
  ok(
    "negative 2: wrong X-Admin-Token → 401",
    wrongToken.status === 401,
    `got status=${wrongToken.status}`,
  );

  const unknownUser = await adminCall(
    "GET",
    `/admin/users/does-not-exist/sessions`,
    { token: ADMIN_TOKEN },
  );
  ok(
    "negative 3: GET on unknown userId → 404",
    unknownUser.status === 404,
    `got status=${unknownUser.status}`,
  );

  const unknownUserPost = await adminCall(
    "POST",
    `/admin/users/does-not-exist/sessions/revoke-all`,
    { token: ADMIN_TOKEN },
  );
  ok(
    "negative 4: POST revoke-all on unknown userId → 404",
    unknownUserPost.status === 404,
    `got status=${unknownUserPost.status}`,
  );

  await prisma.$disconnect();

  console.log(`\n${pass} pass, ${fail} fail`);
  if (fail > 0) process.exit(1);
}

main().catch(async (err) => {
  console.error(err);
  process.exit(1);
});
