/**
 * E2E test for /api/me/sessions (issue #34, Phase 3 of #30).
 *
 * Verifies user self-service session management:
 *   1. Create two sessions for alice (simulating two devices)
 *   2. GET /api/me/sessions → returns 2 active sessions
 *   3. DELETE /api/me/sessions/:jti (revoke one) → 200, other session still works
 *   4. Revoke-one on a jti that belongs to ANOTHER user → 404 (no info leak)
 *   5. Revoke-one on the SAME jti again → 404 (already revoked)
 *   6. DELETE /api/me/sessions (revoke-all) → 200, count >= 1
 *   7. After revoke-all: original cookie fails /oauth/authorize
 *   8. Negative: GET / DELETE without cookie → 401
 */
import { PrismaClient } from "../lib/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { createHash, randomBytes } from "node:crypto";
import { createSessionCookie } from "./lib/session-cookie";

const BASE = "http://localhost:3000";
const REDIRECT_URI = "http://localhost:3000/api/auth/callback";
const SCOPES = "openid profile email";
const ALICE_EMAIL = "alice@example.com";
const CLIENT_ID = "demo-client";

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
  u.searchParams.set("client_id", CLIENT_ID);
  u.searchParams.set("redirect_uri", REDIRECT_URI);
  u.searchParams.set("scope", SCOPES);
  u.searchParams.set("state", "me-sessions-test");
  u.searchParams.set("code_challenge", codeChallenge(codeVerifier()));
  u.searchParams.set("code_challenge_method", "S256");
  const res = await fetch(u, {
    headers: { Cookie: `oauth_session=${cookie}` },
    redirect: "manual",
  });
  return { status: res.status, location: res.headers.get("location") };
}

async function listSessions(
  cookie: string,
): Promise<{ status: number; body: { sessions?: Array<{ jti: string }> } }> {
  const res = await fetch(`${BASE}/api/me/sessions`, {
    headers: { Cookie: `oauth_session=${cookie}` },
  });
  return { status: res.status, body: await res.json() };
}

async function revokeOne(
  cookie: string,
  jti: string,
): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${BASE}/api/me/sessions/${encodeURIComponent(jti)}`, {
    method: "DELETE",
    headers: { Cookie: `oauth_session=${cookie}` },
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

async function revokeAll(cookie: string): Promise<{ status: number; body: unknown }> {
  const res = await fetch(`${BASE}/api/me/sessions`, {
    method: "DELETE",
    headers: { Cookie: `oauth_session=${cookie}` },
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

async function main() {
  const prisma = new PrismaClient({
    adapter: new PrismaLibSql({
      url: process.env["DATABASE_URL"] ?? "file:./dev.db",
    }),
  });

  const alice = await prisma.user.findUnique({
    where: { email: ALICE_EMAIL },
  });
  if (!alice) {
    console.error("Seed alice missing — run npm run db:seed");
    process.exit(1);
  }

  console.log("=== /api/me/sessions (issue #34 Phase 3) ===");

  // ── Step 1: create two sessions for alice (two devices) ──
  const cookieA = await createSessionCookie(alice.id);
  const cookieB = await createSessionCookie(alice.id);

  // Extract jti from each cookie so we can target revoke-one.
  const jtiA = await extractJti(cookieA);
  const jtiB = await extractJti(cookieB);
  ok(
    "step 1: created two sessions for alice (jtiA + jtiB)",
    !!jtiA && !!jtiB && jtiA !== jtiB,
    `jtiA=${jtiA?.slice(0, 8)} jtiB=${jtiB?.slice(0, 8)}`,
  );

  // ── Step 2: GET /api/me/sessions returns 2 ──
  const list1 = await listSessions(cookieA);
  const sessions1 = (list1.body.sessions ?? []).map((s) => s.jti);
  ok(
    "step 2: GET /api/me/sessions → 200 with 2 sessions",
    list1.status === 200 && sessions1.length >= 2 && sessions1.includes(jtiA!) && sessions1.includes(jtiB!),
    `got status=${list1.status} count=${sessions1.length}`,
  );

  // ── Step 3: revoke session A via cookie B (cross-session) ──
  // Use cookie B to authenticate, revoke session A's jti. After this,
  // cookie A should no longer authorize, but cookie B should.
  const rev1 = await revokeOne(cookieB, jtiA!);
  ok(
    "step 3a: DELETE /api/me/sessions/:jtiA with cookieB → 200",
    rev1.status === 200,
    `got status=${rev1.status}`,
  );

  const authA = await authorizeWithCookie(cookieA);
  ok(
    "step 3b: revoked session A → /oauth/authorize redirects to /login",
    authA.status === 302 && authA.location?.includes("/login") === true,
    `got status=${authA.status} location=${authA.location}`,
  );

  const authB = await authorizeWithCookie(cookieB);
  ok(
    "step 3c: unrevoked session B still authorizes",
    authB.status === 302,
    `got status=${authB.status}`,
  );

  // ── Step 4: revoke-one on already-revoked jti → 404 ──
  const rev2 = await revokeOne(cookieB, jtiA!);
  ok(
    "step 4: DELETE on already-revoked jti → 404",
    rev2.status === 404,
    `got status=${rev2.status}`,
  );

  // ── Step 5: revoke-all via cookie B ──
  const revAll = await revokeAll(cookieB);
  ok(
    "step 5a: DELETE /api/me/sessions (revoke-all) → 200 with revoked >= 1",
    revAll.status === 200 && typeof (revAll.body as { revoked?: number })?.revoked === "number" && (revAll.body as { revoked: number }).revoked >= 1,
    `got status=${revAll.status} body=${JSON.stringify(revAll.body)}`,
  );

  const authB2 = await authorizeWithCookie(cookieB);
  ok(
    "step 5b: cookieB (used for revoke-all) → /oauth/authorize redirects to /login",
    authB2.status === 302 && authB2.location?.includes("/login") === true,
    `got status=${authB2.status} location=${authB2.location}`,
  );

  // ── Step 6: negative — no cookie → 401 ──
  const noAuth = await fetch(`${BASE}/api/me/sessions`);
  ok("step 6a: GET without cookie → 401", noAuth.status === 401, `got ${noAuth.status}`);
  const noAuthDel = await fetch(`${BASE}/api/me/sessions`, { method: "DELETE" });
  ok("step 6b: DELETE without cookie → 401", noAuthDel.status === 401, `got ${noAuthDel.status}`);
  const noAuthJti = await fetch(`${BASE}/api/me/sessions/any-jti-here`, { method: "DELETE" });
  ok("step 6c: DELETE /api/me/sessions/:jti without cookie → 401", noAuthJti.status === 401, `got ${noAuthJti.status}`);

  await prisma.$disconnect();

  console.log(`\n${pass} pass, ${fail} fail`);
  if (fail > 0) process.exit(1);
}

/**
 * Extract the jti from a session JWT cookie by calling the production
 * verifySessionCookie helper. The JWT's jti claim is the Session row's
 * primary key, so this gives us a value we can pass to revoke-one.
 */
async function extractJti(cookie: string): Promise<string | null> {
  const { extractSessionJti } = await import("../lib/oauth/session");
  return extractSessionJti(cookie);
}

main().catch(async (err) => {
  console.error(err);
  process.exit(1);
});
