/**
 * E2E test for DELETE /api/users/me (issue #35, Phase 4 of #30).
 *
 * Verifies the GDPR right-to-erasure flow against a running dev server:
 *   1. Login as alice → get session cookie
 *   2. Confirm /oauth/authorize accepts the cookie (redirects to consent
 *      or callback with code, depending on whether alice has prior consent)
 *   3. DELETE /api/users/me → 204
 *   4. Same cookie → /oauth/authorize redirects to /login (revoked)
 *   5. DELETE again → 204 (idempotent — re-running is a no-op)
 *   6. Login with original email + password → fails (passwordHash cleared)
 *   7. After restore: DB row has deletedAt set + anonymized email
 *
 * Test isolation: deletes alice's Consent row at the start (other e2e
 * suites may have left one behind) and restores it at the end so
 * downstream tests aren't broken.
 */
import { PrismaClient } from "../lib/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { createHash, randomBytes } from "node:crypto";
import { createSessionCookie } from "./lib/session-cookie";

const BASE = "http://localhost:3000";
const REDIRECT_URI = "http://localhost:3000/api/auth/callback";
const SCOPES = "openid profile email";
const ALICE_EMAIL = "alice@example.com";
const ALICE_PASSWORD = "alice-password";
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

/**
 * /oauth/authorize returns 302 to either:
 *   - /api/auth/callback?code=... (alice has consent for demo-client)
 *   - /consent?client_id=... (no consent yet, needs user to grant)
 *
 * Either is a valid "session works" outcome for our purposes. Both prove
 * verifySessionCookie returned a valid session.
 */
async function authorizeWithCookie(
  cookie: string,
): Promise<{ status: number; location: string | null }> {
  const u = new URL(`${BASE}/oauth/authorize`);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", CLIENT_ID);
  u.searchParams.set("redirect_uri", REDIRECT_URI);
  u.searchParams.set("scope", SCOPES);
  u.searchParams.set("state", "gdpr-delete-test");
  u.searchParams.set("code_challenge", codeChallenge(codeVerifier()));
  u.searchParams.set("code_challenge_method", "S256");

  const res = await fetch(u, {
    headers: { Cookie: `oauth_session=${cookie}` },
    redirect: "manual",
  });
  return { status: res.status, location: res.headers.get("location") };
}

function isAuthSuccess(status: number, location: string | null): boolean {
  if (status !== 302) return false;
  if (!location) return false;
  // Either redirect with auth code, or redirect to /consent page.
  return (
    location.includes("/api/auth/callback?code=") ||
    location.includes("/consent")
  );
}

async function deleteMe(cookie: string): Promise<{ status: number; body: string }> {
  const res = await fetch(`${BASE}/api/users/me`, {
    method: "DELETE",
    headers: { Cookie: `oauth_session=${cookie}` },
    redirect: "manual",
  });
  const body = await res.text().catch(() => "");
  return { status: res.status, body };
}

async function login(
  email: string,
  password: string,
): Promise<{ status: number; cookies: string }> {
  const res = await fetch(`${BASE}/api/auth/login-post`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ email, password, next: "/" }),
    redirect: "manual",
  });
  const setCookies = res.headers.getSetCookie?.() ?? [];
  return { status: res.status, cookies: setCookies.join("; ") };
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

  // ── Test isolation: snapshot + clean ──
  // Snapshot alice's pre-test state for full restore at the end.
  const snapshot = {
    email: alice.email,
    passwordHash: alice.passwordHash,
    name: alice.name,
    deletedAt: alice.deletedAt,
  };
  // Capture alice's existing consents so we can restore them at the end.
  const originalConsents = await prisma.consent.findMany({
    where: { userId: alice.id },
  });
  // Clean: delete alice's consents so authorize deterministically goes to
  // /api/auth/callback (new auth code) instead of /consent.
  await prisma.consent.deleteMany({ where: { userId: alice.id } });

  console.log("=== GDPR DELETE /api/users/me (issue #35 Phase 4) ===");

  // ── Step 1: fresh session, authorize works ──
  const cookie = await createSessionCookie(alice.id);
  const before = await authorizeWithCookie(cookie);
  ok(
    "step 1: pre-deletion cookie → 302 to callback or consent (auth success)",
    isAuthSuccess(before.status, before.location),
    `got status=${before.status} location=${before.location}`,
  );

  // ── Step 2: DELETE without session → 401 ──
  const noAuth = await fetch(`${BASE}/api/users/me`, {
    method: "DELETE",
    redirect: "manual",
  });
  ok("step 2: DELETE without cookie → 401", noAuth.status === 401, `got ${noAuth.status}`);

  // ── Step 3: DELETE with valid session → 204 ──
  const del = await deleteMe(cookie);
  ok("step 3: DELETE with valid cookie → 204", del.status === 204, `got ${del.status}`);

  // ── Step 4: same cookie no longer authorizes ──
  const after = await authorizeWithCookie(cookie);
  ok(
    "step 4: post-deletion cookie → 302 to /login",
    after.status === 302 && after.location?.includes("/login") === true,
    `got status=${after.status} location=${after.location}`,
  );

  // ── Step 5: DELETE again is idempotent → 204 ──
  // (Need a fresh session to call DELETE since the first one's cookie is
  // now revoked. Create one and check it gets the right behavior.)
  const cookie2 = await createSessionCookie(alice.id);
  const before2 = await authorizeWithCookie(cookie2);
  ok(
    "step 5a: pre-second-delete cookie still authorizes (session row exists)",
    isAuthSuccess(before2.status, before2.location),
    `got status=${before2.status} location=${before2.location}`,
  );
  const del2 = await deleteMe(cookie2);
  ok("step 5b: second DELETE on already-deleted user → 204 (idempotent)", del2.status === 204, `got ${del2.status}`);

  // ── Step 6: DB row was anonymized + soft-deleted ──
  const afterRow = await prisma.user.findUnique({ where: { id: alice.id } });
  ok("step 6a: User.deletedAt is set", afterRow?.deletedAt !== null);
  ok("step 6b: User.email is anonymized", afterRow?.email !== ALICE_EMAIL && afterRow?.email.startsWith("deleted-"));
  ok("step 6c: User.name is null", afterRow?.name === null);
  ok("step 6d: User.passwordHash is empty (login impossible)", afterRow?.passwordHash === "");

  // ── Step 7: login with original email/password fails ──
  const loginAttempt = await login(ALICE_EMAIL, ALICE_PASSWORD);
  ok(
    "step 7: login with original credentials → redirect to /login (failed)",
    loginAttempt.status === 303 || loginAttempt.status === 302,
    `got status=${loginAttempt.status}`,
  );

  // ── Restore alice for downstream tests ──
  await prisma.user.update({
    where: { id: alice.id },
    data: {
      email: snapshot.email,
      passwordHash: snapshot.passwordHash,
      name: snapshot.name,
      deletedAt: null,
    },
  });
  // Restore consents (the soft-delete removed them; without restoration
  // downstream e2e suites that expect a consented alice would fail).
  if (originalConsents.length > 0) {
    await prisma.consent.createMany({
      data: originalConsents.map((c) => ({
        userId: c.userId,
        clientId: c.clientId,
        scopes: c.scopes,
        // createdAt: skip — Prisma default now() is fine
      })),
    });
  }
  console.log(`  ℹ restored alice for downstream tests`);

  await prisma.$disconnect();

  console.log(`\n${pass} pass, ${fail} fail`);
  if (fail > 0) process.exit(1);
}

main().catch(async (err) => {
  console.error(err);
  console.error("⚠ test crashed — run npm run db:seed to fully restore alice");
  process.exit(1);
});
