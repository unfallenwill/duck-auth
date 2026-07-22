/**
 * Session revocation regression test (issue #30 Phase 1).
 *
 * The bug being fixed: the session cookie was a stateless HS256 JWT with no
 * server-side record. Logging out (or admin kicking) could clear the local
 * cookie, but a copy of the cookie captured before logout could still be
 * used to authorize. After Phase 1, logout marks `Session.revokedAt`,
 * and `verifySessionCookie` rejects revoked sessions regardless of JWT
 * signature validity.
 *
 * This script proves the fix end-to-end against a running server:
 *   1. Create a real Session row + JWT cookie via createSessionCookie.
 *   2. Confirm /oauth/authorize accepts it (302 to callback with code).
 *   3. Simulate logout by setting Session.revokedAt = now.
 *   4. Re-issue the same cookie value — /oauth/authorize must now redirect
 *      to /login instead of issuing an authorization code.
 */
import { PrismaClient } from "../lib/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { createHash, randomBytes } from "node:crypto";
import { createSessionCookie } from "./lib/session-cookie";
import { extractSessionJti } from "@/lib/oauth/session";

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
  const verifier = codeVerifier();
  u.searchParams.set("state", "revocation-test");
  u.searchParams.set("code_challenge", codeChallenge(verifier));
  u.searchParams.set("code_challenge_method", "S256");

  const res = await fetch(u, {
    headers: { Cookie: `oauth_session=${cookie}` },
    redirect: "manual",
  });
  return { status: res.status, location: res.headers.get("location") };
}

async function main() {
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

  console.log("=== Session Revocation Regression (issue #30 Phase 1) ===");

  // 1. Create a real Session row + JWT cookie.
  const sessionCookie = await createSessionCookie(alice.id);
  ok("issued session cookie via createSessionCookie", typeof sessionCookie === "string" && sessionCookie.length > 0);

  // 2. Cookie must work at /oauth/authorize.
  const before = await authorizeWithCookie(sessionCookie);
  const beforeHasCode =
    before.status === 302 &&
    before.location?.includes("/api/auth/callback") === true &&
    before.location?.includes("code=") === true;
  ok(
    "step 1: valid cookie → 302 to callback with code",
    beforeHasCode,
    `got status=${before.status} location=${before.location}`,
  );

  // 3. Find the Session row and mark it revoked (simulating logout).
  // The JWT carries the jti as payload; extract it without DB lookup so
  // Use the production extractSessionJti helper (parse-only, signature-verified,
  // no DB) so the test exercises the same code path the logout route uses.
  const jti = await extractSessionJti(sessionCookie);
  if (!jti) {
    console.error("Could not extract jti from session cookie");
    process.exit(1);
  }
  const updated = await prisma.session.update({
    where: { jti },
    data: { revokedAt: new Date() },
  });
  ok("step 2: marked Session.revokedAt = now", updated.revokedAt !== null);

  // 4. Same cookie value must now be rejected — expect redirect to /login.
  const after = await authorizeWithCookie(sessionCookie);
  const rejected =
    after.status === 302 &&
    after.location?.includes("/login") === true;
  ok(
    "step 3: revoked cookie → 302 to /login (was the bug — used to silently accept)",
    rejected,
    `got status=${after.status} location=${after.location}`,
  );

  // 5. Same jti in DB still has the revokedAt set (sanity: revoke is sticky).
  const reread = await prisma.session.findUnique({ where: { jti } });
  ok(
    "step 4: Session.revokedAt persisted in DB after revoke",
    reread?.revokedAt !== null,
  );

  // 6. End-to-end: actually call POST /api/auth/logout with a fresh cookie
  // and verify the route handler marks the DB row revoked (not just our
  // direct prisma update above). This catches typos in the logout route
  // (wrong import, wrong table name, accidentally-thrown error, etc.)
  const freshCookie = await createSessionCookie(alice.id);
  const freshJti = await extractSessionJti(freshCookie);
  if (!freshJti) {
    console.error("Could not extract jti from fresh cookie");
    process.exit(1);
  }
  const logoutRes = await fetch(`${BASE}/api/auth/logout`, {
    method: "POST",
    headers: { Cookie: `oauth_session=${freshCookie}` },
    redirect: "manual",
  });
  // Logout returns 303 redirect to /. The DB row should now be revoked.
  const afterLogout = await prisma.session.findUnique({ where: { jti: freshJti } });
  ok(
    "step 5: POST /api/auth/logout → 303",
    logoutRes.status === 303,
    `got status=${logoutRes.status}`,
  );
  ok(
    "step 6: logout route marked Session.revokedAt in DB",
    afterLogout?.revokedAt !== null,
    `revokedAt=${afterLogout?.revokedAt}`,
  );

  // 7. The fresh cookie (captured before logout) must now be rejected.
  const afterLogoutAuth = await authorizeWithCookie(freshCookie);
  const afterLogoutRejected =
    afterLogoutAuth.status === 302 &&
    afterLogoutAuth.location?.includes("/login") === true;
  ok(
    "step 7: post-logout cookie → 302 to /login",
    afterLogoutRejected,
    `got status=${afterLogoutAuth.status} location=${afterLogoutAuth.location}`,
  );

  await prisma.$disconnect();

  console.log(`\n${pass} pass, ${fail} fail`);
  if (fail > 0) process.exit(1);
}

main().catch(async (err) => {
  console.error(err);
  process.exit(1);
});