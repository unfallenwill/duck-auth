/**
 * Real consent-flow regression test.
 *
 * The original e2e tests bypassed the consent UI by directly upserting
 * consent rows via Prisma — meaning they never tested the real "user
 * clicks Allow" path. B2 (consent not persisted) went undetected because
 * of this. This script fixes that:
 *
 *   1. DELETE any existing consent for alice × demo-client.
 *   2. GET /oauth/authorize → must 302 to /consent (proves consent gate).
 *   3. Invoke the pure `recordConsent()` (what approveConsent calls).
 *   4. GET /oauth/authorize AGAIN → must 302 directly to callback URL
 *      with an authorization code (proves the recordConsent write
 *      unblocks the authorize endpoint).
 */
import { PrismaClient } from "../lib/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { recordConsent } from "../lib/oauth/consent";
import { createSessionCookie } from "./lib/session-cookie";

const url = process.env["DATABASE_URL"] ?? "file:./dev.db";
const adapter = new PrismaLibSql({ url });
const prisma = new PrismaClient({ adapter });

const BASE = "http://localhost:3000";
const CLIENT_ID = "demo-client";
const REDIRECT_URI = "http://localhost:3000/api/auth/callback";
const SCOPES = "openid profile email";
const STATE = "consent-flow-test";

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

async function getAliceId(): Promise<string> {
  const u = await prisma.user.findUnique({
    where: { email: "alice@example.com" },
  });
  if (!u) throw new Error("Seed alice missing — run npm run db:seed");
  return u.id;
}



function buildAuthorizeUrl(): string {
  const params = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT_URI,
    scope: SCOPES,
    state: STATE,
    code_challenge_method: "S256",
  });
  // PKCE S256: dummy challenge is fine — we won't redeem the code here.
  params.set("code_challenge", "consent-flow-test-challenge");
  return `${BASE}/oauth/authorize?${params.toString()}`;
}

async function main() {
  console.log("=== Real Consent-Flow Regression ===\n");

  const aliceId = await getAliceId();
  const session = await createSessionCookie(aliceId);
  const authzUrl = buildAuthorizeUrl();

  // Step 1: clear any existing consent.
  await prisma.consent.deleteMany({
    where: { userId: aliceId, clientId: CLIENT_ID },
  });
  console.log(`[step 1] cleared consent for alice × ${CLIENT_ID}`);

  // Step 2: GET /oauth/authorize should redirect to /consent (no consent row).
  const r1 = await fetch(authzUrl, {
    headers: { Cookie: `oauth_session=${session}` },
    redirect: "manual",
  });
  const loc1 = r1.headers.get("location") ?? "";
  ok(
    "step 2: authorize without consent → redirect to /consent",
    r1.status === 302 && loc1.includes("/consent"),
    `status=${r1.status} location=${loc1}`,
  );

  // Step 3: simulate the user clicking "Allow" by invoking the same
  // recordConsent() that approveConsent calls server-side.
  await recordConsent(aliceId, CLIENT_ID, SCOPES);
  console.log(`[step 3] recorded consent (simulates approveConsent)`);

  const row = await prisma.consent.findUnique({
    where: { userId_clientId: { userId: aliceId, clientId: CLIENT_ID } },
  });
  ok(
    "step 3b: consent row exists in DB",
    row !== null && row.scopes === SCOPES,
    `row=${JSON.stringify(row)}`,
  );

  // Step 4: GET /oauth/authorize again — should now skip consent and
  // issue an authorization code directly to the callback URL.
  const r2 = await fetch(authzUrl, {
    headers: { Cookie: `oauth_session=${session}` },
    redirect: "manual",
  });
  const loc2 = r2.headers.get("location") ?? "";
  const cb = new URL(loc2);
  const code = cb.searchParams.get("code");
  const state = cb.searchParams.get("state");
  ok(
    "step 4: authorize with consent → 302 to callback with code",
    r2.status === 302 && loc2.startsWith(REDIRECT_URI) && code !== null,
    `status=${r2.status} location=${loc2}`,
  );
  ok("step 4b: state is preserved through consent flow", state === STATE);

  console.log(
    `\n${pass === 4 ? "✅" : "❌"} ${pass}/4 consent-flow checks passed.` +
      (fail > 0 ? ` (${fail} failed)` : ""),
  );

  await prisma.$disconnect();
  if (fail > 0) process.exit(1);
}

main().catch(async (err) => {
  console.error(err);
  await prisma.$disconnect();
  process.exit(1);
});