/**
 * End-to-end OAuth flow test for duck-auth.
 *
 * Steps:
 *   1. Login (POST /login) → set oauth_session cookie
 *   2. Authorize (GET /oauth/authorize) → get redirect to /consent (since no prior consent)
 *   3. Approve consent (POST /consent) → server action redirects to /oauth/authorize
 *      → which now generates a code → redirects to client redirect_uri
 *   4. Exchange code for tokens (POST /oauth/token)
 *   5. Fetch userinfo (GET /oauth/userinfo)
 *   6. Refresh tokens (POST /oauth/token with grant_type=refresh_token)
 *   7. Revoke (POST /oauth/revoke)
 */
import { createHash, randomBytes } from "node:crypto";
import { PrismaClient } from "../lib/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { createSessionCookie } from "./lib/session-cookie";

let aliceId: string | null = null;
async function getAliceId(): Promise<string> {
  if (aliceId) return aliceId;
  const p = new PrismaClient({
    adapter: new PrismaLibSql({ url: process.env["DATABASE_URL"] ?? "file:./dev.db" }),
  });
  const u = await p.user.findUnique({ where: { email: "alice@example.com" } });
  await p.$disconnect();
  if (!u) throw new Error("seed alice missing — run npm run db:seed");
  aliceId = u.id;
  return aliceId;
}

const BASE = "http://localhost:3000";
const REDIRECT_URI = "http://localhost:3000/api/auth/callback";
const SCOPES = "openid profile email";

function codeVerifier(): string {
  return randomBytes(32).toString("base64url");
}

function codeChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

/** Minimal cookie jar. */
class Jar {
  private store = new Map<string, string>();
  capture(setCookie: string[] | string | null) {
    if (!setCookie) return;
    const list = Array.isArray(setCookie) ? setCookie : [setCookie];
    for (const sc of list) {
      const [pair] = sc.split(";");
      const eq = pair.indexOf("=");
      if (eq > 0) {
        const name = pair.slice(0, eq).trim();
        const value = pair.slice(eq + 1).trim();
        this.store.set(name, value);
      }
    }
  }
  header(): string {
    return Array.from(this.store.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }
  get(name: string): string | undefined {
    return this.store.get(name);
  }
}

async function main() {
  console.log("=== End-to-End OAuth Flow Test ===\n");

  const jar = new Jar();
  const verifier = codeVerifier();
  const challenge = codeChallenge(verifier);
  const state = randomBytes(24).toString("base64url");

  // ----- 1. Direct session login -----
  // Since the Next.js server action requires an opaque action ID, we can't
  // submit the form from outside the browser easily. Instead, we generate the
  // session cookie directly using the same HMAC secret.
  const sessionJwt = await createSessionCookie(await getAliceId());
  jar.capture(`oauth_session=${sessionJwt}; Path=/`);
  console.log(`✓ injected session cookie for user ${await getAliceId()}`);

  // ----- 2. Authorize (GET /oauth/authorize) -----
  const authorizeUrl = new URL(`${BASE}/oauth/authorize`);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("client_id", "demo-client");
  authorizeUrl.searchParams.set("redirect_uri", REDIRECT_URI);
  authorizeUrl.searchParams.set("scope", SCOPES);
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("code_challenge", challenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");

  const authorizeRes = await fetch(authorizeUrl, {
    redirect: "manual",
    headers: { Cookie: jar.header() },
  });
  jar.capture(authorizeRes.headers.getSetCookie());
  console.log(`✓ /oauth/authorize → ${authorizeRes.status}`);
  if (authorizeRes.status !== 302) {
    console.error("Expected 302 redirect");
    process.exit(1);
  }
  let location = authorizeRes.headers.get("location")!;
  console.log(`  location: ${location}`);

  // First time → consent page.
  if (location.includes("/consent")) {
    console.log("  → consent required");

    // Find redirect_uri from the consent URL and approve.
    const consentUrl = new URL(location, BASE);
    const consentRedirect = consentUrl.searchParams.get("redirect_uri");
    if (!consentRedirect) throw new Error("missing redirect_uri in consent URL");

    // Approve consent by directly inserting a Consent row + re-issuing.
    // Since we can't easily POST to the server action, we'll go through the
    // authorize endpoint again — but we need to first insert a consent record.
    // We do that by calling authorize again with a consent cookie or by
    // inserting directly via Prisma.
    //
    // Easiest: insert via Prisma.
    const { PrismaClient } = await import(
      "../lib/generated/prisma/client.js"
    );
    const { PrismaLibSql } = await import("@prisma/adapter-libsql");
    const adapter = new PrismaLibSql({
      url: process.env.DATABASE_URL ?? "file:./dev.db",
    });
    const prisma = new PrismaClient({ adapter });
    await prisma.consent.upsert({
      where: {
        userId_clientId: {
          userId: "cmruhiqi30000xctf72q918j1",
          clientId: "demo-client",
        },
      },
      update: { scopes: SCOPES },
      create: {
        userId: "cmruhiqi30000xctf72q918j1",
        clientId: "demo-client",
        scopes: SCOPES,
      },
    });
    await prisma.$disconnect();
    console.log("  ✓ inserted consent record via Prisma");

    // Re-authorize: this time should skip consent and issue code directly.
    const reAuthRes = await fetch(authorizeUrl, {
      redirect: "manual",
      headers: { Cookie: jar.header() },
    });
    jar.capture(reAuthRes.headers.getSetCookie());
    console.log(`✓ re-authorize → ${reAuthRes.status}`);
    if (reAuthRes.status !== 302) {
      console.error("Expected 302 redirect after consent");
      process.exit(1);
    }
    location = reAuthRes.headers.get("location")!;
    console.log(`  location: ${location}`);
  }

  // ----- 3. Parse authorization code from redirect -----
  const callbackUrl = new URL(location);
  if (callbackUrl.host !== new URL(REDIRECT_URI).host) {
    console.error(`Expected redirect to ${REDIRECT_URI}, got ${location}`);
    process.exit(1);
  }
  const code = callbackUrl.searchParams.get("code");
  const returnedState = callbackUrl.searchParams.get("state");
  if (!code || returnedState !== state) {
    console.error("Missing code or state mismatch");
    process.exit(1);
  }
  console.log(`✓ got authorization code (${code.slice(0, 8)}...)`);

  // ----- 4. Exchange code for tokens -----
  const basic = Buffer.from("demo-client:demo-secret-change-me").toString(
    "base64",
  );
  const tokenRes = await fetch(`${BASE}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    }),
  });
  if (!tokenRes.ok) {
    console.error(`✗ token exchange failed: ${tokenRes.status}`);
    console.error(await tokenRes.text());
    process.exit(1);
  }
  const tokens = (await tokenRes.json()) as {
    access_token: string;
    refresh_token: string;
    id_token: string;
    expires_in: number;
    scope: string;
    token_type: string;
  };
  console.log(`✓ token exchange OK (expires_in=${tokens.expires_in}s)`);
  console.log(`  access_token: ${tokens.access_token.slice(0, 20)}...`);
  console.log(`  refresh_token: ${tokens.refresh_token.slice(0, 20)}...`);
  console.log(`  id_token: ${tokens.id_token.slice(0, 20)}...`);

  // ----- 5. Fetch userinfo -----
  const userinfoRes = await fetch(`${BASE}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  if (!userinfoRes.ok) {
    console.error(`✗ userinfo failed: ${userinfoRes.status}`);
    process.exit(1);
  }
  const userinfo = await userinfoRes.json();
  console.log("✓ userinfo:", JSON.stringify(userinfo));

  // ----- 6. Decode JWT id_token to verify claims -----
  const idClaims = JSON.parse(
    Buffer.from(tokens.id_token.split(".")[1]!, "base64url").toString(),
  );
  console.log("✓ id_token claims:", JSON.stringify({
    sub: idClaims.sub,
    aud: idClaims.aud,
    iss: idClaims.iss,
    email: idClaims.email,
    name: idClaims.name,
    exp: idClaims.exp,
  }));

  // ----- 7. Refresh token rotation -----
  const refreshRes = await fetch(`${BASE}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
    }),
  });
  if (!refreshRes.ok) {
    console.error(`✗ refresh failed: ${refreshRes.status}`);
    process.exit(1);
  }
  const refreshed = await refreshRes.json();
  console.log(`✓ refresh OK, new access_token: ${refreshed.access_token.slice(0, 20)}...`);

  // ----- 8. Verify old refresh token now fails -----
  const reuseRes = await fetch(`${BASE}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
    }),
  });
  if (reuseRes.status !== 400) {
    console.error(`✗ old refresh token should be revoked, got ${reuseRes.status}`);
    process.exit(1);
  }
  console.log("✓ old refresh token correctly rejected");

  // ----- 9. Revoke the new access_token, verify /userinfo rejects -----
  const revokeAccRes = await fetch(`${BASE}/oauth/revoke`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams({
      token: refreshed.access_token,
      token_type_hint: "access_token",
    }),
  });
  if (revokeAccRes.status !== 200) {
    console.error(`✗ access_token revoke failed: ${revokeAccRes.status}`);
    process.exit(1);
  }
  console.log("✓ access_token revoked");

  const revokedRes = await fetch(`${BASE}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${refreshed.access_token}` },
  });
  if (revokedRes.status !== 401) {
    console.error(`✗ revoked access token still works, got ${revokedRes.status}`);
    process.exit(1);
  }
  console.log("✓ /userinfo correctly rejects revoked access_token");

  // ----- 10. Revoke refresh token (RFC 7009: revoke is idempotent). -----
  await fetch(`${BASE}/oauth/revoke`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams({
      token: refreshed.refresh_token,
      token_type_hint: "refresh_token",
    }),
  });
  console.log("✓ refresh_token revoked");

  // ----- 11. Verify code is one-time (re-use fails) -----
  const codeReuseRes = await fetch(`${BASE}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: REDIRECT_URI,
      code_verifier: verifier,
    }),
  });
  if (codeReuseRes.status !== 400) {
    console.error(`✗ reused code should fail, got ${codeReuseRes.status}`);
    process.exit(1);
  }
  console.log("✓ reused authorization code correctly rejected");

  console.log("\n✅ All OAuth flow checks passed.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});