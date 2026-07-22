/**
 * Audit-script: verify the access token contains `aud` and `typ: at+jwt`,
 * and the token endpoint sets Cache-Control: no-store.
 */
import { PrismaClient } from "../lib/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { createHash, randomBytes } from "node:crypto";
import { createSessionCookie } from "./lib/session-cookie";

const BASE = "http://localhost:3000";
const url = process.env["DATABASE_URL"] ?? "file:./dev.db";
const prisma = new PrismaClient({ adapter: new PrismaLibSql({ url }) });

async function main() {
  const alice = await prisma.user.findUnique({
    where: { email: "alice@example.com" },
  });
  if (!alice) throw new Error("seed missing");
  const sess = await createSessionCookie(alice.id);

  const verifier = randomBytes(32).toString("base64url");
  const challenge = createHash("sha256").update(verifier).digest("base64url");
  const u = new URL(`${BASE}/oauth/authorize`);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("client_id", "demo-client");
  u.searchParams.set("redirect_uri", `${BASE}/api/auth/callback`);
  u.searchParams.set("scope", "openid profile email");
  u.searchParams.set("state", "audit");
  u.searchParams.set("code_challenge", challenge);
  u.searchParams.set("code_challenge_method", "S256");

  const r1 = await fetch(u, {
    headers: { Cookie: `oauth_session=${sess}` },
    redirect: "manual",
  });
  const code = new URL(r1.headers.get("location")!).searchParams.get("code");

  const r2 = await fetch(`${BASE}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization:
        "Basic " + Buffer.from("demo-client:demo-secret-change-me").toString("base64"),
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code!,
      redirect_uri: `${BASE}/api/auth/callback`,
      code_verifier: verifier,
    }),
  });

  console.log("--- access token inspection ---");
  const tok = (await r2.json()) as { access_token: string };
  const header = decodeProtectedHeader(tok.access_token);
  const claims = decodeJwt(tok.access_token);
  console.log("header:", JSON.stringify(header));
  console.log("claims:", JSON.stringify({
    aud: claims.aud,
    sub: claims.sub,
    iss: claims.iss,
    client_id: claims.client_id,
    scope: claims.scope,
    jti: claims.jti,
    iat: claims.iat,
    exp: claims.exp,
  }));

  console.log("\n--- token endpoint response headers ---");
  console.log("Cache-Control:", r2.headers.get("cache-control"));
  console.log("Pragma:", r2.headers.get("pragma"));

  // Assertions
  const checks = [
    ["typ = at+jwt", header.typ === "at+jwt"],
    ["aud claim present", typeof claims.aud === "string" && claims.aud === "demo-client"],
    ["Cache-Control: no-store", r2.headers.get("cache-control") === "no-store"],
    ["Pragma: no-cache", r2.headers.get("pragma") === "no-cache"],
  ] as const;
  for (const [label, ok] of checks) {
    console.log(`${ok ? "✓" : "✗"} ${label}`);
  }

  await prisma.$disconnect();
}
main();