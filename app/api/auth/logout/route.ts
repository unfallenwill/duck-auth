import { cookies } from "next/headers";
import { NextResponse } from "next/server";

const ISSUER = process.env["OAUTH_ISSUER"] ?? "http://localhost:3000";

/**
 * POST /api/auth/logout
 * Best-effort: revoke access + refresh tokens at /oauth/revoke, then clear
 * all client-side cookies. Even if the revoke calls fail, the local cookies
 * are cleared so the user is effectively logged out from this app.
 */
export async function POST(req: Request) {
  const cookieStore = await cookies();
  const access = cookieStore.get("oauth_access_token")?.value;
  const refresh = cookieStore.get("oauth_refresh_token")?.value;

  const clientId = process.env["DEMO_CLIENT_ID"] ?? "demo-client";
  const clientSecret = process.env["DEMO_CLIENT_SECRET"] ?? "";
  const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

  // Revoke both tokens (best-effort, ignore failures).
  if (refresh) {
    await fetch(`${ISSUER}/oauth/revoke`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basic}`,
      },
      body: new URLSearchParams({ token: refresh, token_type_hint: "refresh_token" }),
    }).catch(() => {});
  }
  if (access) {
    await fetch(`${ISSUER}/oauth/revoke`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization: `Basic ${basic}`,
      },
      body: new URLSearchParams({ token: access, token_type_hint: "access_token" }),
    }).catch(() => {});
  }

  // Clear all oauth cookies (and the session cookie if present).
  for (const name of [
    "oauth_access_token",
    "oauth_refresh_token",
    "oauth_id_token",
    "oauth_state",
    "oauth_verifier",
    "oauth_session",
  ]) {
    cookieStore.delete(name);
  }

  return NextResponse.redirect(new URL("/", req.url), 303);
}