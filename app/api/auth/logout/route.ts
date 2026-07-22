import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { prisma } from "@/lib/generated/prisma-client";
import { extractSessionJti } from "@/lib/oauth/session";
import { ISSUER } from "@/lib/oauth/discovery";
import { config } from "@/lib/config";

/**
 * POST /api/auth/logout
 * Best-effort: revoke access + refresh tokens at /oauth/revoke, mark the
 * server-side Session row as revoked, then clear all client-side cookies.
 * Even if the revoke calls fail, the local cookies are cleared so the user
 * is effectively logged out from this app.
 */
export async function POST(req: Request) {
  const cookieStore = await cookies();
  const access = cookieStore.get("oauth_access_token")?.value;
  const refresh = cookieStore.get("oauth_refresh_token")?.value;
  const sessionCookie = cookieStore.get("oauth_session")?.value;

  const clientId = config.demoClientId;
  const clientSecret = config.demoClientSecret;
  const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");

  // Mark the server-side Session row as revoked so the same cookie value
  // (e.g. captured before logout) cannot be used to authorize anymore.
  // Best-effort: if jti extraction fails (e.g. expired cookie) we still
  // clear the local cookies. DB failures are logged (not silently dropped)
  // so monitoring can alert — a swallowed revoke leaves the user's
  // session active in the DB until expiresAt (default 2h), so the failure
  // mode is observable.
  const jti = await extractSessionJti(sessionCookie ?? "");
  if (jti) {
    await prisma.session
      .update({
        where: { jti },
        data: { revokedAt: new Date() },
      })
      .catch((err) => {
        console.error(
          "[logout] failed to mark Session.revokedAt; cookie cleared but session still DB-active until expiry:",
          err,
        );
      });
  }

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