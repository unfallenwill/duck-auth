import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { prisma } from "@/lib/generated/prisma-client";
import { extractSessionJti } from "@/lib/oauth/session";
import { config } from "@/lib/config";
import { revoke } from "@/lib/oauth-client";

/**
 * POST /api/auth/logout
 * Best-effort: revoke access + refresh tokens (in-process), mark the
 * server-side Session row as revoked, then clear all client-side cookies.
 * Even if the revoke calls fail, the local cookies are cleared so the user
 * is effectively logged out from this app.
 *
 * Issue #29: was two `fetch(${ISSUER}/oauth/revoke, ...)` calls — same
 * process, extra HTTP roundtrip + ISSUER env coupling. Now uses the
 * in-process `revoke` wrapper which mirrors the HTTP API surface.
 */
export async function POST(req: Request) {
  const cookieStore = await cookies();
  const access = cookieStore.get("oauth_access_token")?.value;
  const refresh = cookieStore.get("oauth_refresh_token")?.value;
  const sessionCookie = cookieStore.get("oauth_session")?.value;

  const clientId = config.demoClientId;

  // Mark the server-side Session row as revoked so the same cookie value
  // (e.g. captured before logout) cannot be used to authorize anymore.
  // Best-effort: if jti extraction fails (e.g. expired cookie, OR a legacy
  // pre-Phase-1 cookie with no jti claim — see issue #37 Phase 5) we still
  // clear the local cookies below. DB failures are logged (not silently
  // dropped) so monitoring can alert — a swallowed revoke leaves the
  // user's session active in the DB until expiresAt (default 2h), so the
  // failure mode is observable.
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

  // Revoke both tokens (best-effort, ignore failures — same contract as
  // the original fetch-based code).
  await Promise.all([
    refresh
      ? revoke({ token: refresh, hint: "refresh_token", clientId })
      : Promise.resolve(),
    access
      ? revoke({ token: access, hint: "access_token", clientId })
      : Promise.resolve(),
  ]);

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
