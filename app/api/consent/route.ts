import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { prisma } from "@/lib/generated/prisma-client";
import { recordConsent } from "@/lib/oauth/consent";
import { verifySessionCookie } from "@/lib/oauth/session";
import {
  authorizeError,
  type OAuthErrorCode,
} from "@/lib/oauth/errors";
import {
  filterScopes,
  parseScopes,
} from "@/lib/oauth/discovery";

/**
 * POST /api/consent
 *
 * Approve or deny the consent prompt from /consent. Plain route handler
 * (not a server action) — Playwright/Chromium have well-tested behavior
 * with route handlers + redirect, while server-action redirects can
 * race the test harness's navigation observation.
 *
 * Body params: client_id, redirect_uri, state, scope, code_challenge,
 *              code_challenge_method, action (approve|deny)
 */
export async function POST(req: Request) {
  const form = await req.formData();
  const clientId = String(form.get("client_id") ?? "");
  const redirectUri = String(form.get("redirect_uri") ?? "");
  const state = String(form.get("state") ?? "");
  const scope = String(form.get("scope") ?? "");
  const codeChallenge = String(form.get("code_challenge") ?? "");
  const codeChallengeMethod = String(form.get("code_challenge_method") ?? "");
  const action = String(form.get("action") ?? "approve");

  // Resolve userId from the session cookie.
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("oauth_session")?.value;
  if (!sessionCookie) {
    return NextResponse.json({ error: "no_session" }, { status: 401 });
  }
  const session = await verifySessionCookie(sessionCookie);
  if (!session) {
    return NextResponse.json({ error: "invalid_session" }, { status: 401 });
  }

  // Validate redirect_uri against registered client URIs (prevents
  // open redirect — defense in depth on top of the server-action check).
  const client = await prisma.client.findUnique({ where: { id: clientId } });
  const allowed = client ? (JSON.parse(client.redirectUris) as string[]) : [];
  if (!client || !allowed.includes(redirectUri)) {
    return NextResponse.json(
      { error: "invalid_redirect_uri" },
      { status: 400 },
    );
  }

  if (action === "deny") {
    const target = authorizeError(
      redirectUri,
      state || undefined,
      "access_denied" satisfies OAuthErrorCode,
    );
    return NextResponse.redirect(target, 303);
  }

  // Validate scopes against the client's allowed list.
  const { valid, invalid } = filterScopes(
    parseScopes(scope),
    client.allowedScopes,
  );
  if (invalid.length > 0) {
    return NextResponse.json(
      { error: "invalid_scope", error_description: `Disallowed scopes: ${invalid.join(", ")}` },
      { status: 400 },
    );
  }
  const safeScope = valid.join(" ");

  // Persist the consent and bounce back to /oauth/authorize with the
  // original PKCE + state params.
  await recordConsent(session.uid, clientId, safeScope);
  const target = new URL("/oauth/authorize", req.url);
  target.searchParams.set("response_type", "code");
  target.searchParams.set("client_id", clientId);
  target.searchParams.set("redirect_uri", redirectUri);
  target.searchParams.set("scope", safeScope);
  target.searchParams.set("state", state);
  if (codeChallenge) {
    target.searchParams.set("code_challenge", codeChallenge);
    if (codeChallengeMethod) {
      target.searchParams.set("code_challenge_method", codeChallengeMethod);
    }
  }
  return NextResponse.redirect(target, 303);
}