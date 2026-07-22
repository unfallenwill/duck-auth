import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { cookieDefaults } from "@/lib/oauth/cookies";
import { config } from "@/lib/config";
import { exchangeCode } from "@/lib/oauth-client";

/**
 * GET /api/auth/callback
 * Receives ?code=...&state=... from the OAuth server, validates state,
 * exchanges code for tokens (in-process), stores tokens, redirects home.
 *
 * Issue #29: was `fetch(${ISSUER}/oauth/token, ...)` — same process,
 * extra HTTP roundtrip + ISSUER env coupling. Now uses the in-process
 * `exchangeCode` wrapper which mirrors the HTTP API surface but calls
 * the service helpers directly.
 */
export async function GET(req: Request) {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  const cookieStore = await cookies();

  if (error) {
    return NextResponse.redirect(
      new URL(`/?oauth_error=${encodeURIComponent(error)}`, req.url),
      302,
    );
  }

  if (!code || !state) {
    return NextResponse.json(
      { error: "invalid_request", error_description: "missing code or state" },
      { status: 400 },
    );
  }

  // Validate state (CSRF).
  const expectedState = cookieStore.get("oauth_state")?.value;
  const codeVerifier = cookieStore.get("oauth_verifier")?.value;
  if (!expectedState || expectedState !== state || !codeVerifier) {
    return NextResponse.json(
      { error: "invalid_state", error_description: "state mismatch" },
      { status: 400 },
    );
  }

  // Clear one-time cookies regardless of outcome (they're burned by use).
  cookieStore.delete("oauth_state");
  cookieStore.delete("oauth_verifier");

  // Exchange code for tokens (in-process). exchangeCode throws on
  // invalid_grant / unknown code etc. — we surface those as redirects
  // with an oauth_error query param so the home page can show the error.
  let tokens;
  try {
    tokens = await exchangeCode({
      code,
      redirectUri: config.demoRedirectUri,
      codeVerifier,
      clientId: config.demoClientId,
    });
  } catch (err) {
    const detail = err instanceof Error ? err.message : String(err);
    return NextResponse.redirect(
      new URL(
        `/?oauth_error=token_exchange_failed&detail=${encodeURIComponent(detail)}`,
        req.url,
      ),
      302,
    );
  }

  // IMPORTANT: must use NextResponse.redirect() (not Response.redirect) so the
  // cookie() writes below are attached to the outgoing 302 response.
  const homeRedirect = NextResponse.redirect(new URL("/", req.url), 302);

  const accessOpts = { ...cookieDefaults(), maxAge: tokens.expires_in };
  cookieStore.set("oauth_access_token", tokens.access_token, accessOpts);
  cookieStore.set("oauth_refresh_token", tokens.refresh_token, {
    ...cookieDefaults(),
    maxAge: 60 * 60 * 24 * 30,
  });
  if (tokens.id_token) {
    cookieStore.set("oauth_id_token", tokens.id_token, accessOpts);
  }

  return homeRedirect;
}
