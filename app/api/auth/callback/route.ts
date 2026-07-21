import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { cookieDefaults } from "@/lib/oauth/cookies";
import { ISSUER } from "@/lib/oauth/discovery";
import { config } from "@/lib/config";

/**
 * GET /api/auth/callback
 * Receives ?code=...&state=... from the OAuth server, validates state,
 * exchanges code for tokens at /oauth/token, stores tokens, redirects home.
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

  // Exchange code for tokens.
  const clientId = config.demoClientId;
  const clientSecret = config.demoClientSecret;
  const redirectUri = config.demoRedirectUri;

  const basic = Buffer.from(`${clientId}:${clientSecret}`).toString("base64");
  const tokenRes = await fetch(`${ISSUER}/oauth/token`, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      code_verifier: codeVerifier,
    }),
  });

  // Clear one-time cookies regardless of outcome.
  cookieStore.delete("oauth_state");
  cookieStore.delete("oauth_verifier");

  if (!tokenRes.ok) {
    const err = await tokenRes.text();
    return NextResponse.redirect(
      new URL(
        `/?oauth_error=token_exchange_failed&detail=${encodeURIComponent(err)}`,
        req.url,
      ),
      302,
    );
  }

  const tokens = (await tokenRes.json()) as {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    id_token?: string;
    token_type: string;
    scope: string;
  };

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