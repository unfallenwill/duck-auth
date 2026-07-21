import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import {
  randomToken,
  generateCodeVerifier,
  codeChallengeS256,
} from "@/lib/oauth/crypto";
import { cookieDefaults } from "@/lib/oauth/cookies";
import { config } from "@/lib/config";

/**
 * GET /api/auth/login
 * Starts the OAuth Authorization Code Flow with PKCE.
 * Stores state + code_verifier in cookies, then redirects to /oauth/authorize.
 */
export async function GET(req: Request) {
  const clientId = config.demoClientId;
  const redirectUri = config.demoRedirectUri;
  const issuer = config.issuer;

  // Generate anti-CSRF state + PKCE pair.
  const state = randomToken(24);
  const codeVerifier = generateCodeVerifier(32);
  const codeChallenge = codeChallengeS256(codeVerifier);

  // Stash in httpOnly cookies (short-lived; consumed by /callback).
  const cookieStore = await cookies();
  const cookieOpts = { ...cookieDefaults(), maxAge: 60 * 10 };
  cookieStore.set("oauth_state", state, cookieOpts);
  cookieStore.set("oauth_verifier", codeVerifier, cookieOpts);

  // Build /oauth/authorize URL.
  const authorize = new URL("/oauth/authorize", issuer);
  authorize.searchParams.set("response_type", "code");
  authorize.searchParams.set("client_id", clientId);
  authorize.searchParams.set("redirect_uri", redirectUri);
  authorize.searchParams.set("scope", "openid profile email");
  authorize.searchParams.set("state", state);
  authorize.searchParams.set("code_challenge", codeChallenge);
  authorize.searchParams.set("code_challenge_method", "S256");

  return NextResponse.redirect(authorize, 302);

  void req;
}