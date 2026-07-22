/**
 * In-process OAuth client wrapper.
 *
 * Issue #29: the demo client (`/api/auth/*`) used to call
 * `${ISSUER}/oauth/*` via real HTTP `fetch()` — same process, same
 * Prisma client, same rate-limit buckets, but an extra roundtrip per
 * call. Worse, this binds the demo client to the `$ISSUER` env var,
 * blocks the eventual RP/AS split (4 routes would all need rewriting),
 * and makes log correlation harder (HTTP trace across two endpoints).
 *
 * This module is the in-process equivalent: typed methods that call the
 * underlying service helpers directly. The shape mirrors the HTTP API
 * so the call sites stay readable and a future RP/AS split can swap
 * this for a real HTTP client without changing the 4 route files.
 *
 * **Scope**: only `/api/auth/*` (demo client) imports this. The
 * `/oauth/*` routes import from `lib/oauth/token-service.ts` directly
 * since they ARE the server side of the HTTP boundary.
 */
import {
  exchangeAuthorizationCode,
  exchangeRefreshToken,
  getUserInfo,
  revokeToken,
  type TokenSetData,
  type UserInfoClaims,
} from "@/lib/oauth/token-service";
import { verifyPkceS256 } from "@/lib/oauth/crypto";
import { prisma } from "@/lib/generated/prisma-client";

/**
 * Exchange an authorization code for a token set.
 *
 * Equivalent to `POST /oauth/token` with `grant_type=authorization_code`.
 * Validates the code, runs PKCE, marks the code used (CAS), and issues
 * tokens — all atomic via `exchangeAuthorizationCode`.
 */
export async function exchangeCode(args: {
  code: string;
  redirectUri: string;
  codeVerifier: string | null;
  clientId: string;
}): Promise<TokenSetData> {
  const record = await prisma.authorizationCode.findUnique({
    where: { code: args.code },
  });
  if (!record) {
    // Match the HTTP path's error shape. The route handler converts
    // OAuthError into a tokenError response.
    throw new Error("Unknown code");
  }
  return exchangeAuthorizationCode({
    code: args.code,
    redirectUri: args.redirectUri,
    codeVerifier: args.codeVerifier,
    clientId: args.clientId,
    authorizationCode: record,
    verifyPkceS256,
  });
}

/**
 * Exchange a refresh token for a fresh token set.
 *
 * Equivalent to `POST /oauth/token` with `grant_type=refresh_token`.
 * CAS-revokes the old refresh token, issues a new set.
 */
export async function refreshTokens(args: {
  refreshToken: string;
  clientId: string;
}): Promise<TokenSetData> {
  const record = await prisma.refreshToken.findUnique({
    where: { token: args.refreshToken },
  });
  if (!record) throw new Error("Unknown refresh token");
  return exchangeRefreshToken({
    refreshToken: args.refreshToken,
    clientId: args.clientId,
    refreshTokenRecord: record,
  });
}

/**
 * Revoke a token (best-effort, swallows DB errors). Same semantics as
 * `POST /oauth/revoke` (RFC 7009): always returns 200, never leaks
 * whether the token existed.
 */
export async function revoke(args: {
  token: string;
  hint?: "access_token" | "refresh_token";
  clientId: string;
}): Promise<void> {
  await revokeToken(args.token, args.hint, args.clientId).catch(() => {
    // Match the route handler's best-effort behavior: log nothing,
    // continue. Logout is still "effective" from the user's perspective
    // even if the server-side revoke fails, because the local cookies
    // are cleared too.
  });
}

/**
 * Fetch the OIDC userinfo claims for an access token.
 *
 * Returns `null` on invalid/expired/revoked/unknown token. Equivalent
 * to `GET /oauth/userinfo` returning 401.
 */
export async function userinfo(
  accessToken: string,
): Promise<UserInfoClaims | null> {
  return getUserInfo(accessToken);
}
