import { prisma } from "@/lib/generated/prisma-client";
import { Prisma } from "@/lib/generated/prisma/client";
import { OAuthError } from "@/lib/oauth/errors";
import { randomToken } from "@/lib/oauth/crypto";
import { signAccessToken, verifyAccessToken, signIdToken } from "@/lib/oauth/jwt";
import { tokenResponse } from "@/lib/oauth/http";
import { parseScopes } from "@/lib/oauth/discovery";

const ACCESS_TOKEN_TTL = 60 * 60; // 1h
const REFRESH_TOKEN_TTL = 60 * 60 * 24 * 30; // 30d
const ID_TOKEN_TTL = 60 * 60; // 1h

/**
 * Plain data shape of a successful token response. Returned by helpers so
 * callers (both the /oauth/token HTTP route and the in-process
 * lib/oauth-client.ts wrapper) get a typed object — wrapping in a
 * Response is the route handler's job, not the service layer's.
 */
export interface TokenSetData {
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  refresh_token: string;
  scope: string;
  id_token?: string;
}

/**
 * Same as TokenSetData but represented as the response body (id_token
 * always present, possibly undefined — matches the JSON wire format).
 */
export interface UserInfoClaims {
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string | null;
}

/**
 * Issue access + refresh (+ optional id token), persist to DB, return
 * the token set as a plain object.
 *
 * ATOMICITY: `tx` is REQUIRED. The caller MUST open a
 * `prisma.$transaction(async (tx) => {...})` and pass the tx client here.
 * This guarantees the token writes are atomic with any CAS-protected
 * resource consumption (e.g. authorizationCode.usedAt,
 * refreshToken.revokedAt) happening in the caller — the same shape of
 * bug as issue #28.
 *
 * ERRORS: Throws `OAuthError` for expected failure modes (e.g. user
 * record missing). Throwing is critical inside a transaction: returning
 * a Response would let the tx commit, leaving the caller-side CAS write
 * permanently applied. By throwing, the transaction rolls back and the
 * caller-side CAS is undone.
 *
 * To produce the /oauth/token HTTP response, the route handler wraps
 * the returned `TokenSetData` in `tokenResponse(...)`.
 */
export async function issueTokenSet(
  userId: string,
  clientId: string,
  scopes: string,
  tx: Prisma.TransactionClient,
): Promise<TokenSetData> {
  const db = tx;

  const user = await db.user.findUnique({ where: { id: userId } });
  if (!user) {
    throw new OAuthError("server_error", "User record missing");
  }

  const access = await signAccessToken({
    sub: user.id,
    clientId,
    scopes,
    ttlSeconds: ACCESS_TOKEN_TTL,
  });
  await db.accessToken.create({
    data: {
      jti: access.jti,
      clientId,
      userId: user.id,
      scopes,
      expiresAt: access.expiresAt,
    },
  });

  const refreshToken = randomToken(48);
  await db.refreshToken.create({
    data: {
      token: refreshToken,
      clientId,
      userId: user.id,
      scopes,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL * 1000),
    },
  });

  let idToken: string | undefined;
  const scopeList = scopes.split(/\s+/);
  if (scopeList.includes("openid")) {
    const id = await signIdToken({
      sub: user.id,
      ...(scopeList.includes("email") ? { email: user.email } : {}),
      ...(scopeList.includes("profile") ? { name: user.name } : {}),
      clientId,
      ttlSeconds: ID_TOKEN_TTL,
    });
    idToken = id.token;
  }

  const data: TokenSetData = {
    access_token: access.token,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL,
    refresh_token: refreshToken,
    scope: scopes,
    ...(idToken ? { id_token: idToken } : {}),
  };
  return data;
}

/**
 * Wrap a TokenSetData as the /oauth/token HTTP response. Used by the
 * route handler. Kept as a small helper so the route code stays
 * readable and the response shape is documented in one place.
 */
export function tokenSetResponse(data: TokenSetData): Response {
  return tokenResponse(data as unknown as Record<string, unknown>);
}

/**
 * Revoke a token by value. Implements RFC 7009 §2.1 semantics:
 * - For refresh tokens (opaque strings), look up by `token` directly.
 * - For access tokens (JWT), decode without verifying signature and
 *   look up by `jti`. The DB is the source of truth for revocation.
 *
 * Returns `revoked: true` if the token existed, belonged to the client,
 * and was non-revoked. `revoked: false` means either unknown, wrong
 * client, or already revoked — all indistinguishable to the caller (per
 * RFC 7009 §2.2 the route handler always returns 200).
 *
 * `clientId` enforces the cross-client revocation boundary: a token
 * issued to client A cannot be revoked by client B. (RFC 7009 doesn't
 * strictly require this, but it's a safe default.)
 */
export async function revokeToken(
  token: string,
  hint: "access_token" | "refresh_token" | undefined,
  clientId: string,
): Promise<{ revoked: boolean }> {
  // Refresh-token-shaped: opaque string in the refreshTokens table.
  // Try the refresh path first if hint says so, or if no hint.
  if (hint !== "access_token") {
    const refresh = await prisma.refreshToken.findUnique({ where: { token } });
    if (refresh && refresh.clientId === clientId && !refresh.revokedAt) {
      await prisma.refreshToken.update({
        where: { token },
        data: { revokedAt: new Date() },
      });
      return { revoked: true };
    }
    if (refresh && refresh.clientId === clientId) {
      // Found but already revoked.
      return { revoked: false };
    }
    // Not a refresh token (or wrong client) — fall through to access path
    // unless hint was explicit.
    if (hint === "refresh_token") return { revoked: false };
  }

  // Access-token-shaped: JWT, decode without verify, look up by jti.
  let jti: string | undefined;
  try {
    const parts = token.split(".");
    if (parts.length === 3) {
      const payload = JSON.parse(
        Buffer.from(parts[1]!, "base64url").toString("utf8"),
      );
      if (typeof payload.jti === "string") jti = payload.jti;
    }
  } catch {
    // Malformed token — caller treats as "not found".
    return { revoked: false };
  }
  if (!jti) return { revoked: false };

  const access = await prisma.accessToken.findUnique({ where: { jti } });
  if (!access || access.clientId !== clientId) {
    return { revoked: false };
  }
  if (access.revokedAt) return { revoked: false };
  await prisma.accessToken.update({
    where: { jti },
    data: { revokedAt: new Date() },
  });
  return { revoked: true };
}

/**
 * Fetch the OIDC userinfo claims for an access token. Implements RFC 7662
 * introspection-like checks via the DB (signature was already verified by
 * verifyAccessToken, but we still need to confirm the token hasn't been
 * revoked since signing).
 *
 * Returns null on:
 *   - Invalid signature / expired / malformed token
 *   - Token revoked in DB
 *   - Token expired in DB
 *   - User record missing (shouldn't happen but handled)
 *
 * Throws on DB errors — those are real server errors, not "no info".
 */
export async function getUserInfo(accessToken: string): Promise<UserInfoClaims | null> {
  let claims;
  try {
    claims = await verifyAccessToken(accessToken);
  } catch {
    return null;
  }

  const stored = await prisma.accessToken.findUnique({
    where: { jti: claims.jti },
  });
  if (!stored || stored.revokedAt) return null;
  if (stored.expiresAt < new Date()) return null;

  const user = await prisma.user.findUnique({ where: { id: claims.sub } });
  if (!user) return null;

  const scopes = parseScopes(claims.scope);
  const out: UserInfoClaims = { sub: user.id };
  if (scopes.includes("email")) {
    out.email = user.email;
    // No email-verification flow exists yet. Per OIDC Core §5.1, this
    // claim MUST be true ONLY when the address has been verified; we
    // conservatively return false until verification is implemented.
    out.email_verified = false;
  }
  if (scopes.includes("profile")) {
    out.name = user.name;
  }
  return out;
}

/**
 * Convenience: run an authorization_code exchange in a transaction.
 * Used by the /oauth/token route AND the in-process oauth-client wrapper.
 *
 * Returns the TokenSetData on success; throws OAuthError on failure (the
 * tx is rolled back, so any CAS-protected state is unchanged).
 */
export async function exchangeAuthorizationCode(args: {
  code: string;
  redirectUri: string;
  codeVerifier: string | null;
  clientId: string;
  authorizationCode: {
    userId: string;
    clientId: string;
    redirectUri: string;
    scopes: string;
    expiresAt: Date;
    usedAt: Date | null;
    codeChallenge: string | null;
    codeChallengeMethod: string | null;
  };
  verifyPkceS256: (verifier: string, challenge: string) => boolean;
}): Promise<TokenSetData> {
  if (args.authorizationCode.expiresAt < new Date()) {
    throw new OAuthError("invalid_grant", "Code expired");
  }
  if (args.authorizationCode.clientId !== args.clientId) {
    throw new OAuthError(
      "invalid_grant",
      "Code was issued to a different client",
    );
  }
  if (args.authorizationCode.redirectUri !== args.redirectUri) {
    throw new OAuthError(
      "invalid_grant",
      "redirect_uri does not match the one used in authorization",
    );
  }
  if (args.authorizationCode.codeChallenge) {
    if (!args.codeVerifier) {
      throw new OAuthError(
        "invalid_request",
        "code_verifier is required (PKCE)",
      );
    }
    if (args.authorizationCode.codeChallengeMethod === "S256") {
      if (!args.verifyPkceS256(args.codeVerifier, args.authorizationCode.codeChallenge)) {
        throw new OAuthError("invalid_grant", "PKCE verification failed");
      }
    }
  }

  return prisma.$transaction(async (tx) => {
    const used = await tx.authorizationCode.updateMany({
      where: { code: args.code, usedAt: null },
      data: { usedAt: new Date() },
    });
    if (used.count === 0) {
      throw new OAuthError("invalid_grant", "Code already used");
    }
    return issueTokenSet(
      args.authorizationCode.userId,
      args.clientId,
      args.authorizationCode.scopes,
      tx,
    );
  });
}

/**
 * Convenience: run a refresh_token exchange in a transaction.
 * Returns the TokenSetData on success; throws OAuthError on failure.
 */
export async function exchangeRefreshToken(args: {
  refreshToken: string;
  clientId: string;
  refreshTokenRecord: {
    userId: string;
    clientId: string;
    scopes: string;
    expiresAt: Date;
    revokedAt: Date | null;
  };
}): Promise<TokenSetData> {
  if (args.refreshTokenRecord.expiresAt < new Date()) {
    throw new OAuthError("invalid_grant", "Refresh token expired");
  }
  if (args.refreshTokenRecord.clientId !== args.clientId) {
    throw new OAuthError(
      "invalid_grant",
      "Token belongs to a different client",
    );
  }

  return prisma.$transaction(async (tx) => {
    const revoked = await tx.refreshToken.updateMany({
      where: { token: args.refreshToken, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (revoked.count === 0) {
      throw new OAuthError(
        "invalid_grant",
        "Refresh token revoked or already rotated",
      );
    }
    return issueTokenSet(
      args.refreshTokenRecord.userId,
      args.clientId,
      args.refreshTokenRecord.scopes,
      tx,
    );
  });
}
