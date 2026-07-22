import { prisma } from "@/lib/generated/prisma-client";
import { Prisma } from "@/lib/generated/prisma/client";
import { OAuthError } from "@/lib/oauth/errors";
import { randomToken } from "@/lib/oauth/crypto";
import { signAccessToken, signIdToken } from "@/lib/oauth/jwt";
import { tokenResponse } from "@/lib/oauth/http";

const ACCESS_TOKEN_TTL = 60 * 60; // 1h
const REFRESH_TOKEN_TTL = 60 * 60 * 24 * 30; // 30d
const ID_TOKEN_TTL = 60 * 60; // 1h

/**
 * Shared token issuance: sign access + refresh (+ optional id token),
 * persist to DB, build the response. Used by all grant types.
 *
 * ATOMICITY: `tx` is REQUIRED. The caller MUST open a
 * `prisma.$transaction(async (tx) => {...})` and pass the tx client here.
 * This guarantees the token writes are atomic with any CAS-protected
 * resource consumption (e.g. authorizationCode.usedAt, refreshToken.revokedAt)
 * happening in the caller — the same shape of bug as issue #28.
 *
 * ERRORS: Throws `OAuthError` for expected failure modes (e.g. user record
 * missing). This is critical inside a transaction: returning a Response
 * would let the tx commit, leaving the caller-side CAS write permanently
 * applied. By throwing, the transaction rolls back and the caller-side CAS
 * is undone.
 */
export async function issueTokenSet(
  userId: string,
  clientId: string,
  scopes: string,
  tx: Prisma.TransactionClient,
): Promise<Response> {
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

  return tokenResponse({
    access_token: access.token,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL,
    refresh_token: refreshToken,
    scope: scopes,
    ...(idToken ? { id_token: idToken } : {}),
  });
}
