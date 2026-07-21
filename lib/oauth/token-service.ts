import { prisma } from "@/lib/generated/prisma-client";
import { tokenError } from "@/lib/oauth/errors";
import { randomToken } from "@/lib/oauth/crypto";
import { signAccessToken, signIdToken } from "@/lib/oauth/jwt";
import { tokenResponse } from "@/lib/oauth/http";

const ACCESS_TOKEN_TTL = 60 * 60; // 1h
const REFRESH_TOKEN_TTL = 60 * 60 * 24 * 30; // 30d
const ID_TOKEN_TTL = 60 * 60; // 1h

/**
 * Shared token issuance: sign access + refresh (+ optional id token),
 * persist to DB, build the response. Used by all grant types.
 */
export async function issueTokenSet(
  userId: string,
  clientId: string,
  scopes: string,
): Promise<Response> {
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) return tokenError("server_error", "User record missing", 500);

  const access = await signAccessToken({
    sub: user.id,
    clientId,
    scopes,
    ttlSeconds: ACCESS_TOKEN_TTL,
  });
  await prisma.accessToken.create({
    data: {
      jti: access.jti,
      clientId,
      userId: user.id,
      scopes,
      expiresAt: access.expiresAt,
    },
  });

  const refreshToken = randomToken(48);
  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      clientId,
      userId: user.id,
      scopes,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL * 1000),
    },
  });

  let idToken: string | undefined;
  if (scopes.split(/\s+/).includes("openid")) {
    const id = await signIdToken({
      sub: user.id,
      email: user.email,
      name: user.name,
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
