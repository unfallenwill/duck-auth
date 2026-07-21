import { prisma } from "@/lib/generated/prisma-client";
import { tokenError } from "@/lib/oauth/errors";
import {
  randomToken,
  verifyPkceS256,
} from "@/lib/oauth/crypto";
import {
  signAccessToken,
  signIdToken,
} from "@/lib/oauth/jwt";
import {
  authenticateClient,
  readFormBody,
  tokenResponse,
} from "@/lib/oauth/client-auth";
import { tokenRateLimit } from "@/lib/oauth/rate-limit";

const ACCESS_TOKEN_TTL = 60 * 60; // 1h
const REFRESH_TOKEN_TTL = 60 * 60 * 24 * 30; // 30d
const ID_TOKEN_TTL = 60 * 60; // 1h

export async function POST(req: Request) {
  const form = await readFormBody(req);

  if (!tokenRateLimit(req, form)) {
    return new Response(
      JSON.stringify({ error: "rate_limited", error_description: "Too many requests" }),
      { status: 429, headers: { "Retry-After": "60" } },
    );
  }

  const auth = await authenticateClient(req, form);
  if (!auth) {
    return new Response(
      JSON.stringify({
        error: "invalid_client",
        error_description: "Client authentication failed",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "WWW-Authenticate": 'Basic realm="oauth"',
        },
      },
    );
  }

  const grantType = form.get("grant_type");

  if (grantType === "authorization_code") {
    return handleAuthorizationCode(auth.clientId, form);
  }
  if (grantType === "refresh_token") {
    return handleRefreshToken(auth.clientId, form);
  }

  return tokenError("unsupported_grant_type");
}

async function handleAuthorizationCode(
  clientId: string,
  form: URLSearchParams,
) {
  const code = form.get("code");
  const redirectUri = form.get("redirect_uri");
  const codeVerifier = form.get("code_verifier");

  if (!code) return tokenError("invalid_request", "code is required");
  if (!redirectUri) {
    return tokenError("invalid_request", "redirect_uri is required");
  }

  // Fetch the code first to validate bound parameters (client, redirect_uri,
  // PKCE). The actual "mark used" step uses a CAS update to avoid TOCTOU.
  const record = await prisma.authorizationCode.findUnique({ where: { code } });
  if (!record) return tokenError("invalid_grant", "Unknown code");
  if (record.expiresAt < new Date()) {
    return tokenError("invalid_grant", "Code expired");
  }
  if (record.clientId !== clientId) {
    return tokenError("invalid_grant", "Code was issued to a different client");
  }
  if (record.redirectUri !== redirectUri) {
    return tokenError(
      "invalid_grant",
      "redirect_uri does not match the one used in authorization",
    );
  }

  if (record.codeChallenge) {
    if (!codeVerifier) {
      return tokenError("invalid_request", "code_verifier is required (PKCE)");
    }
    if (record.codeChallengeMethod === "S256") {
      if (!verifyPkceS256(codeVerifier, record.codeChallenge)) {
        return tokenError("invalid_grant", "PKCE verification failed");
      }
    }
  }

  // CAS: only the first concurrent request succeeds.
  const used = await prisma.authorizationCode.updateMany({
    where: { code, usedAt: null },
    data: { usedAt: new Date() },
  });
  if (used.count === 0) {
    return tokenError("invalid_grant", "Code already used");
  }

  const user = await prisma.user.findUnique({ where: { id: record.userId } });
  if (!user) {
    return tokenError("server_error", "User record missing", 500);
  }

  const access = await signAccessToken({
    sub: user.id,
    clientId,
    scopes: record.scopes,
    ttlSeconds: ACCESS_TOKEN_TTL,
  });
  await prisma.accessToken.create({
    data: {
      jti: access.jti,
      clientId,
      userId: user.id,
      scopes: record.scopes,
      expiresAt: access.expiresAt,
    },
  });

  const refreshToken = randomToken(48);
  await prisma.refreshToken.create({
    data: {
      token: refreshToken,
      clientId,
      userId: user.id,
      scopes: record.scopes,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL * 1000),
    },
  });

  let idToken: string | undefined;
  if (record.scopes.split(/\s+/).includes("openid")) {
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
    scope: record.scopes,
    ...(idToken ? { id_token: idToken } : {}),
  });
}

async function handleRefreshToken(
  clientId: string,
  form: URLSearchParams,
) {
  const refresh = form.get("refresh_token");
  if (!refresh) {
    return tokenError("invalid_request", "refresh_token is required");
  }

  // Fetch the token first to validate client + expiry.
  const record = await prisma.refreshToken.findUnique({
    where: { token: refresh },
  });
  if (!record) return tokenError("invalid_grant", "Unknown refresh token");
  if (record.expiresAt < new Date()) {
    return tokenError("invalid_grant", "Refresh token expired");
  }
  if (record.clientId !== clientId) {
    return tokenError("invalid_grant", "Token belongs to a different client");
  }

  // CAS: only the first concurrent rotation succeeds.
  const revoked = await prisma.refreshToken.updateMany({
    where: { token: refresh, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  if (revoked.count === 0) {
    return tokenError("invalid_grant", "Refresh token revoked or already rotated");
  }

  const user = await prisma.user.findUnique({ where: { id: record.userId } });
  if (!user) return tokenError("server_error", "User missing", 500);

  const access = await signAccessToken({
    sub: user.id,
    clientId,
    scopes: record.scopes,
    ttlSeconds: ACCESS_TOKEN_TTL,
  });
  await prisma.accessToken.create({
    data: {
      jti: access.jti,
      clientId,
      userId: user.id,
      scopes: record.scopes,
      expiresAt: access.expiresAt,
    },
  });

  const newRefresh = randomToken(48);
  await prisma.refreshToken.create({
    data: {
      token: newRefresh,
      clientId,
      userId: user.id,
      scopes: record.scopes,
      expiresAt: new Date(Date.now() + REFRESH_TOKEN_TTL * 1000),
    },
  });

  let idToken: string | undefined;
  if (record.scopes.split(/\s+/).includes("openid")) {
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
    refresh_token: newRefresh,
    scope: record.scopes,
    ...(idToken ? { id_token: idToken } : {}),
  });
}