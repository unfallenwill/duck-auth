import { prisma } from "@/lib/generated/prisma-client";
import { OAuthError, tokenError } from "@/lib/oauth/errors";
import { verifyPkceS256 } from "@/lib/oauth/crypto";
import { authenticateClient } from "@/lib/oauth/client-auth";
import { readFormBody } from "@/lib/oauth/http";
import { tokenRateLimit } from "@/lib/oauth/rate-limit";
import { issueTokenSet } from "@/lib/oauth/token-service";

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

  try {
    if (grantType === "authorization_code") {
      return await handleAuthorizationCode(auth.clientId, form);
    }
    if (grantType === "refresh_token") {
      return await handleRefreshToken(auth.clientId, form);
    }
    throw new OAuthError("unsupported_grant_type");
  } catch (err) {
    // OAuthError is the throwable form of a token endpoint error.
    // Anything else is a real server error and propagates to Next.js.
    if (err instanceof OAuthError) {
      return tokenError(err.code, err.message, err.status);
    }
    throw err;
  }
}

async function handleAuthorizationCode(
  clientId: string,
  form: URLSearchParams,
) {
  const code = form.get("code");
  const redirectUri = form.get("redirect_uri");
  const codeVerifier = form.get("code_verifier");

  if (!code) throw new OAuthError("invalid_request", "code is required");
  if (!redirectUri) {
    throw new OAuthError("invalid_request", "redirect_uri is required");
  }

  const record = await prisma.authorizationCode.findUnique({ where: { code } });
  if (!record) throw new OAuthError("invalid_grant", "Unknown code");
  if (record.expiresAt < new Date()) {
    throw new OAuthError("invalid_grant", "Code expired");
  }
  if (record.clientId !== clientId) {
    throw new OAuthError("invalid_grant", "Code was issued to a different client");
  }
  if (record.redirectUri !== redirectUri) {
    throw new OAuthError(
      "invalid_grant",
      "redirect_uri does not match the one used in authorization",
    );
  }

  if (record.codeChallenge) {
    if (!codeVerifier) {
      throw new OAuthError("invalid_request", "code_verifier is required (PKCE)");
    }
    if (record.codeChallengeMethod === "S256") {
      if (!verifyPkceS256(codeVerifier, record.codeChallenge)) {
        throw new OAuthError("invalid_grant", "PKCE verification failed");
      }
    }
  }

  // Atomic CAS + token issuance. If anything throws (CAS failure, DB
  // constraint, prisma error), the whole transaction rolls back and the
  // authorization code remains usable for a retry.
  //
  // `record` is captured by closure from the read above (outside the tx).
  // The fields we use (`userId`, `scopes`) are immutable after creation
  // per the Prisma schema, so the closure capture is safe — the only
  // mutable field, `usedAt`, is protected by the CAS updateMany below.
  return prisma.$transaction(async (tx) => {
    const used = await tx.authorizationCode.updateMany({
      where: { code, usedAt: null },
      data: { usedAt: new Date() },
    });
    if (used.count === 0) {
      throw new OAuthError("invalid_grant", "Code already used");
    }
    return await issueTokenSet(record.userId, clientId, record.scopes, tx);
  });
}

async function handleRefreshToken(
  clientId: string,
  form: URLSearchParams,
) {
  const refresh = form.get("refresh_token");
  if (!refresh) {
    throw new OAuthError("invalid_request", "refresh_token is required");
  }

  const record = await prisma.refreshToken.findUnique({
    where: { token: refresh },
  });
  if (!record) throw new OAuthError("invalid_grant", "Unknown refresh token");
  if (record.expiresAt < new Date()) {
    throw new OAuthError("invalid_grant", "Refresh token expired");
  }
  if (record.clientId !== clientId) {
    throw new OAuthError("invalid_grant", "Token belongs to a different client");
  }

  // Atomic CAS + token issuance. On failure, the refresh token stays
  // un-revoked and the client can retry.
  return prisma.$transaction(async (tx) => {
    const revoked = await tx.refreshToken.updateMany({
      where: { token: refresh, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    if (revoked.count === 0) {
      throw new OAuthError(
        "invalid_grant",
        "Refresh token revoked or already rotated",
      );
    }
    return await issueTokenSet(record.userId, clientId, record.scopes, tx);
  });
}