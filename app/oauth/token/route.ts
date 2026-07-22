import { prisma } from "@/lib/generated/prisma-client";
import { OAuthError, tokenError } from "@/lib/oauth/errors";
import { verifyPkceS256 } from "@/lib/oauth/crypto";
import { authenticateClient } from "@/lib/oauth/client-auth";
import { readFormBody } from "@/lib/oauth/http";
import { tokenRateLimit } from "@/lib/oauth/rate-limit";
import {
  exchangeAuthorizationCode,
  exchangeRefreshToken,
  tokenSetResponse,
} from "@/lib/oauth/token-service";

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

  // Delegate validation + atomic CAS + token issuance to the shared
  // service helper (same code path used by the in-process oauth-client
  // wrapper, see lib/oauth-client.ts).
  const data = await exchangeAuthorizationCode({
    code,
    redirectUri,
    codeVerifier,
    clientId,
    authorizationCode: record,
    verifyPkceS256,
  });
  return tokenSetResponse(data);
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

  const data = await exchangeRefreshToken({
    refreshToken: refresh,
    clientId,
    refreshTokenRecord: record,
  });
  return tokenSetResponse(data);
}
