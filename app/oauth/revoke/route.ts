import { prisma } from "@/lib/generated/prisma-client";
import { authenticateClient } from "@/lib/oauth/client-auth";
import { readFormBody } from "@/lib/oauth/http";
import { revokeRateLimit } from "@/lib/oauth/rate-limit";

/**
 * POST /oauth/revoke (RFC 7009).
 *
 * Client authentication is REQUIRED per RFC 7009 §2.1. If auth fails, we
 * silently return 200 (per RFC 7009 §2.2 we never leak whether a token
 * existed).
 *
 * Either token type can be revoked. For refresh tokens (opaque strings),
 * we look them up directly. For access tokens (JWT), we decode without
 * verifying (the DB is the source of truth for revocation status — the
 * signature only proves the token was once valid).
 *
 * Per RFC 7009 §2.2 we always return 200, even for unknown tokens, to
 * avoid leaking information.
 */
export async function POST(req: Request) {
  if (!revokeRateLimit(req)) {
    return new Response(
      JSON.stringify({ error: "rate_limited", error_description: "Too many requests" }),
      { status: 429, headers: { "Retry-After": "60" } },
    );
  }
  const form = await readFormBody(req);

  // Client authentication is required. If it fails, we return 200 without
  // revoking anything — silently rejecting prevents enumeration attacks.
  const auth = await authenticateClient(req, form);
  if (!auth) {
    return new Response(null, { status: 200 });
  }
  const clientId = auth.clientId;

  const token = form.get("token");
  if (typeof token !== "string" || !token) {
    return Response.json(
      { error: "invalid_request", error_description: "token is required" },
      { status: 400 },
    );
  }

  // Path 1: refresh token (opaque string, looked up directly). Must belong
  // to the authenticated client.
  const refresh = await prisma.refreshToken.findUnique({ where: { token } });
  if (refresh && refresh.clientId === clientId && !refresh.revokedAt) {
    await prisma.refreshToken.update({
      where: { token },
      data: { revokedAt: new Date() },
    });
  }

  // Path 2: access token (JWT). Decode without verify, look up by jti.
  // Only catch parse/decode errors (malformed token) — let DB errors
  // propagate so they surface as 500s rather than silently failing.
  let jti: string | undefined;
  try {
    const parts = token.split(".");
    if (parts.length === 3) {
      const payload = JSON.parse(
        Buffer.from(parts[1]!, "base64url").toString("utf8"),
      );
      if (typeof payload.jti === "string") {
        jti = payload.jti;
      }
    }
  } catch {
    // Malformed token — per RFC 7009 §2.2, return 200 without leaking.
    return new Response(null, { status: 200 });
  }

  if (jti) {
    const access = await prisma.accessToken.findUnique({ where: { jti } });
    if (access && access.clientId === clientId && !access.revokedAt) {
      await prisma.accessToken.update({
        where: { jti },
        data: { revokedAt: new Date() },
      });
    }
  }

  return new Response(null, { status: 200 });
}