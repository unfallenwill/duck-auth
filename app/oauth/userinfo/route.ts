import { prisma } from "@/lib/generated/prisma-client";
import { verifyAccessToken } from "@/lib/oauth/jwt";
import { tokenError } from "@/lib/oauth/errors";
import { parseScopes } from "@/lib/oauth/discovery";

export async function GET(req: Request) {
  const auth = req.headers.get("authorization") ?? "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    return tokenError("invalid_request", "Missing Bearer token", 401);
  }
  const token = m[1]!;

  let claims;
  try {
    claims = await verifyAccessToken(token);
  } catch {
    return tokenError("invalid_grant", "Invalid or expired token", 401);
  }

  // Check revocation in DB.
  const stored = await prisma.accessToken.findUnique({
    where: { jti: claims.jti },
  });
  if (!stored || stored.revokedAt) {
    return tokenError("invalid_grant", "Token revoked", 401);
  }
  if (stored.expiresAt < new Date()) {
    return tokenError("invalid_grant", "Token expired", 401);
  }

  const user = await prisma.user.findUnique({ where: { id: claims.sub } });
  if (!user) return tokenError("server_error", "User missing", 500);

  const scopes = parseScopes(claims.scope);
  const out: Record<string, unknown> = { sub: user.id };
  if (scopes.includes("email")) {
    out["email"] = user.email;
    // No email-verification flow exists yet. Per OIDC Core §5.1, this claim
    // MUST be true ONLY when the address has been verified; we conservatively
    // return false until verification is implemented. RPs must not use the
    // email until verification is added.
    out["email_verified"] = false;
  }
  if (scopes.includes("profile")) {
    out["name"] = user.name;
  }

  return Response.json(out, {
    headers: { "Cache-Control": "no-store" },
  });
}