import { tokenError } from "@/lib/oauth/errors";
import { getUserInfo } from "@/lib/oauth/token-service";

/**
 * GET /oauth/userinfo (OIDC Core §5.3).
 *
 * Delegates claim assembly to the shared `getUserInfo` helper used by
 * the in-process oauth-client wrapper (see lib/oauth-client.ts).
 */
export async function GET(req: Request) {
  const auth = req.headers.get("authorization") ?? "";
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (!m) {
    return tokenError("invalid_request", "Missing Bearer token", 401);
  }
  const token = m[1]!;

  const claims = await getUserInfo(token);
  if (!claims) {
    return tokenError("invalid_grant", "Invalid, expired, or revoked token", 401);
  }

  return Response.json(claims, {
    headers: { "Cache-Control": "no-store" },
  });
}
