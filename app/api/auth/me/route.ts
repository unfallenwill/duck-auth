import { cookies } from "next/headers";
import { userinfo } from "@/lib/oauth-client";

/**
 * GET /api/auth/me
 * Uses the stored access_token to fetch OIDC userinfo (in-process).
 * Returns 401 if no token or token is invalid/expired/revoked.
 *
 * Issue #29: was `fetch(${ISSUER}/oauth/userinfo, ...)` — same process,
 * extra HTTP roundtrip + ISSUER env coupling. Now uses the in-process
 * `userinfo` wrapper which calls the service helper directly.
 */
export async function GET() {
  const cookieStore = await cookies();
  const token = cookieStore.get("oauth_access_token")?.value;

  if (!token) {
    return Response.json({ error: "not_authenticated" }, { status: 401 });
  }

  const claims = await userinfo(token);
  if (!claims) {
    return Response.json({ error: "token_invalid" }, { status: 401 });
  }

  return Response.json(claims);
}
