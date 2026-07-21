import { cookies } from "next/headers";

const ISSUER = process.env["OAUTH_ISSUER"] ?? "http://localhost:3000";

/**
 * GET /api/auth/me
 * Uses the stored access_token to call /oauth/userinfo.
 * Returns 401 if no token; calls server-side so the token never leaves the
 * server boundary.
 */
export async function GET() {
  const cookieStore = await cookies();
  const token = cookieStore.get("oauth_access_token")?.value;

  if (!token) {
    return Response.json({ error: "not_authenticated" }, { status: 401 });
  }

  const res = await fetch(`${ISSUER}/oauth/userinfo`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  });

  if (res.status === 401) {
    return Response.json({ error: "token_invalid" }, { status: 401 });
  }
  if (!res.ok) {
    return Response.json(
      { error: "userinfo_failed", status: res.status },
      { status: 502 },
    );
  }

  const userinfo = await res.json();
  return Response.json(userinfo);
}