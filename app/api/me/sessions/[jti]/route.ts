/**
 * DELETE /api/me/sessions/:jti  — revoke one of my sessions
 *
 * Issue #34, Phase 3 of #30. User self-service session management.
 *
 * Auth: session cookie (existing `verifySessionCookie` pattern).
 * Authorization: the session being revoked MUST belong to the calling
 * user. The `userId` guard in `revokeSessionByJti` enforces this — if
 * the jti exists but belongs to another user, the response is 404
 * (not 403) to avoid leaking session existence across users.
 *
 * After this call, the revoked session cookie fails `verifySessionCookie`
 * on the next request → `/oauth/authorize` redirects to `/login`.
 * Sessions not in the revoked set (other devices) keep working.
 */
import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { verifySessionCookie } from "@/lib/oauth/session";
import { revokeSessionByJti } from "@/lib/oauth/admin-actions";
import { audit } from "@/lib/audit";

export async function DELETE(
  _req: Request,
  ctx: { params: Promise<{ jti: string }> },
) {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("oauth_session")?.value;

  if (!sessionCookie) {
    return NextResponse.json(
      { error: "unauthorized", error_description: "No session cookie." },
      { status: 401 },
    );
  }
  const session = await verifySessionCookie(sessionCookie);
  if (!session) {
    return NextResponse.json(
      { error: "unauthorized", error_description: "Invalid or expired session." },
      { status: 401 },
    );
  }

  const { jti } = await ctx.params;
  const { revoked } = await revokeSessionByJti(session.uid, jti);

  if (!revoked) {
    // Either jti doesn't exist, belongs to another user, or was already
    // revoked. All three are 404 from the caller's perspective — don't
    // leak which one applies.
    return NextResponse.json(
      { error: "not_found", error_description: "Session not found." },
      { status: 404 },
    );
  }

  audit({
    actor: "self",
    action: "user.session.revoke_one",
    target: jti,
    metadata: { user_id: session.uid },
  });

  return NextResponse.json({ revoked: true, jti });
}
