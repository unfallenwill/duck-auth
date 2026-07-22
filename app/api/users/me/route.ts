/**
 * DELETE /api/users/me
 *
 * GDPR right-to-erasure (issue #35, Phase 4 of #30). The user invokes
 * this to delete their own account + all associated data.
 *
 * Auth: requires a valid session cookie (existing `verifySessionCookie`
 * pattern; same as `/api/auth/logout`). No admin token — this is the
 * user's own action, not admin-initiated.
 *
 * Behavior (see lib/oauth/user-deletion.ts for details):
 *   1. Soft-delete User (set deletedAt)
 *   2. Anonymize PII (email, name, passwordHash)
 *   3. Mark all sessions/tokens revoked
 *   4. Hard-delete Consent rows
 * All in a single transaction.
 *
 * After this returns 204:
 *   - The session cookie is revoked (next /oauth/authorize redirects to
 *     /login). The client should clear its local cookies.
 *   - The hard-delete (cascade) runs after the retention window via
 *     scripts/purge-deleted-users.ts.
 *
 * Audit: logged with actor="self" since this is the user's own action
 * (no admin identity to attribute). Distinct from admin actions, which
 * use actor=admin or actor=env-token.
 */
import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { verifySessionCookie } from "@/lib/oauth/session";
import { deleteCurrentUser } from "@/lib/oauth/user-deletion";
import { audit } from "@/lib/audit";

export async function DELETE() {
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

  const result = await deleteCurrentUser(session.uid);

  audit({
    actor: "self",
    action: "user.delete_self",
    target: result.userId,
    metadata: {
      revoked_sessions: result.revokedSessions,
      revoked_access_tokens: result.revokedAccessTokens,
      revoked_refresh_tokens: result.revokedRefreshTokens,
      deleted_consents: result.deletedConsents,
      anonymized_email: result.anonymizedEmail,
    },
  });

  return new NextResponse(null, { status: 204 });
}
