/**
 * POST /admin/users/:userId/sessions/revoke-all
 *
 * Force-logs the user out of every active session. After this call, any
 * existing `oauth_session` cookie for this user fails
 * `verifySessionCookie` (Tier 1 DB check sees revokedAt != null) and any
 * `/oauth/authorize` request redirects to /login.
 *
 * Issue #38, Phase 2 of #30. Auth: X-Admin-Token header (Option A).
 */
import { NextResponse } from "next/server";
import { prisma } from "@/lib/generated/prisma-client";
import {
  checkAdminToken,
  adminAuthErrorResponse,
} from "@/lib/oauth/admin-auth";
import { revokeAllSessionsForUser } from "@/lib/oauth/admin-actions";
import { audit } from "@/lib/audit";

export async function POST(
  req: Request,
  ctx: { params: Promise<{ userId: string }> },
) {
  const auth = checkAdminToken(req);
  const err = adminAuthErrorResponse(auth);
  if (err) return err;

  const { userId } = await ctx.params;

  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: { id: true },
  });
  if (!user) {
    return NextResponse.json(
      { error: "not_found", error_description: "User not found." },
      { status: 404 },
    );
  }

  const { count } = await revokeAllSessionsForUser(userId);

  // Audit AFTER the mutation succeeds — log the actual outcome, not the
  // intent. Failed mutations throw and never reach this line.
  audit({
    actor: auth.actor,
    action: "admin.sessions.revoke_all",
    target: userId,
    metadata: { revoked: count },
  });

  return NextResponse.json({ userId, revoked: count });
}
