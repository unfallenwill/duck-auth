/**
 * POST /admin/users/:userId/tokens/revoke-all
 *
 * Revokes every non-revoked AccessToken + RefreshToken for the user.
 * The user keeps their session cookie but every subsequent `/oauth/userinfo`
 * call fails (DB sees revokedAt) and `/oauth/token` won't issue fresh
 * tokens until they log in again (refresh tokens are dead).
 *
 * Typically used alongside `/sessions/revoke-all` — kicking the user out
 * AND invalidating any tokens already distributed to relying parties.
 *
 * Issue #38, Phase 2 of #30. Auth: X-Admin-Token header (Option A).
 */
import { NextResponse } from "next/server";
import { prisma } from "@/lib/generated/prisma-client";
import {
  checkAdminToken,
  adminAuthErrorResponse,
} from "@/lib/oauth/admin-auth";
import { revokeAllTokensForUser } from "@/lib/oauth/admin-actions";
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

  const { access, refresh } = await revokeAllTokensForUser(userId);

  audit({
    actor: auth.actor,
    action: "admin.tokens.revoke_all",
    target: userId,
    metadata: { revoked_access: access, revoked_refresh: refresh },
  });

  return NextResponse.json({ userId, revoked_access: access, revoked_refresh: refresh });
}
