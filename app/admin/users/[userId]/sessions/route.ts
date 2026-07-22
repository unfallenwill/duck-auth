/**
 * GET /admin/users/:userId/sessions
 *
 * Lists the user's currently-active (non-revoked, non-expired) sessions.
 * Used by the admin UI to show "what would be kicked if I clicked revoke".
 *
 * Issue #38, Phase 2 of #30. Auth: X-Admin-Token header (Option A).
 */
import { NextResponse } from "next/server";
import { prisma } from "@/lib/generated/prisma-client";
import {
  checkAdminToken,
  adminAuthErrorResponse,
} from "@/lib/oauth/admin-auth";
import { listActiveSessionsForUser } from "@/lib/oauth/admin-actions";

export async function GET(
  req: Request,
  ctx: { params: Promise<{ userId: string }> },
) {
  const auth = checkAdminToken(req);
  const err = adminAuthErrorResponse(auth);
  if (err) return err;

  const { userId } = await ctx.params;

  // Confirm user exists — distinguish "user not found" (404) from
  // "user has no active sessions" (200 with empty array).
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

  const sessions = await listActiveSessionsForUser(userId);
  return NextResponse.json({
    userId,
    sessions: sessions.map((s) => ({
      jti: s.jti,
      userAgent: s.userAgent,
      ipAddress: s.ipAddress,
      createdAt: s.createdAt.toISOString(),
      expiresAt: s.expiresAt.toISOString(),
    })),
  });
}
