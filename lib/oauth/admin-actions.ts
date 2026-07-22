/**
 * Admin-side mutation and query helpers for session / token revocation.
 *
 * These are the core logic behind the `/admin/users/:userId/...` routes
 * (issue #38, Phase 2 of #30). They are intentionally framework-agnostic:
 * no Request/Response handling, no auth checks, no audit logging. The
 * route handlers wire those layers on top.
 *
 * Atomicity note: every mutation uses `updateMany` with a `revokedAt: null`
 * guard so concurrent admin invocations don't double-write and a session
 * that races with the call still gets revoked (matches the CAS pattern in
 * MEMORY.md / `lib/oauth/token-service.ts`).
 */

import { prisma } from "@/lib/generated/prisma-client";

export interface RevokeAllSessionsResult {
  /** Number of sessions newly marked revoked by THIS call. */
  count: number;
}

export interface RevokeAllTokensResult {
  access: number;
  refresh: number;
}

export interface ActiveSessionInfo {
  jti: string;
  userAgent: string | null;
  ipAddress: string | null;
  createdAt: Date;
  expiresAt: Date;
}

/**
 * Mark every non-revoked session for `userId` as revoked now.
 *
 * Idempotent: if the user has zero active sessions, returns `{ count: 0 }`.
 * Does NOT throw if the user has no sessions at all — that's a valid
 * "nothing to do" state. Callers that need to distinguish "user not found"
 * from "user has no sessions" should query `prisma.user.findUnique`
 * separately first.
 */
export async function revokeAllSessionsForUser(
  userId: string,
): Promise<RevokeAllSessionsResult> {
  const result = await prisma.session.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date() },
  });
  return { count: result.count };
}

/**
 * Mark every non-revoked AccessToken + RefreshToken for `userId` as
 * revoked now. Both updates run in a single transaction so partial
 * failure can't leave tokens revoked on one side only.
 */
export async function revokeAllTokensForUser(
  userId: string,
): Promise<RevokeAllTokensResult> {
  const now = new Date();
  const [access, refresh] = await prisma.$transaction([
    prisma.accessToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: now },
    }),
    prisma.refreshToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: now },
    }),
  ]);
  return { access: access.count, refresh: refresh.count };
}

/**
 * List currently-active (non-revoked, non-expired) sessions for `userId`,
 * newest first. Useful for the admin UI / audit ("what would I be kicking
 * if I clicked this button?").
 *
 * Note: does NOT filter out the requesting admin's own session. Admins
 * revoking themselves is supported and the route handler does not need
 * special-casing.
 */
export async function listActiveSessionsForUser(
  userId: string,
): Promise<ActiveSessionInfo[]> {
  const now = new Date();
  return prisma.session.findMany({
    where: {
      userId,
      revokedAt: null,
      expiresAt: { gt: now },
    },
    select: {
      jti: true,
      userAgent: true,
      ipAddress: true,
      createdAt: true,
      expiresAt: true,
    },
    orderBy: { createdAt: "desc" },
  });
}
