/**
 * GDPR right-to-erasure (issue #35, Phase 4 of #30).
 *
 * Soft delete:
 *   - Set `User.deletedAt = now`
 *   - Anonymize PII (email, name, passwordHash)
 *   - Mark all Sessions / AccessTokens / RefreshTokens revoked (DB already
 *     cascades lookups, so subsequent requests fail immediately)
 *   - Hard-delete Consent rows (per-user-per-client, no retention needed)
 *
 * All in a single transaction so partial failure can't leave the user
 * half-deleted.
 *
 * After this runs:
 *   - Old session cookies fail `verifySessionCookie` (Tier 1 DB lookup
 *     sees `revokedAt` set) → user is effectively logged out
 *   - Refresh attempts fail at CAS (`revokedAt` already set)
 *   - Login with the original email succeeds for a NEW user (the email
 *     constraint is on the anonymized string now, not the original)
 *   - The old User row stays for the retention window so audit logs /
 *     DSR responses can still reference the user; the daily purge script
 *     hard-deletes after the retention window.
 */
import { createHash } from "node:crypto";
import { prisma } from "@/lib/generated/prisma-client";

const ANON_EMAIL_DOMAIN = "example.invalid";

/**
 * Deterministic, irreversible anonymization for the email field. Same input
 * always produces the same anonymized string (idempotency on repeat
 * deletes), but the original email cannot be recovered.
 */
function anonymizeEmail(original: string): string {
  const hash = createHash("sha256")
    .update(original.toLowerCase())
    .digest("hex")
    .slice(0, 32);
  return `deleted-${hash}@${ANON_EMAIL_DOMAIN}`;
}

export interface DeleteUserResult {
  userId: string;
  anonymizedEmail: string;
  revokedSessions: number;
  revokedAccessTokens: number;
  revokedRefreshTokens: number;
  deletedConsents: number;
  deletedAt: Date;
}

/**
 * Soft-delete a user and cascade-revoke their sessions/tokens.
 * Throws if the user doesn't exist. Idempotent: re-running on a
 * already-deleted user is a no-op (returns zeros for the revoked counts).
 */
export async function deleteCurrentUser(userId: string): Promise<DeleteUserResult> {
  return await prisma.$transaction(async (tx) => {
    const user = await tx.user.findUnique({
      where: { id: userId },
      select: { id: true, email: true, deletedAt: true },
    });
    if (!user) {
      throw new Error(`User not found: ${userId}`);
    }

    // Idempotency: if already deleted, return zeros without re-mutating.
    if (user.deletedAt) {
      return {
        userId,
        anonymizedEmail: user.email,
        revokedSessions: 0,
        revokedAccessTokens: 0,
        revokedRefreshTokens: 0,
        deletedConsents: 0,
        deletedAt: user.deletedAt,
      };
    }

    const now = new Date();
    const anonymizedEmail = anonymizeEmail(user.email);

    // Revoke all active sessions (Tier 1 DB check rejects revoked sessions
    // regardless of JWT signature validity).
    const sessionsResult = await tx.session.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: now },
    });

    // Revoke all active OAuth tokens. Run both updates in the same
    // transaction so partial failure can't leave one side revoked only.
    const [accessResult, refreshResult] = await Promise.all([
      tx.accessToken.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: now },
      }),
      tx.refreshToken.updateMany({
        where: { userId, revokedAt: null },
        data: { revokedAt: now },
      }),
    ]);

    // Hard-delete consents — they're per-user-per-client and have no
    // audit value once the user is gone.
    const consentsResult = await tx.consent.deleteMany({
      where: { userId },
    });

    // Soft-delete the user + anonymize PII. Empty passwordHash makes
    // password-based login impossible (bcrypt compare against "" fails).
    await tx.user.update({
      where: { id: userId },
      data: {
        deletedAt: now,
        email: anonymizedEmail,
        name: null,
        passwordHash: "",
      },
    });

    return {
      userId,
      anonymizedEmail,
      revokedSessions: sessionsResult.count,
      revokedAccessTokens: accessResult.count,
      revokedRefreshTokens: refreshResult.count,
      deletedConsents: consentsResult.count,
      deletedAt: now,
    };
  });
}

/**
 * Hard-delete users whose `deletedAt < cutoff`. Returns the number of
 * users purged. Cascades remove all dependent Sessions/Tokens/Consents
 * via the existing `onDelete: Cascade` foreign keys.
 *
 * Default cutoff = 30 days ago. Some jurisdictions require longer
 * retention; operators can pass `retentionDays` to override.
 */
export async function purgeDeletedUsers(
  retentionDays: number = 30,
): Promise<{ purged: number; cutoff: Date }> {
  const cutoff = new Date(Date.now() - retentionDays * 86400_000);
  // Hard delete: prisma cascades to Sessions, AccessTokens, RefreshTokens,
  // AuthorizationCodes, Consent (all have onDelete: Cascade on userId).
  const result = await prisma.user.deleteMany({
    where: { deletedAt: { lt: cutoff, not: null } },
  });
  return { purged: result.count, cutoff };
}
