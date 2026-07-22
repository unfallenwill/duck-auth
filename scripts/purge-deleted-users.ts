/**
 * Hard-delete soft-deleted users past the retention window (issue #35).
 *
 * Runs daily via cron alongside scripts/cleanup-tokens.ts. Purges users
 * whose `deletedAt < now - retentionDays`, hard-deleting them along with
 * all dependent rows (Sessions, AccessTokens, RefreshTokens, Consent,
 * AuthorizationCode) via the existing `onDelete: Cascade` foreign keys.
 *
 * Default retention: 30 days. Some jurisdictions require longer (PCI-DSS
 * can require 1 year for financial data); pass `--retention-days N` to
 * override.
 *
 * Usage:
 *   npm run db:purge-deleted-users                  # 30-day retention
 *   npm run db:purge-deleted-users -- --retention-days 90
 *   npm run db:purge-deleted-users -- --dry-run     # count only, no delete
 */
import "dotenv/config";
import { purgeDeletedUsers } from "../lib/oauth/user-deletion";

function parseArgs(): { retentionDays: number; dryRun: boolean } {
  const args = process.argv.slice(2);
  const dryRun = args.includes("--dry-run");

  const retentionIdx = args.indexOf("--retention-days");
  let retentionDays = 30;
  if (retentionIdx >= 0) {
    const v = args[retentionIdx + 1];
    if (!v) throw new Error("--retention-days requires a value");
    const n = parseInt(v, 10);
    if (!Number.isFinite(n) || n <= 0) {
      throw new Error(`--retention-days must be a positive integer, got: ${v}`);
    }
    retentionDays = n;
  }
  return { retentionDays, dryRun };
}

async function main(): Promise<void> {
  const { retentionDays, dryRun } = parseArgs();
  const cutoff = new Date(Date.now() - retentionDays * 86400_000);

  if (dryRun) {
    // Count without deleting. Uses the same query but skips the DELETE.
    const { prisma } = await import("../lib/generated/prisma-client");
    const count = await prisma.user.count({
      where: { deletedAt: { lt: cutoff, not: null } },
    });
    console.log(`[dry-run] ${count} user(s) would be purged (cutoff: ${cutoff.toISOString()}).`);
    return;
  }

  const result = await purgeDeletedUsers(retentionDays);
  console.log(
    `✓ Purged ${result.purged} user(s) deleted before ${result.cutoff.toISOString()}.`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
