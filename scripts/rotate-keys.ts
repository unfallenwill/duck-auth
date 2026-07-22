/**
 * Rotate the OAuth signing key set (issue #31).
 *
 * - Generates a new primary key pair.
 * - Demotes the current primary to retired with a grace window.
 * - Old tokens (signed with the previous kid) keep verifying until the
 *   grace window expires, after which `--purge` removes them.
 *
 * Usage:
 *   npm run db:keys:rotate                      # default 7-day grace
 *   npm run db:keys:rotate -- --grace 14d       # custom grace (d/h/m/s)
 *   npm run db:keys:rotate -- --grace 3600      # 1 hour in seconds
 *   npm run db:keys:rotate -- --purge           # remove expired retired keys
 *   npm run db:keys:rotate -- --status          # show current key set
 *
 * The script rewrites the keys file. The server's cached key set becomes
 * stale after the rewrite; in production, restart the server (or implement
 * in-process cache invalidation via SIGHUP) so subsequent requests load
 * the new primary.
 *
 * Idempotent: `--purge` is safe to run repeatedly.
 */
import "dotenv/config";
import {
  loadKeys,
  rotateKeys,
  purgeExpiredRetiredKeys,
} from "../lib/oauth/keys";

function parseGrace(input: string): number {
  const m = input.match(/^(\d+)([smhd])?$/);
  if (!m) {
    throw new Error(
      `Invalid --grace value: ${input}. Use a number with optional unit (s/m/h/d), e.g. 7d, 3600s, 24h.`,
    );
  }
  const n = parseInt(m[1]!, 10);
  const unit = m[2] ?? "s";
  switch (unit) {
    case "s":
      return n;
    case "m":
      return n * 60;
    case "h":
      return n * 3600;
    case "d":
      return n * 86400;
    default:
      throw new Error(`Unknown grace unit: ${unit}`);
  }
}

function printStatus(): void {
  // Wrap in async IIFE so we can use await at top level.
  void (async () => {
    const keys = await loadKeys();
    console.log("=== Current OAuth signing key set ===");
    console.log(`primary: ${keys.primaryKid}`);
    console.log(`  createdAt: ${keys.primary.createdAt}`);
    console.log(`retired: ${keys.retired.length} key(s)`);
    for (const r of keys.retired) {
      const until = r.retiredAt ?? "(no expiry)";
      console.log(`  - ${r.kid}  createdAt=${r.createdAt}  retiredAt=${until}`);
    }
    console.log(`JWKS publishes ${keys.jwks.length} key(s).`);
  })();
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);

  if (args.includes("--status")) {
    printStatus();
    return;
  }

  if (args.includes("--purge")) {
    const { purged } = await purgeExpiredRetiredKeys();
    if (purged === 0) {
      console.log("No expired retired keys to purge.");
    } else {
      console.log(`✓ Purged ${purged} expired retired key(s).`);
    }
    return;
  }

  const graceIdx = args.indexOf("--grace");
  const graceInput = graceIdx >= 0 ? args[graceIdx + 1] : "7d";
  const graceSeconds = parseGrace(graceInput);

  const before = await loadKeys();
  console.log("=== Pre-rotation state ===");
  console.log(`primary: ${before.primaryKid}`);
  console.log(`retired: ${before.retired.length} key(s)`);
  console.log("");

  const result = await rotateKeys({ graceSeconds });

  console.log("✓ Rotated.");
  console.log(`  previous primary (now retired): ${result.previousKid}`);
  console.log(`  new primary:                    ${result.newKid}`);
  console.log(`  grace window until:             ${result.retiredUntil}`);
  console.log("");
  console.log("Next steps:");
  console.log("  1. Restart the server so it loads the new primary.");
  console.log("  2. New tokens are signed with the new kid.");
  console.log(
    `  3. Tokens signed with ${result.previousKid} keep verifying until ${result.retiredUntil}.`,
  );
  console.log(
    `  4. After ${result.retiredUntil}, run \`npm run db:keys:rotate -- --purge\` to drop the retired entry.`,
  );
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
