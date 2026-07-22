/**
 * Delete expired tokens from the DB.
 *
 * Run via cron / scheduled task:
 *   0 3 * * *  cd /app && npm run db:cleanup
 *
 * Idempotent and safe to run multiple times. Reports counts so a cron log
 * is meaningful.
 */
import "dotenv/config";
import { PrismaClient } from "../lib/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";

import { config } from "../lib/config";

const adapter = new PrismaLibSql({ url: config.databaseUrl });
const prisma = new PrismaClient({ adapter });

async function main() {
  const now = new Date();

  const [codes, access, refresh, sessions] = await Promise.all([
    prisma.authorizationCode.deleteMany({
      where: { expiresAt: { lt: now } },
    }),
    prisma.accessToken.deleteMany({
      where: { expiresAt: { lt: now } },
    }),
    prisma.refreshToken.deleteMany({
      where: { expiresAt: { lt: now } },
    }),
    prisma.session.deleteMany({
      where: { expiresAt: { lt: now } },
    }),
  ]);

  console.log(`[${now.toISOString()}] cleanup:`);
  console.log(`  authorization codes deleted: ${codes.count}`);
  console.log(`  access tokens deleted:       ${access.count}`);
  console.log(`  refresh tokens deleted:      ${refresh.count}`);
  console.log(`  sessions deleted:            ${sessions.count}`);

  await prisma.$disconnect();
}

main().catch(async (err) => {
  console.error("[cleanup] failed:", err);
  await prisma.$disconnect();
  process.exit(1);
});