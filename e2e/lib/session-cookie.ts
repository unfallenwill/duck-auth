/**
 * Shared helper for e2e tests: create a real Session row in the DB and
 * sign a JWT cookie that the production verifySessionCookie will accept.
 *
 * Issue #30 Phase 1 made sessions DB-backed: any JWT cookie must carry a
 * `jti` claim that exists as a Session row in the DB, otherwise
 * verifySessionCookie returns null. Tests that previously signed raw JWTs
 * (no jti, no DB row) must use this helper instead.
 */
import { randomUUID } from "node:crypto";
import { SignJWT } from "jose";
import { PrismaClient } from "../../lib/generated/prisma/client";
import { PrismaLibSql } from "@prisma/adapter-libsql";
import { SESSION_COOKIE_DEV_FALLBACK } from "../../lib/config";

const secret = new TextEncoder().encode(
  process.env["OAUTH_SESSION_SECRET"] ?? SESSION_COOKIE_DEV_FALLBACK,
);

export async function createSessionCookie(
  userId: string,
  ttlSeconds = 60 * 60,
): Promise<string> {
  const jti = randomUUID();
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);

  const prisma = new PrismaClient({
    adapter: new PrismaLibSql({
      url: process.env["DATABASE_URL"] ?? "file:./dev.db",
    }),
  });
  await prisma.session.create({
    data: { jti, userId, expiresAt },
  });
  await prisma.$disconnect();

  const now = Math.floor(Date.now() / 1000);
  return await new SignJWT({ uid: userId, jti })
    .setProtectedHeader({ alg: "HS256", typ: "session" })
    .setIssuedAt(now)
    .setExpirationTime(now + ttlSeconds)
    .sign(secret);
}