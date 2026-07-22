/**
 * Session cookie signing/verification (HS256).
 *
 * Cookie value is a JWT (HS256) carrying `{ uid, jti }`. The JWT's signature
 * provides defense-in-depth against cookie tampering. The `jti` claim is a
 * UUID that points to a row in the `Session` DB table — THAT row is the
 * authoritative source of session validity (revokedAt, expiresAt, etc.).
 *
 * We MUST look up the DB row on every verification because revocation is
 * the whole point of this PR (issue #30, Phase 1). The JWT signature is
 * NOT a substitute for the DB check — it's an additional layer of defense
 * in case the DB is read but the HS256 secret is not leaked.
 *
 * Uses a separate symmetric secret (OAUTH_SESSION_SECRET) — completely
 * isolated from the RS256 key pair used for OAuth JWTs.
 */
import { SignJWT, jwtVerify } from "jose";
import { randomUUID } from "node:crypto";
import { prisma } from "@/lib/generated/prisma-client";
import { config } from "@/lib/config";

const DEFAULT_TTL_SECONDS = 60 * 60 * 2; // 2 hours

async function getSessionSecret(): Promise<Uint8Array> {
  return new TextEncoder().encode(config.sessionSecret);
}

export interface SignSessionOptions {
  /** Override the default 2-hour TTL. */
  ttlSeconds?: number;
  /** Client User-Agent header (for session list display + audit). */
  userAgent?: string;
  /** Client IP (for session list display + audit). Trusted-proxy assumption is the caller's responsibility. */
  ipAddress?: string;
}

/**
 * Sign a new session cookie. Persists a Session row in the DB so the
 * session can be revoked later.
 */
export async function signSessionCookie(
  userId: string,
  opts: SignSessionOptions = {},
): Promise<{ value: string; expiresAt: Date }> {
  const ttlSeconds = opts.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  const jti = randomUUID();
  const expiresAt = new Date(Date.now() + ttlSeconds * 1000);
  const secret = await getSessionSecret();

  // Write the DB row first. If this fails, the cookie is never issued —
  // no orphan JWTs referring to non-existent sessions.
  //
  // Reverse case (DB row written, .sign() throws): an orphan row exists
  // with no matching cookie. This is recoverable: the row's expiresAt
  // is set, so scripts/cleanup-tokens.ts will sweep it within 2h. Not
  // symmetric with the "no orphan JWTs" guarantee above, but acceptable
  // — sign() failures are rare (corrupted secret / jose bug) and the
  // row contains no PII.
  await prisma.session.create({
    data: {
      jti,
      userId,
      expiresAt,
      userAgent: opts.userAgent,
      ipAddress: opts.ipAddress,
    },
  });

  const value = await new SignJWT({ uid: userId, jti })
    .setProtectedHeader({ alg: "HS256", typ: "session" })
    .setIssuedAt()
    .setExpirationTime(Math.floor(expiresAt.getTime() / 1000))
    .sign(secret);

  return { value, expiresAt };
}

/**
 * Verify a session cookie. Returns `{ uid }` on success, `null` if any of:
 *   - signature verification failed (token tampered or signed with wrong key)
 *   - missing `uid` claim (applies to both tiers)
 *   - missing `jti` claim AND legacy fallback is disabled
 *   - Tier 1 (new format) rejections:
 *       - no Session row with that `jti` (never existed, or already cleaned up)
 *       - Session row exists but `expiresAt < now`
 *       - Session row exists but `revokedAt !== null`
 *       - Session row exists but `userId !== uid` from the JWT (tampering defense)
 *
 * Two-tier dispatch (issue #37, Phase 5):
 *   - Tier 1 (new format): JWT carries `jti` → DB lookup is authoritative
 *   - Tier 2 (legacy fallback): JWT lacks `jti` AND `config.sessionLegacyGracePeriod`
 *     is true → signature-only verification, no DB, not revocable. Bounded by
 *     the JWT's own `exp` claim (jose enforces it inside `jwtVerify`).
 *
 * One `jwtVerify` call is shared between both tiers — jose doesn't require
 * `jti` to be present, so the branch happens on payload shape AFTER verify.
 */
export async function verifySessionCookie(
  value: string,
): Promise<{ uid: string } | null> {
  if (!value) return null;

  let payload: { uid?: unknown; jti?: unknown };
  try {
    const secret = await getSessionSecret();
    const result = await jwtVerify(value, secret, { algorithms: ["HS256"] });
    payload = result.payload as { uid?: unknown; jti?: unknown };
  } catch {
    return null;
  }

  const { uid, jti } = payload;
  if (typeof uid !== "string") return null;

  // Tier 1: new format — DB-backed, revocable.
  if (typeof jti === "string") {
    const row = await prisma.session.findUnique({
      where: { jti },
      select: { userId: true, expiresAt: true, revokedAt: true },
    });
    if (!row) return null;
    if (row.expiresAt < new Date()) return null;
    if (row.revokedAt !== null) return null;
    if (row.userId !== uid) return null;
    return { uid };
  }

  // Tier 2: legacy fallback — signature-only, no DB lookup.
  // Read config per-call (NOT cached) — `config` is a Proxy getter and an
  // operator may toggle OAUTH_SESSION_LEGACY_GRACE at runtime.
  if (config.sessionLegacyGracePeriod) {
    return { uid };
  }

  return null;
}

/**
 * Extract the `jti` claim from a session cookie WITHOUT doing a DB lookup.
 *
 * Used by callers that need the jti to perform a targeted DB operation
 * (e.g. logout calls `prisma.session.update({ where: { jti }, data: { revokedAt } })`).
 * Performs signature verification so a tampered cookie cannot trigger a
 * revocation against an arbitrary jti, but does NOT consult the Session
 * table — so a revoked/expired cookie still yields its original jti here.
 *
 * **Legacy cookies (issue #37 Phase 5)** have no `jti` claim and no
 * Session row, so this returns `null` for them. That is correct behavior:
 * logout's DB update is a no-op for legacy cookies, but
 * `cookieStore.delete` in `app/api/auth/logout/route.ts` still clears
 * client-side state. No parallel legacy fallback is needed here — the
 * logout route already handles a `null` jti gracefully.
 *
 * Returns `null` if the cookie is malformed, has no jti, or signature
 * verification fails.
 */
export async function extractSessionJti(value: string): Promise<string | null> {
  if (!value) return null;
  try {
    const secret = await getSessionSecret();
    const { payload } = await jwtVerify(value, secret, { algorithms: ["HS256"] });
    const jti = (payload as { jti?: unknown }).jti;
    return typeof jti === "string" ? jti : null;
  } catch {
    return null;
  }
}