/**
 * Session cookie signing/verification (HS256).
 *
 * Uses a separate symmetric secret (OAUTH_SESSION_SECRET) — completely
 * isolated from the RS256 key pair used for OAuth JWTs.
 *
 * LIMITATION: Session cookies are stateless JWTs — once issued they cannot
 * be revoked before expiry. The default TTL is intentionally short (2 hours)
 * to limit the window of abuse if a cookie is stolen. If server-side
 * revocation is required, wrap verification with a deny-list store (e.g.
 * Redis) or switch to opaque server-side sessions.
 */
import { SignJWT, jwtVerify } from "jose";
import { config } from "@/lib/config";

async function getSessionSecret(): Promise<Uint8Array> {
  return new TextEncoder().encode(config.sessionSecret);
}

export async function signSessionCookie(
  userId: string,
  ttlSeconds = 60 * 60 * 2,
): Promise<{ value: string; expiresAt: Date }> {
  const secret = await getSessionSecret();
  const now = Math.floor(Date.now() / 1000);
  const exp = now + ttlSeconds;
  const value = await new SignJWT({ uid: userId })
    .setProtectedHeader({ alg: "HS256", typ: "session" })
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(secret);
  return { value, expiresAt: new Date(exp * 1000) };
}

export async function verifySessionCookie(
  value: string,
): Promise<{ uid: string } | null> {
  try {
    const secret = await getSessionSecret();
    const { payload } = await jwtVerify(value, secret, {
      algorithms: ["HS256"],
    });
    const uid = (payload as { uid?: unknown }).uid;
    if (typeof uid !== "string") return null;
    return { uid };
  } catch {
    return null;
  }
}