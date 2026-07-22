/**
 * JWT signing and verification for OAuth access tokens and id tokens (RS256).
 *
 * Key management is delegated to lib/oauth/keys.ts.
 * Session cookie logic is in lib/oauth/session.ts.
 *
 * Multi-key support (issue #31):
 * - Sign always uses the primary key (loadKeys().signingKey) and sets
 *   `kid` in the JWT header.
 * - Verify reads `kid` from the JWT header and looks up the matching
 *   key in `loadKeys().verificationKeys` (primary + non-expired retired).
 * - JWKS endpoint returns all non-expired keys (primary + retired).
 */
import { SignJWT, jwtVerify } from "jose";
import { uuid } from "@/lib/oauth/crypto";
import { ISSUER } from "@/lib/oauth/discovery";
import { loadKeys } from "@/lib/oauth/keys";

export interface AccessTokenClaims {
  sub: string;
  client_id: string;
  aud: string;
  scope: string;
  jti: string;
  iat: number;
  exp: number;
  iss: string;
}

/** Sign an access token (JWT, RS256). Uses the current primary key. */
export async function signAccessToken(payload: {
  sub: string;
  clientId: string;
  scopes: string;
  ttlSeconds: number;
  jti?: string;
}): Promise<{ token: string; jti: string; expiresAt: Date }> {
  const { signingKey, primaryKid } = await loadKeys();
  const jti = payload.jti ?? uuid();
  const now = Math.floor(Date.now() / 1000);
  const exp = now + payload.ttlSeconds;

  const token = await new SignJWT({
    client_id: payload.clientId,
    scope: payload.scopes,
    jti,
  })
    .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: primaryKid })
    .setIssuer(ISSUER)
    .setSubject(payload.sub)
    .setAudience(payload.clientId)
    .setJti(jti)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(signingKey);

  return { token, jti, expiresAt: new Date(exp * 1000) };
}

/** Sign an id_token (OIDC). Uses the current primary key. */
export async function signIdToken(payload: {
  sub: string;
  email?: string;
  name?: string | null;
  clientId: string;
  ttlSeconds: number;
}): Promise<{ token: string; expiresAt: Date }> {
  const { signingKey, primaryKid } = await loadKeys();
  const now = Math.floor(Date.now() / 1000);
  const exp = now + payload.ttlSeconds;
  const token = await new SignJWT({
    ...(payload.email ? { email: payload.email } : {}),
    ...(payload.name ? { name: payload.name } : {}),
  })
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: primaryKid })
    .setIssuer(ISSUER)
    .setSubject(payload.sub)
    .setAudience(payload.clientId)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(signingKey);
  return { token, expiresAt: new Date(exp * 1000) };
}

/**
 * Verify an access token. Reads `kid` from the JWT header and looks up
 * the matching key in the verification map. Throws if the kid is missing,
 * unknown, or the signature doesn't verify.
 */
export async function verifyAccessToken(
  token: string,
): Promise<AccessTokenClaims> {
  const { verificationKeys, primaryKid } = await loadKeys();
  const { payload } = await jwtVerify(
    token,
    async (header) => {
      const kid = header.kid;
      if (!kid) {
        // Backward compat: tokens issued before #31 had a hardcoded kid,
        // but if any caller ever produces a token without one, fall back
        // to the primary. Better than rejecting outright during migration.
        const fallback = verificationKeys.get(primaryKid);
        if (!fallback) {
          throw new Error("No kid in token header and primary key unavailable");
        }
        return fallback;
      }
      const key = verificationKeys.get(kid);
      if (!key) {
        throw new Error(`Unknown signing key kid: ${kid}`);
      }
      return key;
    },
    { issuer: ISSUER, algorithms: ["RS256"] },
  );
  return payload as unknown as AccessTokenClaims;
}

/** Return JWKS for /.well-known/jwks.json — primary + retired. */
export async function getJwks() {
  const { jwks } = await loadKeys();
  return { keys: jwks };
}
