/**
 * JWT signing and verification for OAuth access tokens and id tokens (RS256).
 *
 * Key management is delegated to lib/oauth/keys.ts.
 * Session cookie logic is in lib/oauth/session.ts.
 */
import { SignJWT, jwtVerify, exportJWK } from "jose";
import { uuid } from "@/lib/oauth/crypto";
import { ISSUER } from "@/lib/oauth/discovery";
import { loadKeys, KID } from "@/lib/oauth/keys";

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

/** Sign an access token (JWT, RS256). */
export async function signAccessToken(payload: {
  sub: string;
  clientId: string;
  scopes: string;
  ttlSeconds: number;
  jti?: string;
}): Promise<{ token: string; jti: string; expiresAt: Date }> {
  const { privateKey } = await loadKeys();
  const jti = payload.jti ?? uuid();
  const now = Math.floor(Date.now() / 1000);
  const exp = now + payload.ttlSeconds;

  const token = await new SignJWT({
    client_id: payload.clientId,
    scope: payload.scopes,
    jti,
  })
    .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: KID })
    .setIssuer(ISSUER)
    .setSubject(payload.sub)
    .setAudience(payload.clientId)
    .setJti(jti)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(privateKey);

  return { token, jti, expiresAt: new Date(exp * 1000) };
}

/** Sign an id_token (OIDC). */
export async function signIdToken(payload: {
  sub: string;
  email?: string;
  name?: string | null;
  clientId: string;
  ttlSeconds: number;
}): Promise<{ token: string; expiresAt: Date }> {
  const { privateKey } = await loadKeys();
  const now = Math.floor(Date.now() / 1000);
  const exp = now + payload.ttlSeconds;
  const token = await new SignJWT({
    ...(payload.email ? { email: payload.email } : {}),
    ...(payload.name ? { name: payload.name } : {}),
  })
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: KID })
    .setIssuer(ISSUER)
    .setSubject(payload.sub)
    .setAudience(payload.clientId)
    .setIssuedAt(now)
    .setExpirationTime(exp)
    .sign(privateKey);
  return { token, expiresAt: new Date(exp * 1000) };
}

/** Verify an access token. */
export async function verifyAccessToken(
  token: string,
): Promise<AccessTokenClaims> {
  const { publicKey } = await loadKeys();
  const { payload } = await jwtVerify(token, publicKey, {
    issuer: ISSUER,
    algorithms: ["RS256"],
  });
  return payload as unknown as AccessTokenClaims;
}

/** Return JWKS for /.well-known/jwks.json */
export async function getJwks() {
  const { publicKey } = await loadKeys();
  const jwk = await exportJWK(publicKey);
  return {
    keys: [
      {
        ...jwk,
        kid: KID,
        use: "sig",
        alg: "RS256",
      },
    ],
  };
}