// This module uses node:fs + node:crypto — server-only by design. All
// importers are Server Components / Route Handlers / Server Actions.
// Do not import from a Client Component.
import { SignJWT, jwtVerify, importPKCS8, importSPKI, exportJWK } from "jose";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { uuid } from "@/lib/oauth/crypto";
import { ISSUER } from "@/lib/oauth/discovery";
const KID = "key-1";
const KEYS_PATH =
  process.env["OAUTH_KEYS_PATH"] ?? "./.oauth-keys.json";

/**
 * Fail-loud checks for production-required secrets.
 *
 * In production these MUST be set explicitly. In dev/test we fall back to a
 * placeholder so local development keeps working, but we log a warning so it
 * doesn't go unnoticed.
 */
function assertProductionSecrets(): void {
  const sessionSecret = process.env["OAUTH_SESSION_SECRET"];
  const isProd = process.env["NODE_ENV"] === "production";

  if (!sessionSecret) {
    if (isProd) {
      throw new Error(
        "OAUTH_SESSION_SECRET is required in production. " +
          "Generate one with: openssl rand -base64 48",
      );
    }
    console.warn(
      "[oauth] OAUTH_SESSION_SECRET not set — using insecure dev fallback. " +
        "DO NOT deploy without setting it.",
    );
  }
}

assertProductionSecrets();

interface PersistedKeys {
  kid: string;
  publicKey: string;
  privateKey: string;
  createdAt: string;
}

interface Keys {
  privateKey: Awaited<ReturnType<typeof importPKCS8>>;
  publicKey: Awaited<ReturnType<typeof importSPKI>>;
}

let keysPromise: Promise<Keys> | null = null;

/**
 * Load (or generate + persist) the RS256 key pair used to sign JWTs.
 *
 * In production we REQUIRE keys to be persisted so tokens survive restarts;
 * if the file is missing in production we throw. In dev we generate fresh
 * keys per process (matches the original behavior — convenient for testing).
 */
function loadKeys(): Promise<Keys> {
  if (keysPromise) return keysPromise;
  keysPromise = (async () => {
    const isProd = process.env["NODE_ENV"] === "production";

    if (existsSync(KEYS_PATH)) {
      try {
        const raw = readFileSync(KEYS_PATH, "utf8");
        const persisted = JSON.parse(raw) as PersistedKeys;
        if (
          persisted.kid &&
          persisted.publicKey &&
          persisted.privateKey &&
          persisted.publicKey.includes("BEGIN PUBLIC KEY") &&
          persisted.privateKey.includes("BEGIN PRIVATE KEY")
        ) {
          return {
            privateKey: await importPKCS8(persisted.privateKey, "RS256"),
            publicKey: await importSPKI(persisted.publicKey, "RS256"),
          };
        }
        // Malformed file — fall through and regenerate.
      } catch (err) {
        console.warn(
          `[oauth] Failed to read keys from ${KEYS_PATH}: ${err instanceof Error ? err.message : String(err)}. Regenerating.`,
        );
      }
    }

    if (isProd) {
      throw new Error(
        `OAUTH keys file not found at ${KEYS_PATH}. ` +
          "Generate one with: npm run db:keys:init",
      );
    }

    // Dev: generate + persist for stability across hot-reloads (within one
    // boot session). Next start in another process gets fresh keys.
    const { publicKey, privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    try {
      mkdirSync(dirname(KEYS_PATH), { recursive: true });
      writeFileSync(
        KEYS_PATH,
        JSON.stringify(
          {
            kid: KID,
            publicKey,
            privateKey,
            createdAt: new Date().toISOString(),
          } satisfies PersistedKeys,
          null,
          2,
        ),
        "utf8",
      );
    } catch (err) {
      console.warn(
        `[oauth] Could not persist keys to ${KEYS_PATH}: ${err instanceof Error ? err.message : String(err)}. Keys will not survive restart.`,
      );
    }

    return {
      privateKey: await importPKCS8(privateKey, "RS256"),
      publicKey: await importSPKI(publicKey, "RS256"),
    };
  })();
  return keysPromise;
}

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

/**
 * Dev-only fallback for the session-cookie HMAC secret. Shared between the
 * server (lib/oauth/jwt.ts) and the e2e test (e2e/flow.ts) so that signing
 * and verification use the same string when OAUTH_SESSION_SECRET is unset.
 *
 * NEVER use in production — `assertProductionSecrets()` enforces that.
 */
export const SESSION_COOKIE_DEV_FALLBACK =
  "dev-only-change-me-32-bytes-please-please";

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
  email: string;
  name?: string | null;
  clientId: string;
  ttlSeconds: number;
}): Promise<{ token: string; expiresAt: Date }> {
  const { privateKey } = await loadKeys();
  const now = Math.floor(Date.now() / 1000);
  const exp = now + payload.ttlSeconds;
  const builder = new SignJWT({
    email: payload.email,
    ...(payload.name ? { name: payload.name } : {}),
  })
    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: KID })
    .setIssuer(ISSUER)
    .setSubject(payload.sub)
    .setAudience(payload.clientId)
    .setIssuedAt(now)
    .setExpirationTime(exp);
  const token = await builder.sign(privateKey);
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

/** Sign the session cookie (HMAC HS256). Internal — not exposed to clients. */
async function getSessionSecret(): Promise<Uint8Array> {
  const value = process.env["OAUTH_SESSION_SECRET"] ?? SESSION_COOKIE_DEV_FALLBACK;
  return new TextEncoder().encode(value);
}

export async function signSessionCookie(
  userId: string,
  ttlSeconds = 60 * 60 * 24 * 7,
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

/** Verify a session cookie. */
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