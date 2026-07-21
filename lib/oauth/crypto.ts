import {
  randomBytes,
  randomUUID,
  scryptSync,
  timingSafeEqual,
  createHash,
} from "node:crypto";

const SCRYPT_KEYLEN = 64;
const N = 16384; // CPU/memory cost
const r = 8; // block size
const p = 1; // parallelization

/** Hash a password using scrypt with a random salt. Format: "scrypt$N$r$p$salt$hash" */
export function hashPassword(password: string): string {
  const salt = randomBytes(16).toString("hex");
  const derived = scryptSync(password, salt, SCRYPT_KEYLEN, {
    N,
    r,
    p,
  }).toString("hex");
  return `scrypt$${N}$${r}$${p}$${salt}$${derived}`;
}

/** Verify a password against a stored hash. Constant-time comparison. */
export function verifyPassword(password: string, stored: string): boolean {
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  const [, nStr, rStr, pStr, salt, expected] = parts;
  const N_ = Number(nStr);
  const r_ = Number(rStr);
  const p_ = Number(pStr);
  if (!N_ || !r_ || !p_ || !salt || !expected) return false;
  const derived = scryptSync(password, salt, SCRYPT_KEYLEN, {
    N: N_,
    r: r_,
    p: p_,
  });
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(derived);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/** Cryptographically-secure random URL-safe string. Default 32 bytes → 43 chars. */
export function randomToken(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

/** UUID v4 — used as jti for access tokens. */
export function uuid(): string {
  return randomUUID();
}

/**
 * PKCE verification per RFC 7636 (S256 only — plain is deprecated).
 * code_verifier must match: 43-128 chars from [A-Z][a-z][0-9]-._~
 */
export function verifyPkceS256(
  codeVerifier: string,
  codeChallenge: string,
): boolean {
  const hash = createHash("sha256").update(codeVerifier).digest("base64url");
  return timingSafeEqual(Buffer.from(hash), Buffer.from(codeChallenge));
}

/** Generate a code_verifier (43-128 chars from [A-Z][a-z][0-9]-._~). */
export function generateCodeVerifier(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

/** Compute S256 code_challenge from a verifier. */
export function codeChallengeS256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

/** Hash a client_secret for storage. Same format as password but tagged. */
export function hashClientSecret(secret: string): string {
  return hashPassword(secret);
}

export function verifyClientSecret(secret: string, stored: string): boolean {
  return verifyPassword(secret, stored);
}