/**
 * RSA key pair management for JWT signing (RS256).
 *
 * Multi-key support (issue #31):
 * - Storage shape: `{ primary: KeyEntry, retired: KeyEntry[] }`
 * - `KID` is auto-generated per key (no hardcoded constant).
 * - `getJwks()` returns all non-expired keys (primary + retired).
 * - `verifyAccessToken()` reads `kid` from JWT header and looks up.
 * - Rotation: `scripts/rotate-keys.ts --grace 7d` generates a new primary
 *   and demotes the current primary to retired with a grace window.
 *
 * Backward compat: legacy single-key files (shape
 * `{ kid, publicKey, privateKey, createdAt }` at top level) are auto-
 * migrated to the new shape on load. The legacy `kid` is preserved so
 * tokens issued by the previous code keep verifying.
 *
 * Loads keys from a persisted file (`.oauth-keys.json` by default). In dev,
 * generates and persists on first run. In production, the file MUST exist
 * (run `npm run db:keys:init` before starting the server).
 */
import { importPKCS8, importSPKI, exportJWK, JWK } from "jose";
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { config } from "@/lib/config";

const KID_PREFIX = "kid-";
const KID_RANDOM_BYTES = 8; // 16 hex chars = 64 bits of entropy

/**
 * Generate a fresh kid. Format: `kid-<16 hex chars>`. No need for a UUID —
 * the kid only needs to be unique within this server's key set, and 64 bits
 * of entropy is more than enough for that.
 */
export function generateKid(): string {
  return KID_PREFIX + randomBytes(KID_RANDOM_BYTES).toString("hex");
}

/** A single key entry as stored on disk. */
export interface KeyEntry {
  kid: string;
  /** PEM SPKI */
  publicKey: string;
  /** PEM PKCS8 */
  privateKey: string;
  /** ISO 8601 timestamp */
  createdAt: string;
  /** ISO 8601 timestamp; present only on retired entries. */
  retiredAt?: string;
}

/** The on-disk shape. */
export interface KeysFile {
  primary: KeyEntry;
  retired: KeyEntry[];
}

/** Legacy single-key shape, used by code before issue #31. */
interface LegacyKeysFile {
  kid: string;
  publicKey: string;
  privateKey: string;
  createdAt: string;
}

function isLegacyShape(raw: unknown): raw is LegacyKeysFile {
  if (typeof raw !== "object" || raw === null) return false;
  const r = raw as Record<string, unknown>;
  return (
    typeof r["kid"] === "string" &&
    typeof r["publicKey"] === "string" &&
    typeof r["privateKey"] === "string" &&
    typeof r["createdAt"] === "string" &&
    !("primary" in r)
  );
}

function isNewShape(raw: unknown): raw is KeysFile {
  if (typeof raw !== "object" || raw === null) return false;
  const r = raw as Record<string, unknown>;
  const primary = r["primary"] as Record<string, unknown> | undefined;
  return (
    !!primary &&
    typeof primary["kid"] === "string" &&
    typeof primary["publicKey"] === "string" &&
    typeof primary["privateKey"] === "string" &&
    typeof primary["createdAt"] === "string" &&
    Array.isArray(r["retired"])
  );
}

/** Public JWKS entry — primary or retired, with use/alg/kid set. */
export type JwksKey = JWK & { kid: string; use: "sig"; alg: "RS256" };

export interface LoadedKeys {
  /** The current primary kid (used for signing). */
  primaryKid: string;
  /** Private key object for signing (jose KeyLike). */
  signingKey: Awaited<ReturnType<typeof importPKCS8>>;
  /**
   * All verification-capable keys keyed by kid (primary + non-expired
   * retired). Use this to verify a token by reading `kid` from its header.
   */
  verificationKeys: ReadonlyMap<string, Awaited<ReturnType<typeof importSPKI>>>;
  /** JWKS payload for `/.well-known/jwks.json`. */
  jwks: ReadonlyArray<JwksKey>;
  /** Primary entry, including PEM material (for rotation / inspection). */
  primary: KeyEntry;
  /** Retired entries, newest first. */
  retired: ReadonlyArray<KeyEntry>;
}

let keysPromise: Promise<LoadedKeys> | null = null;

/**
 * Load (or generate, in dev) the key set. Cached: repeated calls return the
 * same promise. To force a re-read (after a rotation script wrote a new
 * file), call `resetKeysCache()`.
 */
export function loadKeys(): Promise<LoadedKeys> {
  if (keysPromise) return keysPromise;

  const keysPath = config.keysPath;

  keysPromise = (async () => {
    const isProd = process.env["NODE_ENV"] === "production";
    let keysFile: KeysFile | null = null;
    let migratedFromLegacy = false;

    if (existsSync(keysPath)) {
      try {
        const raw: unknown = JSON.parse(readFileSync(keysPath, "utf8"));
        if (isLegacyShape(raw)) {
          // Auto-migrate: wrap legacy single-key as primary with the same
          // kid, so previously-issued tokens (which carry kid="key-1" or
          // whatever the old hardcoded value was) keep verifying.
          keysFile = {
            primary: {
              kid: raw.kid,
              publicKey: raw.publicKey,
              privateKey: raw.privateKey,
              createdAt: raw.createdAt,
            },
            retired: [],
          };
          migratedFromLegacy = true;
        } else if (isNewShape(raw)) {
          keysFile = raw;
        } else {
          throw new Error("Unrecognized keys file shape");
        }
      } catch (err) {
        console.warn(
          `[oauth] Failed to read keys from ${keysPath}: ${err instanceof Error ? err.message : String(err)}. Regenerating.`,
        );
        keysFile = null;
      }
    }

    if (!keysFile) {
      if (isProd) {
        throw new Error(
          `OAUTH keys file not found at ${keysPath}. ` +
            "Generate one with: npm run db:keys:init",
        );
      }
      // Dev: generate a fresh primary key with auto-generated kid.
      keysFile = generateFreshKeysFile();
      try {
        mkdirSync(dirname(keysPath), { recursive: true });
        writeFileSync(keysPath, JSON.stringify(keysFile, null, 2), "utf8");
      } catch (err) {
        console.warn(
          `[oauth] Could not persist keys to ${keysPath}: ${err instanceof Error ? err.message : String(err)}. Keys will not survive restart.`,
        );
      }
    } else if (migratedFromLegacy) {
      // Persist the migrated shape so we don't migrate again on next boot.
      try {
        writeFileSync(keysPath, JSON.stringify(keysFile, null, 2), "utf8");
      } catch (err) {
        console.warn(
          `[oauth] Could not persist migrated keys to ${keysPath}: ${err instanceof Error ? err.message : String(err)}.`,
        );
      }
    }

    return await buildLoadedKeys(keysFile);
  })();

  return keysPromise;
}

function generateFreshKeysFile(): KeysFile {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
  return {
    primary: {
      kid: generateKid(),
      publicKey,
      privateKey,
      createdAt: new Date().toISOString(),
    },
    retired: [],
  };
}

async function buildLoadedKeys(file: KeysFile): Promise<LoadedKeys> {
  const { primary, retired } = file;

  if (
    !primary.publicKey.includes("BEGIN PUBLIC KEY") ||
    !primary.privateKey.includes("BEGIN PRIVATE KEY")
  ) {
    throw new Error(
      `Invalid keys file: primary key is missing PEM material`,
    );
  }

  const signingKey = await importPKCS8(primary.privateKey, "RS256");
  const primaryPubKey = await importSPKI(primary.publicKey, "RS256");

  const verificationKeys = new Map<
    string,
    Awaited<ReturnType<typeof importSPKI>>
  >();
  verificationKeys.set(primary.kid, primaryPubKey);

  for (const r of retired) {
    if (r.publicKey?.includes("BEGIN PUBLIC KEY")) {
      verificationKeys.set(r.kid, await importSPKI(r.publicKey, "RS256"));
    }
  }

  // Build JWKS array. Stable order: primary first, then retired sorted
  // by createdAt ascending. JWKS consumers (clients) iterate this; order
  // matters for clients that pick the first key they recognize.
  const allEntries: KeyEntry[] = [primary, ...retired].filter((e) =>
    e.publicKey?.includes("BEGIN PUBLIC KEY"),
  );
  const jwks: JwksKey[] = await Promise.all(
    allEntries.map(async (e) => {
      const jwk = await exportJWK(await importSPKI(e.publicKey, "RS256"));
      return {
        ...jwk,
        kid: e.kid,
        use: "sig",
        alg: "RS256",
      };
    }),
  );

  return {
    primaryKid: primary.kid,
    signingKey,
    verificationKeys,
    jwks,
    primary,
    retired,
  };
}

/**
 * For tests / rotation CLI: clear the cached loadKeys() promise so the next
 * call re-reads from disk. Production code should never call this.
 */
export function resetKeysCache(): void {
  keysPromise = null;
}

/**
 * Rotate the key set: generate a new primary, demote the current primary to
 * retired with a grace window. After `graceSeconds`, the retired key can
 * be purged via `purgeExpiredRetiredKeys()`.
 *
 * Used by `scripts/rotate-keys.ts`. NOT exposed via HTTP — keeps rotation
 * auditable and operator-driven.
 */
export async function rotateKeys(opts: {
  graceSeconds: number;
}): Promise<{ previousKid: string; newKid: string; retiredUntil: string }> {
  const current = await loadKeys();
  const now = new Date();
  const retireAt = new Date(now.getTime() + opts.graceSeconds * 1000);

  const fresh = generateFreshKeysFile();
  const newFile: KeysFile = {
    primary: fresh.primary,
    retired: [
      ...current.retired,
      {
        ...current.primary,
        retiredAt: retireAt.toISOString(),
      },
    ],
  };

  writeFileSync(config.keysPath, JSON.stringify(newFile, null, 2), "utf8");
  resetKeysCache();

  return {
    previousKid: current.primaryKid,
    newKid: fresh.primary.kid,
    retiredUntil: retireAt.toISOString(),
  };
}

/**
 * Drop retired keys whose `retiredAt` has passed. Used by
 * `scripts/rotate-keys.ts --purge`. Safe to run repeatedly; no-op when
 * nothing is expired.
 */
export async function purgeExpiredRetiredKeys(): Promise<{ purged: number }> {
  const current = await loadKeys();
  const now = Date.now();
  const survivors = current.retired.filter((r) => {
    if (!r.retiredAt) return true; // no expiry set → keep
    return new Date(r.retiredAt).getTime() > now;
  });
  const purged = current.retired.length - survivors.length;
  if (purged === 0) return { purged: 0 };

  const newFile: KeysFile = {
    primary: current.primary,
    retired: survivors,
  };
  writeFileSync(config.keysPath, JSON.stringify(newFile, null, 2), "utf8");
  resetKeysCache();
  return { purged };
}
