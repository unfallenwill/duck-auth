/**
 * RSA key pair management for JWT signing (RS256).
 *
 * Loads keys from a persisted file (`.oauth-keys.json` by default). In dev,
 * generates and persists on first run. In production, the file MUST exist
 * (run `npm run db:keys:init` before starting the server).
 */
import { importPKCS8, importSPKI } from "jose";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { config } from "@/lib/config";

export const KID = "key-1";

interface PersistedKeys {
  kid: string;
  publicKey: string;
  privateKey: string;
  createdAt: string;
}

export interface Keys {
  privateKey: Awaited<ReturnType<typeof importPKCS8>>;
  publicKey: Awaited<ReturnType<typeof importSPKI>>;
}

let keysPromise: Promise<Keys> | null = null;

export function loadKeys(): Promise<Keys> {
  if (keysPromise) return keysPromise;

  const keysPath = config.keysPath;

  keysPromise = (async () => {
    const isProd = process.env["NODE_ENV"] === "production";

    if (existsSync(keysPath)) {
      try {
        const raw = readFileSync(keysPath, "utf8");
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
      } catch (err) {
        console.warn(
          `[oauth] Failed to read keys from ${keysPath}: ${err instanceof Error ? err.message : String(err)}. Regenerating.`,
        );
      }
    }

    if (isProd) {
      throw new Error(
        `OAUTH keys file not found at ${keysPath}. ` +
          "Generate one with: npm run db:keys:init",
      );
    }

    // Dev: generate + persist for stability across hot-reloads.
    const { publicKey, privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      publicKeyEncoding: { type: "spki", format: "pem" },
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
    });
    try {
      mkdirSync(dirname(keysPath), { recursive: true });
      writeFileSync(
        keysPath,
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
        `[oauth] Could not persist keys to ${keysPath}: ${err instanceof Error ? err.message : String(err)}. Keys will not survive restart.`,
      );
    }

    return {
      privateKey: await importPKCS8(privateKey, "RS256"),
      publicKey: await importSPKI(publicKey, "RS256"),
    };
  })();

  return keysPromise;
}