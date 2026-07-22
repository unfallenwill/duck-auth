/**
 * Generate and persist the RS256 key set used by /oauth/token and /oauth/jwks.
 *
 * Multi-key support (issue #31): writes the new shape
 *   { primary: { kid, publicKey, privateKey, createdAt }, retired: [] }
 * with an auto-generated kid (no more hardcoded "key-1").
 *
 * Idempotent: refuses to overwrite an existing keys file unless --force is given.
 *
 * Usage:
 *   npm run db:keys:init
 *   npm run db:keys:init -- --force   # overwrite existing keys (invalidates ALL issued tokens)
 */
import "dotenv/config";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

import { config } from "../lib/config";
import { generateKid } from "../lib/oauth/keys";

const KEYS_PATH = config.keysPath;
const force = process.argv.includes("--force");

if (!force && existsSync(KEYS_PATH)) {
  console.error(`✗ Keys file already exists at ${KEYS_PATH}.`);
  console.error(`  Use --force to overwrite. WARNING: this invalidates ALL issued tokens.`);
  process.exit(1);
}

const { publicKey, privateKey } = generateKeyPairSync("rsa", {
  modulusLength: 2048,
  publicKeyEncoding: { type: "spki", format: "pem" },
  privateKeyEncoding: { type: "pkcs8", format: "pem" },
});

const kid = generateKid();
const createdAt = new Date().toISOString();

mkdirSync(dirname(KEYS_PATH), { recursive: true });
writeFileSync(
  KEYS_PATH,
  JSON.stringify(
    {
      primary: { kid, publicKey, privateKey, createdAt },
      retired: [],
    },
    null,
    2,
  ),
  "utf8",
);

console.log(`✓ Generated and persisted RS256 key pair to ${KEYS_PATH}`);
console.log(`  kid:       ${kid}`);
console.log(`  alg:       RS256`);
console.log(`  createdAt: ${createdAt}`);
console.log("");
console.log("Remember to set OAUTH_SESSION_SECRET in your .env:");
console.log("  openssl rand -base64 48");
