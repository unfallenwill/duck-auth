/**
 * Generate and persist the RS256 key pair used by /oauth/token and /oauth/jwks.
 *
 * Idempotent: refuses to overwrite an existing keys file unless --force is given.
 *
 * Usage:
 *   npm run db:keys:init
 *   npm run db:keys:init -- --force   # overwrite existing keys
 */
import "dotenv/config";
import { generateKeyPairSync } from "node:crypto";
import { existsSync, writeFileSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";

const KEYS_PATH = process.env["OAUTH_KEYS_PATH"] ?? "./.oauth-keys.json";
const KID = "key-1";
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

mkdirSync(dirname(KEYS_PATH), { recursive: true });
writeFileSync(
  KEYS_PATH,
  JSON.stringify(
    {
      kid: KID,
      publicKey,
      privateKey,
      createdAt: new Date().toISOString(),
    },
    null,
    2,
  ),
  "utf8",
);

console.log(`✓ Generated and persisted RS256 key pair to ${KEYS_PATH}`);
console.log(`  kid: ${KID}`);
console.log(`  alg: RS256`);
console.log(`  createdAt: ${new Date().toISOString()}`);
console.log("");
console.log("Remember to set OAUTH_SESSION_SECRET in your .env:");
console.log("  openssl rand -base64 48");