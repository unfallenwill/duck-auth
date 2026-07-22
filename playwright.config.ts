import { defineConfig } from "@playwright/test";
import { readFileSync, existsSync } from "node:fs";

/**
 * Playwright config for browser-level regression tests.
 *
 * IMPORTANT: These tests need a running Next.js server. The script
 * `e2e:playwright` starts one, waits for readiness, runs the suite,
 * and tears it down.
 */

// Load .env into process.env so tests can read ADMIN_TOKEN, OAUTH_*, etc.
// Next.js auto-loads .env at server startup, but the Playwright *test*
// process is a separate Node process that doesn't get that for free.
// Mirrors what Next.js dotenv does at startup. Quotes + comments handled.
(() => {
  if (!existsSync(".env")) return;
  for (const raw of readFileSync(".env", "utf8").split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = line.match(/^([A-Z_][A-Z0-9_]*)=(.*)$/);
    if (!m) continue;
    const key = m[1]!;
    let val = m[2]!;
    // Strip surrounding quotes if present.
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    // Don't override anything already set in the parent shell.
    if (process.env[key] === undefined) {
      process.env[key] = val;
    }
  }
})();

export default defineConfig({
  testDir: "./e2e/playwright",
  fullyParallel: false, // shared DB state — run serially
  workers: 1,
  reporter: [["list"]],
  use: {
    baseURL: "http://localhost:3000",
    headless: true,
    actionTimeout: 10_000,
    navigationTimeout: 15_000,
    trace: "retain-on-failure",
  },
  // Do not start our own server — `e2e:playwright` handles that so we
  // don't conflict with the e2e:flow suite's own server.
});
