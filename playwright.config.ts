import { defineConfig } from "@playwright/test";

/**
 * Playwright config for browser-level regression tests.
 *
 * IMPORTANT: These tests need a running Next.js server. The script
 * `e2e:playwright` starts one, waits for readiness, runs the suite,
 * and tears it down.
 */
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