/**
 * Unit tests for lib/oauth/keys.ts.
 *
 * Strategy: mock @/lib/config so config.keysPath points to a temp file.
 * Use vi.resetModules() between tests to clear the keysPromise singleton.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { writeFileSync, rmSync, existsSync, readFileSync } from "node:fs";
import { generateKeyPairSync } from "node:crypto";

// ── Helpers ─────────────────────────────────────────────────────────────

function makeTempKeysPath(): string {
  return join(
    tmpdir(),
    `duck-auth-test-keys-${Date.now()}-${Math.random().toString(36).slice(2)}.json`,
  );
}

function generateValidKeyPairPem() {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    publicKeyEncoding: { type: "spki", format: "pem" },
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
  });
}

// Cache original NODE_ENV
const originalNodeEnv = process.env["NODE_ENV"];

// ── Tests ───────────────────────────────────────────────────────────────

describe("loadKeys", () => {
  let keysPath: string;

  beforeEach(() => {
    keysPath = makeTempKeysPath();
    // Ensure dev mode by default
    process.env["NODE_ENV"] = "development";
    // Reset module cache so keysPromise is cleared
    vi.resetModules();
  });

  afterEach(() => {
    // Clean up temp file
    if (existsSync(keysPath)) {
      rmSync(keysPath, { force: true });
    }
    process.env["NODE_ENV"] = originalNodeEnv;
    vi.restoreAllMocks();
  });

  it("auto-generates and persists keys when file does not exist (dev)", async () => {
    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys = await loadKeys();

    expect(keys).toBeDefined();
    expect(keys.privateKey).toBeDefined();
    expect(keys.publicKey).toBeDefined();

    // File should have been persisted
    expect(existsSync(keysPath)).toBe(true);

    const raw = JSON.parse(readFileSync(keysPath, "utf8"));
    expect(raw.kid).toBe("key-1");
    expect(raw.publicKey).toContain("BEGIN PUBLIC KEY");
    expect(raw.privateKey).toContain("BEGIN PRIVATE KEY");
  });

  it("loads keys when file exists with valid content", async () => {
    const pair = generateValidKeyPairPem();
    writeFileSync(
      keysPath,
      JSON.stringify({
        kid: "key-1",
        publicKey: pair.publicKey,
        privateKey: pair.privateKey,
        createdAt: new Date().toISOString(),
      }),
      "utf8",
    );

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys = await loadKeys();

    expect(keys.privateKey).toBeDefined();
    expect(keys.publicKey).toBeDefined();
    // Should not overwrite the file — it already existed
    const raw = JSON.parse(readFileSync(keysPath, "utf8"));
    expect(raw.publicKey).toBe(pair.publicKey);
  });

  it("regenerates keys when file is corrupted (dev)", async () => {
    // Write a corrupted keys file
    writeFileSync(keysPath, "NOT VALID JSON {{{}}}", "utf8");

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys = await loadKeys();

    // In dev, should regenerate and still return valid keys
    expect(keys.privateKey).toBeDefined();
    expect(keys.publicKey).toBeDefined();

    // File should now contain valid JSON
    const raw = JSON.parse(readFileSync(keysPath, "utf8"));
    expect(raw.kid).toBe("key-1");
    expect(raw.publicKey).toContain("BEGIN PUBLIC KEY");
  });

  it("regenerates keys when file has valid JSON but missing key fields (dev)", async () => {
    // Valid JSON but no actual key data — the validation guard in loadKeys
    // silently falls through to the regeneration path
    writeFileSync(keysPath, JSON.stringify({ foo: "bar" }), "utf8");

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys = await loadKeys();

    expect(keys.privateKey).toBeDefined();
    expect(keys.publicKey).toBeDefined();

    // File should have been overwritten with valid keys
    const raw = JSON.parse(readFileSync(keysPath, "utf8"));
    expect(raw.kid).toBe("key-1");
    expect(raw.publicKey).toContain("BEGIN PUBLIC KEY");
  });

  it("caches keys across calls (returns same promise)", async () => {
    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys1 = await loadKeys();
    const keys2 = await loadKeys();

    // Should be the same object (cached)
    expect(keys1).toBe(keys2);
  });

  it("throws in production when keys file does not exist", async () => {
    process.env["NODE_ENV"] = "production";

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");

    await expect(loadKeys()).rejects.toThrow(/keys file not found/i);
  });

  it("throws in production when keys file is corrupted", async () => {
    process.env["NODE_ENV"] = "production";
    writeFileSync(keysPath, "CORRUPT {{{ }}", "utf8");

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");

    await expect(loadKeys()).rejects.toThrow(/keys file not found/i);
  });

  it("returns object with privateKey and publicKey properties", async () => {
    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys = await loadKeys();

    expect(keys).toHaveProperty("privateKey");
    expect(keys).toHaveProperty("publicKey");
  });
});
