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
    (process.env as Record<string, string>)['NODE_ENV'] = "development";
    // Reset module cache so keysPromise is cleared
    vi.resetModules();
  });

  afterEach(() => {
    // Clean up temp file
    if (existsSync(keysPath)) {
      rmSync(keysPath, { force: true });
    }
    (process.env as Record<string, string | undefined>)['NODE_ENV'] = originalNodeEnv;
    vi.restoreAllMocks();
  });

  it("auto-generates and persists keys when file does not exist (dev)", async () => {
    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys = await loadKeys();

    expect(keys).toBeDefined();
    expect(keys.signingKey).toBeDefined();
    expect(keys.primaryKid).toMatch(/^kid-[0-9a-f]{16}$/);
    expect(keys.verificationKeys.size).toBe(1);

    // File should have been persisted in the new shape
    expect(existsSync(keysPath)).toBe(true);
    const raw = JSON.parse(readFileSync(keysPath, "utf8"));
    expect(raw.primary).toBeDefined();
    expect(raw.primary.kid).toMatch(/^kid-[0-9a-f]{16}$/);
    expect(raw.primary.publicKey).toContain("BEGIN PUBLIC KEY");
    expect(raw.primary.privateKey).toContain("BEGIN PRIVATE KEY");
    expect(raw.retired).toEqual([]);
  });

  it("loads keys when file exists with valid new shape", async () => {
    const pair = generateValidKeyPairPem();
    writeFileSync(
      keysPath,
      JSON.stringify({
        primary: {
          kid: "kid-abc123",
          publicKey: pair.publicKey,
          privateKey: pair.privateKey,
          createdAt: new Date().toISOString(),
        },
        retired: [],
      }),
      "utf8",
    );

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys = await loadKeys();

    expect(keys.primaryKid).toBe("kid-abc123");
    expect(keys.signingKey).toBeDefined();
    expect(keys.verificationKeys.get("kid-abc123")).toBeDefined();

    // Should not overwrite the file
    const raw = JSON.parse(readFileSync(keysPath, "utf8"));
    expect(raw.primary.publicKey).toBe(pair.publicKey);
  });

  it("auto-migrates legacy single-key shape to new shape", async () => {
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

    // The legacy kid is preserved so previously-issued tokens keep verifying.
    expect(keys.primaryKid).toBe("key-1");
    expect(keys.verificationKeys.get("key-1")).toBeDefined();

    // The migrated file is persisted so we don't migrate again.
    const raw = JSON.parse(readFileSync(keysPath, "utf8"));
    expect(raw.primary.kid).toBe("key-1");
    expect(raw.retired).toEqual([]);
  });

  it("loads retired keys into verificationKeys", async () => {
    const primary = generateValidKeyPairPem();
    const retired = generateValidKeyPairPem();
    writeFileSync(
      keysPath,
      JSON.stringify({
        primary: {
          kid: "kid-primary",
          publicKey: primary.publicKey,
          privateKey: primary.privateKey,
          createdAt: new Date().toISOString(),
        },
        retired: [
          {
            kid: "kid-retired1",
            publicKey: retired.publicKey,
            privateKey: retired.privateKey,
            createdAt: new Date(Date.now() - 86400_000).toISOString(),
            retiredAt: new Date(Date.now() + 86400_000).toISOString(),
          },
        ],
      }),
      "utf8",
    );

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys = await loadKeys();

    expect(keys.primaryKid).toBe("kid-primary");
    expect(keys.verificationKeys.size).toBe(2);
    expect(keys.verificationKeys.has("kid-primary")).toBe(true);
    expect(keys.verificationKeys.has("kid-retired1")).toBe(true);
    expect(keys.jwks.length).toBe(2);
  });

  it("JWKS contains primary first, then retired", async () => {
    const primary = generateValidKeyPairPem();
    const retired = generateValidKeyPairPem();
    writeFileSync(
      keysPath,
      JSON.stringify({
        primary: {
          kid: "kid-primary",
          publicKey: primary.publicKey,
          privateKey: primary.privateKey,
          createdAt: new Date().toISOString(),
        },
        retired: [
          {
            kid: "kid-retired1",
            publicKey: retired.publicKey,
            privateKey: retired.privateKey,
            createdAt: new Date().toISOString(),
          },
        ],
      }),
      "utf8",
    );

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys = await loadKeys();
    expect(keys.jwks[0]?.kid).toBe("kid-primary");
    expect(keys.jwks[1]?.kid).toBe("kid-retired1");
    for (const jwk of keys.jwks) {
      expect(jwk.use).toBe("sig");
      expect(jwk.alg).toBe("RS256");
      expect(jwk.kty).toBe("RSA");
    }
  });

  it("regenerates keys when file is corrupted (dev)", async () => {
    writeFileSync(keysPath, "NOT VALID JSON {{{}}}", "utf8");

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys = await loadKeys();

    expect(keys.signingKey).toBeDefined();
    expect(keys.primaryKid).toMatch(/^kid-[0-9a-f]{16}$/);

    const raw = JSON.parse(readFileSync(keysPath, "utf8"));
    expect(raw.primary.kid).toMatch(/^kid-[0-9a-f]{16}$/);
  });

  it("regenerates keys when file has valid JSON but missing key fields (dev)", async () => {
    writeFileSync(keysPath, JSON.stringify({ foo: "bar" }), "utf8");

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys = await loadKeys();

    expect(keys.signingKey).toBeDefined();
    const raw = JSON.parse(readFileSync(keysPath, "utf8"));
    expect(raw.primary.kid).toMatch(/^kid-[0-9a-f]{16}$/);
  });

  it("caches keys across calls (returns same promise)", async () => {
    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    const keys1 = await loadKeys();
    const keys2 = await loadKeys();
    expect(keys1).toBe(keys2);
  });

  it("throws in production when keys file does not exist", async () => {
    (process.env as Record<string, string>)['NODE_ENV'] = "production";

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    await expect(loadKeys()).rejects.toThrow(/keys file not found/i);
  });

  it("throws in production when keys file is corrupted", async () => {
    (process.env as Record<string, string>)['NODE_ENV'] = "production";
    writeFileSync(keysPath, "CORRUPT {{{ }}", "utf8");

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys } = await import("@/lib/oauth/keys");
    await expect(loadKeys()).rejects.toThrow(/keys file not found/i);
  });
});

describe("generateKid", () => {
  it("produces kid-<16 hex chars>", async () => {
    const { generateKid } = await import("@/lib/oauth/keys");
    const kid = generateKid();
    expect(kid).toMatch(/^kid-[0-9a-f]{16}$/);
  });

  it("produces unique kids across calls", async () => {
    const { generateKid } = await import("@/lib/oauth/keys");
    const kids = new Set(Array.from({ length: 100 }, () => generateKid()));
    expect(kids.size).toBe(100);
  });
});

describe("rotateKeys", () => {
  let keysPath: string;

  beforeEach(() => {
    keysPath = makeTempKeysPath();
    (process.env as Record<string, string>)['NODE_ENV'] = "development";
    vi.resetModules();
  });

  afterEach(() => {
    if (existsSync(keysPath)) {
      rmSync(keysPath, { force: true });
    }
    (process.env as Record<string, string | undefined>)['NODE_ENV'] = originalNodeEnv;
    vi.restoreAllMocks();
  });

  it("promotes new primary and demotes old primary to retired with grace", async () => {
    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys, rotateKeys } = await import("@/lib/oauth/keys");

    // Seed initial primary.
    await loadKeys();
    const before = await loadKeys();
    const oldKid = before.primaryKid;

    const result = await rotateKeys({ graceSeconds: 3600 });

    expect(result.previousKid).toBe(oldKid);
    expect(result.newKid).not.toBe(oldKid);
    expect(result.newKid).toMatch(/^kid-[0-9a-f]{16}$/);
    expect(new Date(result.retiredUntil).getTime()).toBeGreaterThan(Date.now());

    // Re-load: new primary is active, old is in retired with retiredAt.
    const after = await loadKeys();
    expect(after.primaryKid).toBe(result.newKid);
    expect(after.retired.length).toBe(1);
    expect(after.retired[0]?.kid).toBe(oldKid);
    expect(after.retired[0]?.retiredAt).toBeDefined();

    // Both kids verify.
    expect(after.verificationKeys.has(result.newKid)).toBe(true);
    expect(after.verificationKeys.has(oldKid)).toBe(true);
    expect(after.jwks.length).toBe(2);
  });

  it("chains: rotating twice keeps both previous primaries in retired", async () => {
    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys, rotateKeys } = await import("@/lib/oauth/keys");
    await loadKeys();
    const first = (await loadKeys()).primaryKid;

    await rotateKeys({ graceSeconds: 3600 });
    const second = (await loadKeys()).primaryKid;

    await rotateKeys({ graceSeconds: 3600 });
    const after = await loadKeys();

    expect(after.primaryKid).not.toBe(first);
    expect(after.primaryKid).not.toBe(second);
    expect(after.retired.length).toBe(2);
    const retiredKids = after.retired.map((r) => r.kid);
    expect(retiredKids).toContain(first);
    expect(retiredKids).toContain(second);
  });
});

describe("purgeExpiredRetiredKeys", () => {
  let keysPath: string;

  beforeEach(() => {
    keysPath = makeTempKeysPath();
    (process.env as Record<string, string>)['NODE_ENV'] = "development";
    vi.resetModules();
  });

  afterEach(() => {
    if (existsSync(keysPath)) {
      rmSync(keysPath, { force: true });
    }
    (process.env as Record<string, string | undefined>)['NODE_ENV'] = originalNodeEnv;
    vi.restoreAllMocks();
  });

  it("removes retired keys whose retiredAt has passed", async () => {
    const pair = generateValidKeyPairPem();
    writeFileSync(
      keysPath,
      JSON.stringify({
        primary: {
          kid: "kid-primary",
          publicKey: pair.publicKey,
          privateKey: pair.privateKey,
          createdAt: new Date().toISOString(),
        },
        retired: [
          {
            kid: "kid-expired",
            publicKey: pair.publicKey,
            privateKey: pair.privateKey,
            createdAt: new Date(Date.now() - 86400_000).toISOString(),
            retiredAt: new Date(Date.now() - 60_000).toISOString(), // 1 min ago
          },
          {
            kid: "kid-active",
            publicKey: pair.publicKey,
            privateKey: pair.privateKey,
            createdAt: new Date().toISOString(),
            retiredAt: new Date(Date.now() + 86400_000).toISOString(), // 1 day future
          },
        ],
      }),
      "utf8",
    );

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { purgeExpiredRetiredKeys } = await import("@/lib/oauth/keys");
    const { purged } = await purgeExpiredRetiredKeys();

    expect(purged).toBe(1);
    const raw = JSON.parse(readFileSync(keysPath, "utf8"));
    expect(raw.retired.length).toBe(1);
    expect(raw.retired[0]?.kid).toBe("kid-active");
  });

  it("keeps retired keys without retiredAt set (safety)", async () => {
    const pair = generateValidKeyPairPem();
    writeFileSync(
      keysPath,
      JSON.stringify({
        primary: {
          kid: "kid-primary",
          publicKey: pair.publicKey,
          privateKey: pair.privateKey,
          createdAt: new Date().toISOString(),
        },
        retired: [
          {
            kid: "kid-no-expiry",
            publicKey: pair.publicKey,
            privateKey: pair.privateKey,
            createdAt: new Date().toISOString(),
            // no retiredAt — should be kept
          },
        ],
      }),
      "utf8",
    );

    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { purgeExpiredRetiredKeys } = await import("@/lib/oauth/keys");
    const { purged } = await purgeExpiredRetiredKeys();
    expect(purged).toBe(0);
  });

  it("is a no-op when nothing is expired", async () => {
    vi.doMock("@/lib/config", () => ({
      config: { keysPath },
    }));

    const { loadKeys, purgeExpiredRetiredKeys } = await import("@/lib/oauth/keys");
    await loadKeys(); // seed
    const { purged } = await purgeExpiredRetiredKeys();
    expect(purged).toBe(0);
  });
});
