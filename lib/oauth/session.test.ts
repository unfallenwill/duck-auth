/**
 * Unit tests for lib/oauth/session.ts.
 *
 * Mocks prisma to exercise only the sign/verify orchestration logic,
 * including all revocation semantics introduced by issue #30 Phase 1
 * and the legacy JWT fallback from issue #37 Phase 5.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// ── Hoisted mocks (vi.mock factories run before everything else) ──
const { prismaMock, legacyGrace } = vi.hoisted(() => {
  return {
    prismaMock: {
      session: {
        create: vi.fn(),
        findUnique: vi.fn(),
        update: vi.fn(),
      },
    },
    // Mutable bag so individual tests can flip the env-controlled flag.
    // Mirrors config.sessionLegacyGracePeriod (issue #37 Phase 5).
    legacyGrace: { current: false },
  };
});

vi.mock("@/lib/config", () => ({
  // Proxy so reads happen at call-time, matching the real config getter
  // (which also re-reads on every access — see lib/config.ts).
  config: new Proxy(
    {},
    {
      get(_target, prop: string) {
        if (prop === "sessionSecret") {
          return "test-secret-32-bytes-please-please!!";
        }
        if (prop === "sessionLegacyGracePeriod") {
          return legacyGrace.current;
        }
        return undefined;
      },
    },
  ),
  SESSION_COOKIE_DEV_FALLBACK: "test-secret-32-bytes-please-please!!",
}));

vi.mock("@/lib/generated/prisma-client", () => ({
  prisma: prismaMock,
}));

// Import AFTER mocks.
import {
  signSessionCookie,
  verifySessionCookie,
  extractSessionJti,
} from "@/lib/oauth/session";
import { SignJWT } from "jose";

beforeEach(() => {
  vi.clearAllMocks();
  // Reset legacy fallback flag to default (off) before each test.
  legacyGrace.current = false;
  // Default mock impl: store created rows so verify can find them later.
  const store = new Map<string, {
    jti: string;
    userId: string;
    expiresAt: Date;
    revokedAt: Date | null;
    userAgent: string | null;
    ipAddress: string | null;
  }>();

  prismaMock.session.create.mockImplementation(async (args: {
    data: {
      jti: string;
      userId: string;
      expiresAt: Date;
      userAgent?: string | null;
      ipAddress?: string | null;
    };
  }) => {
    const row = {
      jti: args.data.jti,
      userId: args.data.userId,
      expiresAt: args.data.expiresAt,
      revokedAt: null,
      userAgent: args.data.userAgent ?? null,
      ipAddress: args.data.ipAddress ?? null,
    };
    store.set(row.jti, row);
    return row;
  });

  prismaMock.session.findUnique.mockImplementation(async (args: {
    where: { jti: string };
    select?: unknown;
  }) => {
    const row = store.get(args.where.jti);
    if (!row) return null;
    return {
      userId: row.userId,
      expiresAt: row.expiresAt,
      revokedAt: row.revokedAt,
    };
  });

  prismaMock.session.update.mockImplementation(async (args: {
    where: { jti: string };
    data: { revokedAt: Date };
  }) => {
    const row = store.get(args.where.jti);
    if (!row) return null;
    row.revokedAt = args.data.revokedAt;
    return row;
  });
});

describe("signSessionCookie / verifySessionCookie — round-trip", () => {
  it("round-trips a valid session", async () => {
    const { value } = await signSessionCookie("user-123");
    const session = await verifySessionCookie(value);
    expect(session).toEqual({ uid: "user-123" });
    expect(prismaMock.session.create).toHaveBeenCalledTimes(1);
    expect(prismaMock.session.findUnique).toHaveBeenCalledTimes(1);
  });

  it("produces different cookies for different users", async () => {
    const a = await signSessionCookie("alice");
    const b = await signSessionCookie("bob");
    expect(a.value).not.toBe(b.value);
  });

  it("persists userAgent and ipAddress when provided", async () => {
    await signSessionCookie("u1", {
      userAgent: "Mozilla/5.0",
      ipAddress: "192.0.2.1",
    });
    expect(prismaMock.session.create).toHaveBeenCalledWith(
      expect.objectContaining({
        data: expect.objectContaining({
          userAgent: "Mozilla/5.0",
          ipAddress: "192.0.2.1",
        }),
      }),
    );
  });

  it("default TTL is 2 hours", async () => {
    const now = Date.now();
    const { expiresAt } = await signSessionCookie("u1");
    const ttl = (expiresAt.getTime() - now) / 1000;
    expect(ttl).toBeGreaterThan(7190);
    expect(ttl).toBeLessThan(7210);
  });
});

describe("verifySessionCookie — JWT-level rejections", () => {
  it("returns null for garbage input", async () => {
    expect(await verifySessionCookie("not-a-jwt")).toBeNull();
  });

  it("returns null for empty string", async () => {
    expect(await verifySessionCookie("")).toBeNull();
  });

  it("returns null for JWT without uid claim", async () => {
    const secret = new TextEncoder().encode("test-secret-32-bytes-please-please!!");
    const token = await new SignJWT({ foo: "bar" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(secret);
    expect(await verifySessionCookie(token)).toBeNull();
  });

  it("returns null for JWT without jti claim (legacy fallback off by default)", async () => {
    const secret = new TextEncoder().encode("test-secret-32-bytes-please-please!!");
    const token = await new SignJWT({ uid: "u1" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(secret);
    expect(await verifySessionCookie(token)).toBeNull();
  });

  it("returns null for JWT signed with wrong secret", async () => {
    const wrongSecret = new TextEncoder().encode("wrong-secret-32-bytes-here-here!!");
    const token = await new SignJWT({ uid: "evil", jti: "any" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(wrongSecret);
    expect(await verifySessionCookie(token)).toBeNull();
  });
});

describe("verifySessionCookie — DB-level rejections (issue #30 Phase 1)", () => {
  it("returns null when no Session row exists for the jti", async () => {
    const secret = new TextEncoder().encode("test-secret-32-bytes-please-please!!");
    // Token for a session that was never persisted (or already cleaned up).
    const token = await new SignJWT({ uid: "ghost", jti: "no-such-jti" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(secret);
    expect(await verifySessionCookie(token)).toBeNull();
  });

  it("returns null when the Session row is revoked, and contrast with non-revoked row", async () => {
    const { value } = await signSessionCookie("u1");
    const createCall = prismaMock.session.create.mock.calls[0]![0] as {
      data: { jti: string; userId: string };
    };

    // Control: row exists with revokedAt = null → verifySessionCookie
    // must accept. This proves the same JWT path returns success when
    // DB says "valid", so the null below is because of the DB row,
    // not the JWT.
    const controlRow = await prismaMock.session.findUnique({
      where: { jti: createCall.data.jti },
    });
    expect(controlRow?.revokedAt).toBeNull();
    expect(await verifySessionCookie(value)).toEqual({ uid: "u1" });

    // Now mark the row revoked and assert verifySessionCookie rejects.
    await prismaMock.session.update({
      where: { jti: createCall.data.jti },
      data: { revokedAt: new Date() },
    });
    expect(await verifySessionCookie(value)).toBeNull();
  });

  it("returns null when the Session row is expired", async () => {
    // Force the in-memory store to return an expired row.
    const expiredJti = "expired-jti";
    const secret = new TextEncoder().encode("test-secret-32-bytes-please-please!!");
    const token = await new SignJWT({ uid: "u1", jti: expiredJti })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(secret);
    prismaMock.session.findUnique.mockResolvedValueOnce({
      userId: "u1",
      expiresAt: new Date(Date.now() - 60_000),
      revokedAt: null,
    });
    expect(await verifySessionCookie(token)).toBeNull();
  });

  it("returns null when JWT uid does not match DB row userId (tampering)", async () => {
    // Attacker manages to forge a valid signature with someone else's jti
    // but mismatched uid (or vice versa). Defense-in-depth check.
    const secret = new TextEncoder().encode("test-secret-32-bytes-please-please!!");
    const token = await new SignJWT({ uid: "alice", jti: "shared-jti" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(secret);
    // The row belongs to bob, not alice.
    prismaMock.session.findUnique.mockResolvedValueOnce({
      userId: "bob",
      expiresAt: new Date(Date.now() + 3600_000),
      revokedAt: null,
    });
    expect(await verifySessionCookie(token)).toBeNull();
  });
});

describe("extractSessionJti — signature-only, no DB lookup", () => {
  it("returns the EXACT jti claim from a valid signed cookie (not just a UUID-shaped string)", async () => {
    // Use a known jti so we can verify the function returns that exact
    // string, not just any UUID-shaped value. The mock store above
    // stores rows by the exact jti, so this round-trips the value.
    const knownJti = "11111111-2222-4333-8444-555555555555";
    prismaMock.session.create.mockResolvedValueOnce({
      jti: knownJti,
      userId: "user-1",
      expiresAt: new Date(Date.now() + 3600_000),
      revokedAt: null,
      userAgent: null,
      ipAddress: null,
    });
    const secret = new TextEncoder().encode(
      "test-secret-32-bytes-please-please!!",
    );
    const value = await new SignJWT({ uid: "user-1", jti: knownJti })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(secret);
    expect(await extractSessionJti(value)).toBe(knownJti);
  });

  it("returns the jti issued by signSessionCookie verbatim", async () => {
    const { value } = await signSessionCookie("user-1");
    const jti = await extractSessionJti(value);
    // Get the jti that signSessionCookie actually wrote to the mock store
    // and assert extractSessionJti returns that exact string.
    const createCall = prismaMock.session.create.mock.calls.at(-1)![0] as {
      data: { jti: string };
    };
    expect(jti).toBe(createCall.data.jti);
  });

  it("returns null for empty string", async () => {
    expect(await extractSessionJti("")).toBeNull();
  });

  it("returns null for garbage input", async () => {
    expect(await extractSessionJti("not-a-jwt")).toBeNull();
  });

  it("returns null for JWT signed with wrong secret", async () => {
    const wrongSecret = new TextEncoder().encode(
      "wrong-secret-32-bytes-here-here!!",
    );
    const token = await new SignJWT({ uid: "evil", jti: "any-jti" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(wrongSecret);
    expect(await extractSessionJti(token)).toBeNull();
  });

  it("returns null for JWT without jti claim", async () => {
    const secret = new TextEncoder().encode(
      "test-secret-32-bytes-please-please!!",
    );
    const token = await new SignJWT({ uid: "u1" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(secret);
    expect(await extractSessionJti(token)).toBeNull();
  });

  it("returns null for expired JWT (jose enforces exp even without DB)", async () => {
    const secret = new TextEncoder().encode(
      "test-secret-32-bytes-please-please!!",
    );
    const token = await new SignJWT({ uid: "u1", jti: "any-jti" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(secret);
    expect(await extractSessionJti(token)).toBeNull();
  });
});

describe("verifySessionCookie — legacy fallback (issue #37 Phase 5)", () => {
  const legacySecret = new TextEncoder().encode(
    "test-secret-32-bytes-please-please!!",
  );

  // Sign a JWT in the pre-Phase-1 format: just { uid }, no jti.
  async function signLegacyCookie(uid: string): Promise<string> {
    return await new SignJWT({ uid })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(legacySecret);
  }

  it("accepts a legacy JWT (no jti) when sessionLegacyGracePeriod is true", async () => {
    legacyGrace.current = true;
    const token = await signLegacyCookie("legacy-user");
    const result = await verifySessionCookie(token);
    expect(result).toEqual({ uid: "legacy-user" });
  });

  it("rejects a legacy JWT (no jti) when sessionLegacyGracePeriod is false", async () => {
    legacyGrace.current = false;
    const token = await signLegacyCookie("legacy-user");
    expect(await verifySessionCookie(token)).toBeNull();
  });

  it("legacy fallback rejects when JWT is signed with the wrong secret", async () => {
    legacyGrace.current = true;
    const wrongSecret = new TextEncoder().encode(
      "wrong-secret-32-bytes-here-here!!",
    );
    const token = await new SignJWT({ uid: "evil" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(wrongSecret);
    expect(await verifySessionCookie(token)).toBeNull();
  });

  it("legacy fallback rejects when exp has passed (jose enforces inside jwtVerify)", async () => {
    legacyGrace.current = true;
    const token = await new SignJWT({ uid: "u1" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt(Math.floor(Date.now() / 1000) - 7200)
      .setExpirationTime(Math.floor(Date.now() / 1000) - 60)
      .sign(legacySecret);
    expect(await verifySessionCookie(token)).toBeNull();
  });

  it("legacy fallback rejects when uid claim is missing entirely", async () => {
    legacyGrace.current = true;
    const token = await new SignJWT({ foo: "bar" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(legacySecret);
    expect(await verifySessionCookie(token)).toBeNull();
  });

  it("legacy fallback does NOT consult the Session table (signature-only)", async () => {
    legacyGrace.current = true;
    const token = await signLegacyCookie("legacy-user");
    const result = await verifySessionCookie(token);
    expect(result).toEqual({ uid: "legacy-user" });
    expect(prismaMock.session.findUnique).not.toHaveBeenCalled();
  });

  it("new-format path wins over legacy fallback when jti is present (Tier 1 → DB)", async () => {
    // Even with legacy enabled, a token with jti goes through Tier 1.
    // No DB row exists → must reject (proves Tier 2 didn't catch it).
    legacyGrace.current = true;
    const token = await new SignJWT({ uid: "u1", jti: "no-such-jti" })
      .setProtectedHeader({ alg: "HS256", typ: "session" })
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(legacySecret);
    expect(await verifySessionCookie(token)).toBeNull();
    // And we DID try the DB — distinguishing from "fell through to Tier 2".
    expect(prismaMock.session.findUnique).toHaveBeenCalledWith(
      expect.objectContaining({ where: { jti: "no-such-jti" } }),
    );
  });

  it("reads sessionLegacyGracePeriod from config per-call (not cached)", async () => {
    // Simulate operator toggling the env var mid-process. The Proxy
    // mock returns the current value of legacyGrace.current on every
    // read, matching the real config getter's behavior.
    const token = await signLegacyCookie("legacy-user");

    legacyGrace.current = false;
    expect(await verifySessionCookie(token)).toBeNull();

    legacyGrace.current = true;
    expect(await verifySessionCookie(token)).toEqual({ uid: "legacy-user" });

    legacyGrace.current = false;
    expect(await verifySessionCookie(token)).toBeNull();
  });
});
