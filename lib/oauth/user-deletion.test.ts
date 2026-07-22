/**
 * Unit tests for lib/oauth/user-deletion.ts.
 *
 * Mocks the prisma transaction wrapper so we can exercise the orchestration
 * logic without a real DB. Each test sets up the mocks it needs and
 * asserts the right prisma calls were made + the right counts returned.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createHash } from "node:crypto";

// ── Prisma mock ─────────────────────────────────────────────────────────

const txState = {
  user: null as null | {
    id: string;
    email: string;
    deletedAt: Date | null;
  },
  sessions: [] as Array<{ revokedAt: Date | null }>,
  accessTokens: [] as Array<{ revokedAt: Date | null }>,
  refreshTokens: [] as Array<{ revokedAt: Date | null }>,
  consents: [] as Array<{ id: string }>,
};

const { txMock, prismaMock } = vi.hoisted(() => {
  const tx = {
    user: {
      findUnique: vi.fn(),
      update: vi.fn(),
    },
    session: {
      updateMany: vi.fn(),
    },
    accessToken: {
      updateMany: vi.fn(),
    },
    refreshToken: {
      updateMany: vi.fn(),
    },
    consent: {
      deleteMany: vi.fn(),
    },
  };
  return {
    txMock: tx,
    prismaMock: {
      $transaction: vi.fn(async (fn: (tx: unknown) => unknown) => fn(tx)),
      user: {
        deleteMany: vi.fn(),
      },
    },
  };
});

// Make the same `tx` object accessible via `prisma.$transaction`.
vi.mock("@/lib/generated/prisma-client", () => ({
  prisma: {
    $transaction: (fn: (tx: unknown) => unknown) => fn(txMock),
    user: prismaMock.user,
  },
}));

import { deleteCurrentUser, purgeDeletedUsers } from "@/lib/oauth/user-deletion";

function resetTxState(): void {
  txState.user = null;
  txState.sessions = [];
  txState.accessTokens = [];
  txState.refreshTokens = [];
  txState.consents = [];
  vi.clearAllMocks();
  prismaMock.$transaction.mockImplementation(async (fn: (tx: unknown) => unknown) =>
    fn(txMock),
  );
}

beforeEach(() => {
  resetTxState();
});

// ── Helper ──────────────────────────────────────────────────────────────

function expectAnonymizedEmail(original: string): string {
  const hash = createHash("sha256")
    .update(original.toLowerCase())
    .digest("hex")
    .slice(0, 32);
  return `deleted-${hash}@example.invalid`;
}

// ── Tests ───────────────────────────────────────────────────────────────

describe("deleteCurrentUser", () => {
  it("throws when user doesn't exist", async () => {
    txMock.user.findUnique.mockResolvedValueOnce(null);
    await expect(deleteCurrentUser("missing-user")).rejects.toThrow(
      /user not found/i,
    );
  });

  it("soft-deletes user, anonymizes PII, revokes tokens, deletes consents", async () => {
    txState.user = {
      id: "user-1",
      email: "alice@example.com",
      deletedAt: null,
    };
    txMock.user.findUnique.mockResolvedValueOnce(txState.user);
    txMock.user.update.mockImplementationOnce(async (args: {
      where: { id: string };
      data: { deletedAt: Date; email: string; name: null; passwordHash: string };
    }) => {
      txState.user = {
        ...txState.user!,
        email: args.data.email,
      };
      return txState.user;
    });
    txMock.session.updateMany.mockImplementationOnce(async (args: {
      where: { userId: string; revokedAt: null };
      data: { revokedAt: Date };
    }) => {
      txState.sessions.forEach((s) => (s.revokedAt = args.data.revokedAt));
      return { count: txState.sessions.length };
    });
    txMock.accessToken.updateMany.mockImplementationOnce(async () => ({
      count: 3,
    }));
    txMock.refreshToken.updateMany.mockImplementationOnce(async () => ({
      count: 2,
    }));
    txMock.consent.deleteMany.mockImplementationOnce(async () => ({
      count: 1,
    }));

    const result = await deleteCurrentUser("user-1");

    expect(result.userId).toBe("user-1");
    expect(result.revokedSessions).toBe(0); // sessions array was empty
    expect(result.revokedAccessTokens).toBe(3);
    expect(result.revokedRefreshTokens).toBe(2);
    expect(result.deletedConsents).toBe(1);
    expect(result.anonymizedEmail).toBe(
      expectAnonymizedEmail("alice@example.com"),
    );

    expect(txMock.user.update).toHaveBeenCalledWith({
      where: { id: "user-1" },
      data: expect.objectContaining({
        email: expectAnonymizedEmail("alice@example.com"),
        name: null,
        passwordHash: "",
        deletedAt: expect.any(Date),
      }),
    });
  });

  it("produces deterministic anonymized email (same input → same output)", async () => {
    txState.user = {
      id: "user-1",
      email: "bob@example.com",
      deletedAt: null,
    };
    txMock.user.findUnique.mockResolvedValueOnce(txState.user);
    txMock.user.update.mockResolvedValueOnce(txState.user);
    txMock.session.updateMany.mockResolvedValueOnce({ count: 0 });
    txMock.accessToken.updateMany.mockResolvedValueOnce({ count: 0 });
    txMock.refreshToken.updateMany.mockResolvedValueOnce({ count: 0 });
    txMock.consent.deleteMany.mockResolvedValueOnce({ count: 0 });

    const result = await deleteCurrentUser("user-1");
    expect(result.anonymizedEmail).toMatch(/^deleted-[0-9a-f]{32}@example\.invalid$/);

    // Run again — same email produces same hash.
    txState.user = { ...txState.user, deletedAt: null };
    txMock.user.findUnique.mockResolvedValueOnce(txState.user);
    txMock.user.update.mockResolvedValueOnce(txState.user);
    txMock.session.updateMany.mockResolvedValueOnce({ count: 0 });
    txMock.accessToken.updateMany.mockResolvedValueOnce({ count: 0 });
    txMock.refreshToken.updateMany.mockResolvedValueOnce({ count: 0 });
    txMock.consent.deleteMany.mockResolvedValueOnce({ count: 0 });
    const result2 = await deleteCurrentUser("user-1");
    expect(result2.anonymizedEmail).toBe(result.anonymizedEmail);
  });

  it("normalizes email case before hashing", async () => {
    txState.user = {
      id: "user-1",
      email: "Alice@Example.COM",
      deletedAt: null,
    };
    txMock.user.findUnique.mockResolvedValueOnce(txState.user);
    txMock.user.update.mockResolvedValueOnce(txState.user);
    txMock.session.updateMany.mockResolvedValueOnce({ count: 0 });
    txMock.accessToken.updateMany.mockResolvedValueOnce({ count: 0 });
    txMock.refreshToken.updateMany.mockResolvedValueOnce({ count: 0 });
    txMock.consent.deleteMany.mockResolvedValueOnce({ count: 0 });

    const result = await deleteCurrentUser("user-1");
    expect(result.anonymizedEmail).toBe(
      expectAnonymizedEmail("alice@example.com"),
    );
  });

  it("is idempotent: re-running on a deleted user returns zeros, no re-mutation", async () => {
    const earlierDeletedAt = new Date(Date.now() - 1000);
    txState.user = {
      id: "user-1",
      email: expectAnonymizedEmail("alice@example.com"),
      deletedAt: earlierDeletedAt,
    };
    txMock.user.findUnique.mockResolvedValueOnce(txState.user);

    const result = await deleteCurrentUser("user-1");

    expect(result.revokedSessions).toBe(0);
    expect(result.revokedAccessTokens).toBe(0);
    expect(result.revokedRefreshTokens).toBe(0);
    expect(result.deletedConsents).toBe(0);
    expect(result.deletedAt).toEqual(earlierDeletedAt);
    // No mutation calls should have been made.
    expect(txMock.user.update).not.toHaveBeenCalled();
    expect(txMock.session.updateMany).not.toHaveBeenCalled();
    expect(txMock.accessToken.updateMany).not.toHaveBeenCalled();
    expect(txMock.refreshToken.updateMany).not.toHaveBeenCalled();
    expect(txMock.consent.deleteMany).not.toHaveBeenCalled();
  });

  it("counts revoked sessions correctly", async () => {
    txState.user = {
      id: "user-1",
      email: "x@y.z",
      deletedAt: null,
    };
    txState.sessions = [
      { revokedAt: null },
      { revokedAt: null },
      { revokedAt: new Date() }, // already revoked → not counted
      { revokedAt: null },
    ];
    txMock.user.findUnique.mockResolvedValueOnce(txState.user);
    txMock.user.update.mockResolvedValueOnce(txState.user);
    txMock.session.updateMany.mockResolvedValueOnce({ count: 3 });
    txMock.accessToken.updateMany.mockResolvedValueOnce({ count: 0 });
    txMock.refreshToken.updateMany.mockResolvedValueOnce({ count: 0 });
    txMock.consent.deleteMany.mockResolvedValueOnce({ count: 0 });

    const result = await deleteCurrentUser("user-1");
    expect(result.revokedSessions).toBe(3);
  });
});

describe("purgeDeletedUsers", () => {
  it("deletes users with deletedAt older than retention cutoff", async () => {
    prismaMock.user.deleteMany.mockResolvedValueOnce({ count: 7 });
    const result = await purgeDeletedUsers(30);
    expect(result.purged).toBe(7);
    expect(prismaMock.user.deleteMany).toHaveBeenCalledWith({
      where: {
        deletedAt: { lt: expect.any(Date), not: null },
      },
    });
    // cutoff should be ~30 days ago
    const expectedCutoff = new Date(Date.now() - 30 * 86400_000);
    const actualCutoff = result.cutoff;
    expect(Math.abs(actualCutoff.getTime() - expectedCutoff.getTime())).toBeLessThan(5000);
  });

  it("respects custom retentionDays", async () => {
    prismaMock.user.deleteMany.mockResolvedValueOnce({ count: 2 });
    const result = await purgeDeletedUsers(90);
    expect(result.purged).toBe(2);
  });

  it("is a no-op when nothing is past retention", async () => {
    prismaMock.user.deleteMany.mockResolvedValueOnce({ count: 0 });
    const result = await purgeDeletedUsers(30);
    expect(result.purged).toBe(0);
  });
});
