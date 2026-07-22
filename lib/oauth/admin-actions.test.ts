/**
 * Unit tests for lib/oauth/admin-actions.ts.
 *
 * Mocks prisma so we can exercise the orchestration logic without a real
 * DB. Each test sets up the mocks it needs.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const { prismaMock } = vi.hoisted(() => ({
  prismaMock: {
    session: {
      updateMany: vi.fn(),
      findMany: vi.fn(),
    },
    accessToken: {
      updateMany: vi.fn(),
    },
    refreshToken: {
      updateMany: vi.fn(),
    },
    $transaction: vi.fn(),
  },
}));

vi.mock("@/lib/generated/prisma-client", () => ({
  prisma: prismaMock,
}));

import {
  revokeAllSessionsForUser,
  revokeAllTokensForUser,
  revokeSessionByJti,
  listActiveSessionsForUser,
} from "@/lib/oauth/admin-actions";

beforeEach(() => {
  vi.clearAllMocks();
});

describe("revokeAllSessionsForUser", () => {
  it("calls updateMany with revokedAt: null guard and returns count", async () => {
    prismaMock.session.updateMany.mockResolvedValueOnce({ count: 3 });
    const result = await revokeAllSessionsForUser("user-1");
    expect(prismaMock.session.updateMany).toHaveBeenCalledWith({
      where: { userId: "user-1", revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
    expect(result).toEqual({ count: 3 });
  });

  it("returns { count: 0 } when no active sessions (idempotent)", async () => {
    prismaMock.session.updateMany.mockResolvedValueOnce({ count: 0 });
    const result = await revokeAllSessionsForUser("user-with-no-sessions");
    expect(result).toEqual({ count: 0 });
  });
});

describe("revokeAllTokensForUser", () => {
  it("runs both updates in a single transaction with revokedAt guards", async () => {
    prismaMock.accessToken.updateMany.mockResolvedValueOnce({ count: 2 });
    prismaMock.refreshToken.updateMany.mockResolvedValueOnce({ count: 1 });
    // $transaction is mocked to await and return the resolved values as an
    // array — matches Prisma's actual contract for array-input transactions.
    prismaMock.$transaction.mockImplementationOnce(
      async (ops: Promise<unknown>[]) => {
        return await Promise.all(ops);
      },
    );

    const result = await revokeAllTokensForUser("user-1");

    expect(prismaMock.$transaction).toHaveBeenCalledTimes(1);
    // The transaction arg is an array of two query promises — verify shape.
    const txArg = prismaMock.$transaction.mock.calls[0]![0] as unknown[];
    expect(Array.isArray(txArg)).toBe(true);
    expect(txArg).toHaveLength(2);

    // Verify each updateMany got the right guard + data.
    expect(prismaMock.accessToken.updateMany).toHaveBeenCalledWith({
      where: { userId: "user-1", revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
    expect(prismaMock.refreshToken.updateMany).toHaveBeenCalledWith({
      where: { userId: "user-1", revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });

    expect(result).toEqual({ access: 2, refresh: 1 });
  });

  it("uses the same timestamp for access + refresh revocation", async () => {
    let capturedAccessTime: Date | undefined;
    let capturedRefreshTime: Date | undefined;
    prismaMock.accessToken.updateMany.mockImplementationOnce(
      async (args: { data: { revokedAt: Date } }) => {
        capturedAccessTime = args.data.revokedAt;
        return { count: 1 };
      },
    );
    prismaMock.refreshToken.updateMany.mockImplementationOnce(
      async (args: { data: { revokedAt: Date } }) => {
        capturedRefreshTime = args.data.revokedAt;
        return { count: 1 };
      },
    );
    prismaMock.$transaction.mockImplementationOnce(
      async (ops: Promise<unknown>[]) => Promise.all(ops),
    );
    await revokeAllTokensForUser("user-1");
    expect(capturedAccessTime).toBeDefined();
    expect(capturedRefreshTime).toBeDefined();
    expect(capturedAccessTime!.getTime()).toBe(capturedRefreshTime!.getTime());
  });

  it("returns zero counts when user has no tokens", async () => {
    prismaMock.accessToken.updateMany.mockResolvedValueOnce({ count: 0 });
    prismaMock.refreshToken.updateMany.mockResolvedValueOnce({ count: 0 });
    prismaMock.$transaction.mockImplementationOnce(
      async (ops: Promise<unknown>[]) => Promise.all(ops),
    );
    const result = await revokeAllTokensForUser("user-no-tokens");
    expect(result).toEqual({ access: 0, refresh: 0 });
  });
});

describe("listActiveSessionsForUser", () => {
  it("queries non-revoked, non-expired sessions newest first", async () => {
    const fakeRows = [
      {
        jti: "jti-1",
        userAgent: "Mozilla",
        ipAddress: "1.2.3.4",
        createdAt: new Date("2026-07-22T10:00:00Z"),
        expiresAt: new Date("2026-07-22T12:00:00Z"),
      },
    ];
    prismaMock.session.findMany.mockResolvedValueOnce(fakeRows);
    const result = await listActiveSessionsForUser("user-1");
    expect(prismaMock.session.findMany).toHaveBeenCalledWith({
      where: {
        userId: "user-1",
        revokedAt: null,
        expiresAt: { gt: expect.any(Date) },
      },
      select: {
        jti: true,
        userAgent: true,
        ipAddress: true,
        createdAt: true,
        expiresAt: true,
      },
      orderBy: { createdAt: "desc" },
    });
    expect(result).toEqual(fakeRows);
  });

  it("returns empty array when user has no active sessions", async () => {
    prismaMock.session.findMany.mockResolvedValueOnce([]);
    const result = await listActiveSessionsForUser("user-1");
    expect(result).toEqual([]);
  });
});

describe("revokeSessionByJti", () => {
  it("uses updateMany with jti + userId + revokedAt guard", async () => {
    prismaMock.session.updateMany.mockResolvedValueOnce({ count: 1 });
    const result = await revokeSessionByJti("user-1", "jti-abc");
    expect(prismaMock.session.updateMany).toHaveBeenCalledWith({
      where: { jti: "jti-abc", userId: "user-1", revokedAt: null },
      data: { revokedAt: expect.any(Date) },
    });
    expect(result).toEqual({ revoked: true });
  });

  it("returns revoked: true when count === 1", async () => {
    prismaMock.session.updateMany.mockResolvedValueOnce({ count: 1 });
    const result = await revokeSessionByJti("user-1", "jti-abc");
    expect(result.revoked).toBe(true);
  });

  it("returns revoked: false when no row matches (jti doesn't exist)", async () => {
    prismaMock.session.updateMany.mockResolvedValueOnce({ count: 0 });
    const result = await revokeSessionByJti("user-1", "no-such-jti");
    expect(result).toEqual({ revoked: false });
  });

  it("returns revoked: false when jti exists but belongs to a different user (no info leak)", async () => {
    // The userId guard makes the count 0 — caller can't distinguish
    // 'jti doesn't exist' from 'jti belongs to another user'.
    prismaMock.session.updateMany.mockResolvedValueOnce({ count: 0 });
    const result = await revokeSessionByJti("alice", "bobs-jti");
    expect(result).toEqual({ revoked: false });
  });

  it("returns revoked: false when session was already revoked", async () => {
    // revokedAt: null guard means already-revoked sessions don't match.
    prismaMock.session.updateMany.mockResolvedValueOnce({ count: 0 });
    const result = await revokeSessionByJti("user-1", "already-revoked");
    expect(result).toEqual({ revoked: false });
  });
});
