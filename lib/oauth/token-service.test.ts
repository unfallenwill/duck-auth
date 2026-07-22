/**
 * Unit tests for lib/oauth/token-service.ts.
 *
 * Strategy: mock Prisma, jwt.ts, and crypto.ts so the test exercises
 * only the orchestration logic inside issueTokenSet.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";

// ── Mock data ─────────────────────────────────────────────────────
const TEST_USER = {
  id: "user-1",
  email: "alice@example.com",
  name: "Alice",
  passwordHash: "hash",
  createdAt: new Date(),
  updatedAt: new Date(),
};

// ── Hoisted mocks (vi.mock factories run before everything else) ──
const { prismaMock } = vi.hoisted(() => {
  const fn = () => vi.fn();
  return {
    prismaMock: {
      user: { findUnique: fn() },
      accessToken: { create: fn() },
      refreshToken: { create: fn() },
    },
  };
});

// Reusable tx mock factory (used by "user not found" and atomicity tests).
// `as any` because Prisma's `TransactionClient` delegate types have ~17
// methods per model — mocking all of them for a focused unit test is
// noise. The runtime contract is verified by the assertions below; type
// narrowing would only catch typos.
function makeTxMock() {
  return {
    user: { findUnique: vi.fn() },
    accessToken: { create: vi.fn() },
    refreshToken: { create: vi.fn() },
  } as any;
}

// `tx` is now a REQUIRED parameter of `issueTokenSet`. In test code we
// pass `prismaMock` (the global mock object) cast to TransactionClient.
// At runtime this hits the same mock functions the tests assert on.
const txClient = prismaMock as unknown as Prisma.TransactionClient;

vi.mock("@/lib/generated/prisma-client", () => ({
  prisma: prismaMock,
}));

vi.mock("@/lib/oauth/jwt", () => ({
  signAccessToken: vi.fn().mockResolvedValue({
    token: "mock-access-token",
    jti: "mock-jti",
    expiresAt: new Date(Date.now() + 3600_000),
  }),
  signIdToken: vi.fn().mockResolvedValue({
    token: "mock-id-token",
    expiresAt: new Date(Date.now() + 3600_000),
  }),
}));

vi.mock("@/lib/oauth/crypto", () => ({
  randomToken: vi.fn().mockReturnValue("mock-refresh-token"),
}));

// Import AFTER mocks.
import { issueTokenSet } from "@/lib/oauth/token-service";
import { signIdToken, signAccessToken } from "@/lib/oauth/jwt";
import { Prisma } from "@/lib/generated/prisma/client";

beforeEach(() => {
  prismaMock.user.findUnique.mockResolvedValue(TEST_USER);
  prismaMock.accessToken.create.mockResolvedValue({});
  prismaMock.refreshToken.create.mockResolvedValue({});
  // vi.clearAllMocks() only clears .mock.calls / .mock.results; the
  // mockResolvedValue implementations set in vi.mock factories persist.
  vi.clearAllMocks();
});

describe("issueTokenSet – normal flow", () => {
  it("returns access_token + refresh_token + id_token when scope includes openid", async () => {
    const res = await issueTokenSet("user-1", "client-x", "openid profile", txClient);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.access_token).toBe("mock-access-token");
    expect(body.token_type).toBe("Bearer");
    expect(body.expires_in).toBe(3600);
    expect(body.refresh_token).toBe("mock-refresh-token");
    expect(body.scope).toBe("openid profile");
    expect(body.id_token).toBe("mock-id-token");
  });

  it("persists access token and refresh token to the DB", async () => {
    await issueTokenSet("user-1", "client-x", "openid", txClient);
    expect(prismaMock.accessToken.create).toHaveBeenCalledTimes(1);
    expect(prismaMock.refreshToken.create).toHaveBeenCalledTimes(1);
  });
});

describe("issueTokenSet – scope without openid", () => {
  it("omits id_token when scope does not include openid", async () => {
    const res = await issueTokenSet("user-1", "client-x", "profile email", txClient);
    const body = await res.json();
    expect(body.access_token).toBe("mock-access-token");
    expect(body.refresh_token).toBe("mock-refresh-token");
    expect(body.id_token).toBeUndefined();
  });
});

describe("issueTokenSet – openid-only scope", () => {
  it("id_token is issued but without email/name claims", async () => {
    vi.mocked(signIdToken).mockClear();

    await issueTokenSet("user-1", "client-x", "openid", txClient);

    // signIdToken should have been called without email or name.
    const callArg = vi.mocked(signIdToken).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect(callArg.sub).toBe("user-1");
    expect(callArg.email).toBeUndefined();
    expect(callArg.name).toBeUndefined();
  });
});

describe("issueTokenSet – openid + email scope", () => {
  it("id_token includes email claim", async () => {
    vi.mocked(signIdToken).mockClear();

    await issueTokenSet("user-1", "client-x", "openid email", txClient);

    const callArg = vi.mocked(signIdToken).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect(callArg.sub).toBe("user-1");
    expect(callArg.email).toBe("alice@example.com");
    // name should NOT be present (profile not requested)
    expect(callArg.name).toBeUndefined();
  });
});

describe("issueTokenSet – user not found", () => {
  it("throws OAuthError(server_error, status 500) when user record is missing — so a tx can roll back", async () => {
    prismaMock.user.findUnique.mockResolvedValue(null);

    await expect(
      issueTokenSet("nonexistent", "client-x", "openid", txClient),
    ).rejects.toMatchObject({
      name: "OAuthError",
      code: "server_error",
      status: 500, // critical: 5xx → 500, not 400
      message: expect.stringContaining("User record missing"),
    });
    // No token persistence attempted.
    expect(prismaMock.accessToken.create).not.toHaveBeenCalled();
    expect(prismaMock.refreshToken.create).not.toHaveBeenCalled();
  });

  it("throws OAuthError inside tx when user missing — CAS caller can roll back", async () => {
    const tx = makeTxMock();
    tx.user.findUnique.mockResolvedValue(null);

    await expect(
      issueTokenSet("user-1", "client-x", "openid", tx),
    ).rejects.toMatchObject({ name: "OAuthError", code: "server_error" });
    // Critical: writes must NOT happen so the outer $transaction has
    // a clean rollback target. If issueTokenSet returned a Response here
    // instead of throwing, the outer tx would commit and the caller's
    // CAS write (e.g. authorizationCode.usedAt) would be permanent.
    expect(tx.accessToken.create).not.toHaveBeenCalled();
    expect(tx.refreshToken.create).not.toHaveBeenCalled();
  });
});

// ── Atomicity tests for fix/issue-28 ──────────────────────────────
//
// issueTokenSet now accepts an optional `tx: Prisma.TransactionClient` so
// callers (grant handlers in app/oauth/token/route.ts) can wrap
// CAS-protected writes + token issuance in a single Prisma transaction.
// These tests prove the tx plumbing works and that the unit-level contract
// holds: errors from inside the tx propagate so the outer transaction can
// roll back.
describe("issueTokenSet – atomicity (issue #28)", () => {
  it("uses the tx client for all DB writes (not the top-level prisma)", async () => {
    const tx = makeTxMock();
    tx.user.findUnique.mockResolvedValue(TEST_USER);
    tx.accessToken.create.mockResolvedValue({});
    tx.refreshToken.create.mockResolvedValue({});

    await issueTokenSet("user-1", "client-x", "openid", tx);

    expect(tx.user.findUnique).toHaveBeenCalledTimes(1);
    expect(tx.accessToken.create).toHaveBeenCalledTimes(1);
    expect(tx.refreshToken.create).toHaveBeenCalledTimes(1);
    // The default prisma must not be touched when a tx is provided.
    expect(prismaMock.user.findUnique).not.toHaveBeenCalled();
    expect(prismaMock.accessToken.create).not.toHaveBeenCalled();
    expect(prismaMock.refreshToken.create).not.toHaveBeenCalled();
  });

  it("propagates accessToken.create failure — refreshToken.create is NOT called (caller can roll back)", async () => {
    const tx = makeTxMock();
    tx.user.findUnique.mockResolvedValue(TEST_USER);
    tx.accessToken.create.mockRejectedValue(new Error("DB constraint violation"));
    tx.refreshToken.create.mockResolvedValue({});

    await expect(
      issueTokenSet("user-1", "client-x", "openid", tx),
    ).rejects.toThrow("DB constraint violation");

    // The whole point: refresh token write must NOT happen so the outer
    // transaction has a clean state to roll back.
    expect(tx.refreshToken.create).not.toHaveBeenCalled();
  });

  it("propagates refreshToken.create failure — error surfaces (outer tx rolls back)", async () => {
    const tx = makeTxMock();
    tx.user.findUnique.mockResolvedValue(TEST_USER);
    tx.accessToken.create.mockResolvedValue({});
    tx.refreshToken.create.mockRejectedValue(new Error("unique constraint"));

    await expect(
      issueTokenSet("user-1", "client-x", "openid", tx),
    ).rejects.toThrow("unique constraint");

    // accessToken.create may have run before the failure; that's fine —
    // the real $transaction() rolls back both. We only verify the error
    // is not swallowed.
    expect(tx.accessToken.create).toHaveBeenCalledTimes(1);
  });

  it("does not touch the top-level prisma client — writes go through tx only", async () => {
    const tx = makeTxMock();
    tx.user.findUnique.mockResolvedValue(TEST_USER);
    tx.accessToken.create.mockResolvedValue({});
    tx.refreshToken.create.mockResolvedValue({});

    await issueTokenSet("user-1", "client-x", "openid", tx);

    expect(tx.user.findUnique).toHaveBeenCalledTimes(1);
    expect(tx.accessToken.create).toHaveBeenCalledTimes(1);
    expect(tx.refreshToken.create).toHaveBeenCalledTimes(1);
    // Belt-and-suspenders: even if a future refactor accidentally
    // re-introduces a prisma fallback, this assertion will catch it.
    expect(prismaMock.user.findUnique).not.toHaveBeenCalled();
    expect(prismaMock.accessToken.create).not.toHaveBeenCalled();
    expect(prismaMock.refreshToken.create).not.toHaveBeenCalled();
  });
});
