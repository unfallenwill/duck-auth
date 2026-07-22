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
    const data = await issueTokenSet("user-1", "client-x", "openid profile", txClient);
    expect(data.access_token).toBe("mock-access-token");
    expect(data.token_type).toBe("Bearer");
    expect(data.expires_in).toBe(3600);
    expect(data.refresh_token).toBe("mock-refresh-token");
    expect(data.scope).toBe("openid profile");
    expect(data.id_token).toBe("mock-id-token");
  });

  it("persists access token and refresh token to the DB", async () => {
    await issueTokenSet("user-1", "client-x", "openid", txClient);
    expect(prismaMock.accessToken.create).toHaveBeenCalledTimes(1);
    expect(prismaMock.refreshToken.create).toHaveBeenCalledTimes(1);
  });
});

describe("issueTokenSet – scope without openid", () => {
  it("omits id_token when scope does not include openid", async () => {
    const data = await issueTokenSet("user-1", "client-x", "profile email", txClient);
    expect(data.access_token).toBe("mock-access-token");
    expect(data.refresh_token).toBe("mock-refresh-token");
    expect(data.id_token).toBeUndefined();
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
    expect(callArg.email).toBeUndefined();
    expect(callArg.name).toBeUndefined();
  });
});

describe("issueTokenSet – conditional claims", () => {
  it("includes email claim when scope includes email", async () => {
    vi.mocked(signIdToken).mockClear();
    await issueTokenSet("user-1", "client-x", "openid email", txClient);
    const callArg = vi.mocked(signIdToken).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect(callArg.email).toBe("alice@example.com");
  });

  it("includes name claim when scope includes profile", async () => {
    vi.mocked(signIdToken).mockClear();
    await issueTokenSet("user-1", "client-x", "openid profile", txClient);
    const callArg = vi.mocked(signIdToken).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect(callArg.name).toBe("Alice");
  });

  it("includes both email and name when scope is openid profile email", async () => {
    vi.mocked(signIdToken).mockClear();
    await issueTokenSet("user-1", "client-x", "openid profile email", txClient);
    const callArg = vi.mocked(signIdToken).mock.calls[0][0] as Record<
      string,
      unknown
    >;
    expect(callArg.email).toBe("alice@example.com");
    expect(callArg.name).toBe("Alice");
  });
});

describe("issueTokenSet – atomicity (user missing)", () => {
  it("throws OAuthError when user not found (causes tx rollback)", async () => {
    prismaMock.user.findUnique.mockResolvedValueOnce(null);
    await expect(
      issueTokenSet("missing-user", "client-x", "openid", txClient),
    ).rejects.toThrow(/user record missing/i);
  });

  it("does NOT call signAccessToken when user lookup fails", async () => {
    prismaMock.user.findUnique.mockResolvedValueOnce(null);
    vi.mocked(signAccessToken).mockClear();
    await expect(
      issueTokenSet("missing-user", "client-x", "openid", txClient),
    ).rejects.toThrow();
    expect(signAccessToken).not.toHaveBeenCalled();
  });

  it("does NOT create accessToken row when user lookup fails", async () => {
    prismaMock.user.findUnique.mockResolvedValueOnce(null);
    prismaMock.accessToken.create.mockClear();
    await expect(
      issueTokenSet("missing-user", "client-x", "openid", txClient),
    ).rejects.toThrow();
    expect(prismaMock.accessToken.create).not.toHaveBeenCalled();
  });
});
