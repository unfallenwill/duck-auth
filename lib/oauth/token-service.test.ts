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

beforeEach(() => {
  prismaMock.user.findUnique.mockResolvedValue(TEST_USER);
  prismaMock.accessToken.create.mockResolvedValue({});
  prismaMock.refreshToken.create.mockResolvedValue({});
  vi.clearAllMocks();
  // Re-set defaults after clearAllMocks clears mock return values too.
  vi.mocked(signAccessToken).mockResolvedValue({
    token: "mock-access-token",
    jti: "mock-jti",
    expiresAt: new Date(Date.now() + 3600_000),
  });
  vi.mocked(signIdToken).mockResolvedValue({
    token: "mock-id-token",
    expiresAt: new Date(Date.now() + 3600_000),
  });
});

describe("issueTokenSet – normal flow", () => {
  it("returns access_token + refresh_token + id_token when scope includes openid", async () => {
    const res = await issueTokenSet("user-1", "client-x", "openid profile");
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
    await issueTokenSet("user-1", "client-x", "openid");
    expect(prismaMock.accessToken.create).toHaveBeenCalledTimes(1);
    expect(prismaMock.refreshToken.create).toHaveBeenCalledTimes(1);
  });
});

describe("issueTokenSet – scope without openid", () => {
  it("omits id_token when scope does not include openid", async () => {
    const res = await issueTokenSet("user-1", "client-x", "profile email");
    const body = await res.json();
    expect(body.access_token).toBe("mock-access-token");
    expect(body.refresh_token).toBe("mock-refresh-token");
    expect(body.id_token).toBeUndefined();
  });
});

describe("issueTokenSet – openid-only scope", () => {
  it("id_token is issued but without email/name claims", async () => {
    vi.mocked(signIdToken).mockClear();

    await issueTokenSet("user-1", "client-x", "openid");

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

    await issueTokenSet("user-1", "client-x", "openid email");

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
  it("returns 500 server_error when user record is missing", async () => {
    prismaMock.user.findUnique.mockResolvedValue(null);

    const res = await issueTokenSet("nonexistent", "client-x", "openid");
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe("server_error");
    expect(body.error_description).toBeTruthy();
    // Should not attempt to persist tokens.
    expect(prismaMock.accessToken.create).not.toHaveBeenCalled();
    expect(prismaMock.refreshToken.create).not.toHaveBeenCalled();
  });
});
