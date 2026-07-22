/**
 * Unit tests for lib/oauth-client.ts.
 *
 * Mocks lib/oauth/token-service.ts + prisma + crypto to exercise the
 * in-process OAuth client wrapper without hitting the DB or signing keys.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

const { prismaMock, serviceMock, cryptoMock } = vi.hoisted(() => {
  return {
    prismaMock: {
      authorizationCode: { findUnique: vi.fn() },
      refreshToken: { findUnique: vi.fn() },
    },
    serviceMock: {
      exchangeAuthorizationCode: vi.fn(),
      exchangeRefreshToken: vi.fn(),
      revokeToken: vi.fn(),
      getUserInfo: vi.fn(),
    },
    cryptoMock: {
      verifyPkceS256: vi.fn(),
    },
  };
});

vi.mock("@/lib/generated/prisma-client", () => ({
  prisma: prismaMock,
}));

vi.mock("@/lib/oauth/token-service", () => serviceMock);

vi.mock("@/lib/oauth/crypto", () => cryptoMock);

// Import AFTER mocks.
import {
  exchangeCode,
  refreshTokens,
  revoke,
  userinfo,
} from "@/lib/oauth-client";

const FAKE_TOKEN_SET = {
  access_token: "at",
  token_type: "Bearer" as const,
  expires_in: 3600,
  refresh_token: "rt",
  scope: "openid",
  id_token: "idt",
};

beforeEach(() => {
  vi.clearAllMocks();
});

describe("exchangeCode", () => {
  it("looks up the auth code record, then calls exchangeAuthorizationCode", async () => {
    prismaMock.authorizationCode.findUnique.mockResolvedValueOnce({
      code: "abc",
      userId: "u1",
      clientId: "c1",
      redirectUri: "https://cb",
      scopes: "openid",
      expiresAt: new Date(Date.now() + 60000),
      usedAt: null,
      codeChallenge: null,
      codeChallengeMethod: null,
    });
    serviceMock.exchangeAuthorizationCode.mockResolvedValueOnce(FAKE_TOKEN_SET);

    const result = await exchangeCode({
      code: "abc",
      redirectUri: "https://cb",
      codeVerifier: "v",
      clientId: "c1",
    });

    expect(prismaMock.authorizationCode.findUnique).toHaveBeenCalledWith({
      where: { code: "abc" },
    });
    expect(serviceMock.exchangeAuthorizationCode).toHaveBeenCalledWith(
      expect.objectContaining({
        code: "abc",
        redirectUri: "https://cb",
        codeVerifier: "v",
        clientId: "c1",
        verifyPkceS256: cryptoMock.verifyPkceS256,
      }),
    );
    expect(result).toEqual(FAKE_TOKEN_SET);
  });

  it("throws when auth code not found", async () => {
    prismaMock.authorizationCode.findUnique.mockResolvedValueOnce(null);
    await expect(
      exchangeCode({
        code: "missing",
        redirectUri: "https://cb",
        codeVerifier: "v",
        clientId: "c1",
      }),
    ).rejects.toThrow(/unknown code/i);
  });

  it("passes null codeVerifier for non-PKCE flows", async () => {
    prismaMock.authorizationCode.findUnique.mockResolvedValueOnce({
      code: "abc",
      userId: "u1",
      clientId: "c1",
      redirectUri: "https://cb",
      scopes: "openid",
      expiresAt: new Date(Date.now() + 60000),
      usedAt: null,
      codeChallenge: null,
      codeChallengeMethod: null,
    });
    serviceMock.exchangeAuthorizationCode.mockResolvedValueOnce(FAKE_TOKEN_SET);

    await exchangeCode({
      code: "abc",
      redirectUri: "https://cb",
      codeVerifier: null,
      clientId: "c1",
    });
    expect(serviceMock.exchangeAuthorizationCode).toHaveBeenCalledWith(
      expect.objectContaining({ codeVerifier: null }),
    );
  });
});

describe("refreshTokens", () => {
  it("looks up the refresh token, then calls exchangeRefreshToken", async () => {
    prismaMock.refreshToken.findUnique.mockResolvedValueOnce({
      token: "rt-old",
      userId: "u1",
      clientId: "c1",
      scopes: "openid",
      expiresAt: new Date(Date.now() + 86400_000),
      revokedAt: null,
    });
    serviceMock.exchangeRefreshToken.mockResolvedValueOnce(FAKE_TOKEN_SET);

    const result = await refreshTokens({
      refreshToken: "rt-old",
      clientId: "c1",
    });

    expect(prismaMock.refreshToken.findUnique).toHaveBeenCalledWith({
      where: { token: "rt-old" },
    });
    expect(result).toEqual(FAKE_TOKEN_SET);
  });

  it("throws when refresh token not found", async () => {
    prismaMock.refreshToken.findUnique.mockResolvedValueOnce(null);
    await expect(
      refreshTokens({ refreshToken: "missing", clientId: "c1" }),
    ).rejects.toThrow(/unknown refresh token/i);
  });
});

describe("revoke", () => {
  it("calls service.revokeToken with the same args", async () => {
    serviceMock.revokeToken.mockResolvedValueOnce({ revoked: true });
    await revoke({ token: "x", hint: "access_token", clientId: "c1" });
    expect(serviceMock.revokeToken).toHaveBeenCalledWith(
      "x",
      "access_token",
      "c1",
    );
  });

  it("passes undefined hint when not provided", async () => {
    serviceMock.revokeToken.mockResolvedValueOnce({ revoked: false });
    await revoke({ token: "x", clientId: "c1" });
    expect(serviceMock.revokeToken).toHaveBeenCalledWith(
      "x",
      undefined,
      "c1",
    );
  });

  it("swallows service errors (best-effort, matches logout contract)", async () => {
    serviceMock.revokeToken.mockRejectedValueOnce(new Error("db down"));
    // Should NOT throw — logout is best-effort by design.
    await expect(
      revoke({ token: "x", clientId: "c1" }),
    ).resolves.toBeUndefined();
  });
});

describe("userinfo", () => {
  it("returns claims on success", async () => {
    const claims = { sub: "u1", email: "x@y.z", email_verified: false };
    serviceMock.getUserInfo.mockResolvedValueOnce(claims);
    const result = await userinfo("at");
    expect(serviceMock.getUserInfo).toHaveBeenCalledWith("at");
    expect(result).toEqual(claims);
  });

  it("returns null when service returns null (invalid/expired/revoked token)", async () => {
    serviceMock.getUserInfo.mockResolvedValueOnce(null);
    expect(await userinfo("bad")).toBeNull();
  });
});
