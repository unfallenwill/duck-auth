/**
 * Unit tests for the new helpers added to lib/oauth/token-service.ts
 * by issue #29:
 *   - revokeToken (RFC 7009 logic)
 *   - getUserInfo (OIDC userinfo assembly)
 *   - exchangeAuthorizationCode + exchangeRefreshToken (extracted from
 *     /oauth/token so the in-process client can share the path)
 *
 * The pre-existing issueTokenSet tests live in token-service.test.ts.
 *
 * Mocking pattern: the hoisted block sets up the mock STRUCTURE
 * (vi.fn() instances). beforeEach uses vi.resetAllMocks() to wipe
 * implementations (vi.clearAllMocks() doesn't reliably do this in
 * vitest 1.x) and then re-establishes persistent defaults via
 * mockResolvedValue/mockImplementation. Tests that need a specific
 * value call mockResolvedValue(mockValue) which sets a new persistent
 * default for subsequent calls in that test.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock factories only — no implementations here. Defaults are set in
// beforeEach so they survive vi.resetAllMocks().
vi.mock("@/lib/generated/prisma-client", () => ({
  prisma: {
    user: { findUnique: vi.fn() },
    accessToken: {
      create: vi.fn(),
      findUnique: vi.fn(),
      update: vi.fn(),
    },
    refreshToken: {
      create: vi.fn(),
      findUnique: vi.fn(),
      update: vi.fn(),
      updateMany: vi.fn(),
    },
    authorizationCode: {
      findUnique: vi.fn(),
      updateMany: vi.fn(),
    },
    $transaction: vi.fn(),
  },
}));

vi.mock("@/lib/oauth/jwt", () => ({
  signAccessToken: vi.fn(),
  signIdToken: vi.fn(),
  verifyAccessToken: vi.fn(),
}));

vi.mock("@/lib/oauth/errors", () => ({
  OAuthError: class OAuthError extends Error {
    code: string;
    status: number;
    constructor(code: string, message?: string, status = 400) {
      super(message ?? code);
      this.code = code;
      this.status = status;
    }
  },
}));

vi.mock("@/lib/oauth/http", () => ({
  tokenResponse: vi.fn((b: Record<string, unknown>) => ({
    status: 200,
    body: b,
  })),
}));

vi.mock("@/lib/oauth/crypto", () => ({
  verifyPkceS256: vi.fn(
    (v: string, c: string) => v === "verifier" && c === "challenge",
  ),
  randomToken: vi.fn(() => "mock-refresh-token"),
}));

// Import AFTER mocks. Use prisma/jwt/crypto via the mocked modules.
import { prisma } from "@/lib/generated/prisma-client";
import {
  revokeToken,
  getUserInfo,
  exchangeAuthorizationCode,
  exchangeRefreshToken,
} from "@/lib/oauth/token-service";

const prismaMock = prisma as unknown as {
  user: { findUnique: ReturnType<typeof vi.fn> };
  accessToken: {
    create: ReturnType<typeof vi.fn>;
    findUnique: ReturnType<typeof vi.fn>;
    update: ReturnType<typeof vi.fn>;
  };
  refreshToken: {
    create: ReturnType<typeof vi.fn>;
    findUnique: ReturnType<typeof vi.fn>;
    update: ReturnType<typeof vi.fn>;
    updateMany: ReturnType<typeof vi.fn>;
  };
  authorizationCode: {
    findUnique: ReturnType<typeof vi.fn>;
    updateMany: ReturnType<typeof vi.fn>;
  };
  $transaction: ReturnType<typeof vi.fn>;
};

// We need access to the mocked jwt functions. Import them from the
// mocked module by reaching through the test-side reference. Since we
// use vi.mock with a factory, the functions are the vi.fn() instances
// we created in the factory. Reach them via the underlying module:
// but `vi.mock` hoists; we need to import the module dynamically or
// use vi.mocked(). The simplest: cast prismaMock-style access for jwt
// via the module's exported bindings. Since the mocked module IS the
// bindings we created, `import * as jwtMod from "@/lib/oauth/jwt"` and
// reading from it gives us the vi.fn instances.
import * as jwtMod from "@/lib/oauth/jwt";
const jwtMock = jwtMod as unknown as {
  signAccessToken: ReturnType<typeof vi.fn>;
  signIdToken: ReturnType<typeof vi.fn>;
  verifyAccessToken: ReturnType<typeof vi.fn>;
};

const FUTURE = new Date(Date.now() + 86400_000);
const USER_FIXTURE = { id: "u1", email: "x@y.z", name: "Alice" };
const ACCESS_ROW_VALID = {
  jti: "mock-jti",
  clientId: "c1",
  userId: "u1",
  revokedAt: null,
  expiresAt: new Date(Date.now() + 3600_000),
};

function setupDefaults() {
  prismaMock.user.findUnique.mockResolvedValue(USER_FIXTURE);
  prismaMock.accessToken.findUnique.mockImplementation(
    () => ACCESS_ROW_VALID,
  );
  prismaMock.refreshToken.findUnique.mockResolvedValue(null);
  prismaMock.refreshToken.updateMany.mockResolvedValue({ count: 0 });
  prismaMock.authorizationCode.findUnique.mockResolvedValue(null);
  prismaMock.authorizationCode.updateMany.mockResolvedValue({ count: 0 });
  jwtMock.signAccessToken.mockResolvedValue({
    token: "mock-access-token",
    jti: "mock-jti",
    expiresAt: new Date(Date.now() + 3600_000),
  });
  jwtMock.signIdToken.mockResolvedValue({
    token: "mock-id-token",
    expiresAt: new Date(Date.now() + 3600_000),
  });
  jwtMock.verifyAccessToken.mockResolvedValue({
    sub: "u1",
    jti: "mock-jti",
    scope: "openid",
  });
  prismaMock.$transaction.mockImplementation(
    async (fn: (tx: unknown) => unknown) => fn(prismaMock),
  );
}

beforeEach(() => {
  // vi.resetAllMocks wipes BOTH call history AND implementations. We
  // re-establish persistent defaults right after so each test starts
  // with a known-good baseline. Per-test mockResolvedValue calls then
  // override only for that test's call sequence.
  vi.resetAllMocks();
  setupDefaults();
});

// ────────────────────────────────────────────────────────────────────
// revokeToken
// ────────────────────────────────────────────────────────────────────

describe("revokeToken — refresh token path", () => {
  it("revokes when refresh token matches and belongs to client", async () => {
    prismaMock.refreshToken.findUnique.mockResolvedValue({
      token: "rt-1",
      clientId: "c1",
      revokedAt: null,
    });
    const result = await revokeToken("rt-1", "refresh_token", "c1");
    expect(result).toEqual({ revoked: true });
    expect(prismaMock.refreshToken.update).toHaveBeenCalledWith({
      where: { token: "rt-1" },
      data: { revokedAt: expect.any(Date) },
    });
  });

  it("returns revoked:false when refresh token already revoked", async () => {
    prismaMock.refreshToken.findUnique.mockResolvedValue({
      token: "rt-1",
      clientId: "c1",
      revokedAt: new Date(),
    });
    const result = await revokeToken("rt-1", "refresh_token", "c1");
    expect(result.revoked).toBe(false);
    expect(prismaMock.refreshToken.update).not.toHaveBeenCalled();
  });

  it("returns revoked:false when refresh token belongs to another client", async () => {
    prismaMock.refreshToken.findUnique.mockResolvedValue({
      token: "rt-1",
      clientId: "other-client",
      revokedAt: null,
    });
    const result = await revokeToken("rt-1", "refresh_token", "c1");
    expect(result.revoked).toBe(false);
  });

  it("with explicit refresh_token hint, returns revoked:false when refresh row missing (no fallthrough)", async () => {
    prismaMock.refreshToken.findUnique.mockResolvedValue(null);
    const result = await revokeToken("rt-1", "refresh_token", "c1");
    expect(result.revoked).toBe(false);
    expect(prismaMock.accessToken.update).not.toHaveBeenCalled();
  });
});

describe("revokeToken — access token path", () => {
  // Helper: build a JWT-shaped string whose payload decodes to the given
  // JSON object via base64url. revokeToken decodes without verifying
  // signature, so any 3-part string with a valid base64url payload works.
  function fakeJwt(payload: Record<string, unknown>): string {
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    return `header.${body}.sig`;
  }
  const GOOD_JWT = fakeJwt({ jti: "at-jti" });

  it("revokes when JWT decodes + jti matches + belongs to client", async () => {
    prismaMock.accessToken.findUnique.mockResolvedValue({
      jti: "at-jti",
      clientId: "c1",
      revokedAt: null,
    });
    const result = await revokeToken(GOOD_JWT, "access_token", "c1");
    expect(result.revoked).toBe(true);
    expect(prismaMock.accessToken.update).toHaveBeenCalledWith({
      where: { jti: "at-jti" },
      data: { revokedAt: expect.any(Date) },
    });
  });

  it("returns revoked:false when access token belongs to another client", async () => {
    prismaMock.accessToken.findUnique.mockResolvedValue({
      jti: "at-jti",
      clientId: "other-client",
      revokedAt: null,
    });
    const result = await revokeToken(GOOD_JWT, "access_token", "c1");
    expect(result.revoked).toBe(false);
  });

  it("returns revoked:false when access token already revoked", async () => {
    prismaMock.accessToken.findUnique.mockResolvedValue({
      jti: "at-jti",
      clientId: "c1",
      revokedAt: new Date(),
    });
    const result = await revokeToken(GOOD_JWT, "access_token", "c1");
    expect(result.revoked).toBe(false);
  });

  it("returns revoked:false for malformed JWT (no dots)", async () => {
    const result = await revokeToken("not-a-jwt", "access_token", "c1");
    expect(result.revoked).toBe(false);
  });

  it("returns revoked:false when JWT payload has no jti claim", async () => {
    const noJtiJwt = fakeJwt({ sub: "u1" });
    const result = await revokeToken(noJtiJwt, "access_token", "c1");
    expect(result.revoked).toBe(false);
  });
});

// ────────────────────────────────────────────────────────────────────
// getUserInfo
// ────────────────────────────────────────────────────────────────────

describe("getUserInfo", () => {
  it("returns null when verifyAccessToken throws (invalid signature)", async () => {
    jwtMock.verifyAccessToken.mockRejectedValue(new Error("bad sig"));
    expect(await getUserInfo("bad-token")).toBeNull();
  });

  it("returns null when access token row not found (DB out of sync)", async () => {
    prismaMock.accessToken.findUnique.mockResolvedValue(null);
    expect(await getUserInfo("at")).toBeNull();
  });

  it("returns null when access token row is revoked", async () => {
    prismaMock.accessToken.findUnique.mockResolvedValue({
      ...ACCESS_ROW_VALID,
      revokedAt: new Date(),
    });
    expect(await getUserInfo("at")).toBeNull();
  });

  it("returns null when access token row is expired", async () => {
    prismaMock.accessToken.findUnique.mockResolvedValue({
      ...ACCESS_ROW_VALID,
      expiresAt: new Date(Date.now() - 1000),
    });
    expect(await getUserInfo("at")).toBeNull();
  });

  it("returns null when user row missing", async () => {
    prismaMock.user.findUnique.mockResolvedValue(null);
    expect(await getUserInfo("at")).toBeNull();
  });

  it("returns sub only when scope has no email/profile claims", async () => {
    jwtMock.verifyAccessToken.mockResolvedValue({
      sub: "u1",
      jti: "mock-jti",
      scope: "openid",
    });
    const claims = await getUserInfo("at");
    expect(claims).toEqual({ sub: "u1" });
  });

  it("includes email when scope has email (email_verified always false until verification flow exists)", async () => {
    jwtMock.verifyAccessToken.mockResolvedValue({
      sub: "u1",
      jti: "mock-jti",
      scope: "openid email",
    });
    const claims = await getUserInfo("at");
    expect(claims).toMatchObject({
      sub: "u1",
      email: "x@y.z",
      email_verified: false,
    });
  });

  it("includes name when scope has profile", async () => {
    jwtMock.verifyAccessToken.mockResolvedValue({
      sub: "u1",
      jti: "mock-jti",
      scope: "openid profile",
    });
    const claims = await getUserInfo("at");
    expect(claims).toMatchObject({ sub: "u1", name: "Alice" });
  });
});

// ────────────────────────────────────────────────────────────────────
// exchangeAuthorizationCode
// ────────────────────────────────────────────────────────────────────

describe("exchangeAuthorizationCode", () => {
  it("throws invalid_grant when expired", async () => {
    await expect(
      exchangeAuthorizationCode({
        code: "abc",
        redirectUri: "https://cb",
        codeVerifier: "v",
        clientId: "c1",
        authorizationCode: {
          userId: "u1",
          clientId: "c1",
          redirectUri: "https://cb",
          scopes: "openid",
          expiresAt: new Date(Date.now() - 1000),
          usedAt: null,
          codeChallenge: null,
          codeChallengeMethod: null,
        },
        verifyPkceS256: (v, c) => v === "verifier" && c === "challenge",
      }),
    ).rejects.toThrow(/code expired/i);
  });

  it("throws invalid_grant when clientId mismatches", async () => {
    await expect(
      exchangeAuthorizationCode({
        code: "abc",
        redirectUri: "https://cb",
        codeVerifier: "v",
        clientId: "c1",
        authorizationCode: {
          userId: "u1",
          clientId: "other-client",
          redirectUri: "https://cb",
          scopes: "openid",
          expiresAt: FUTURE,
          usedAt: null,
          codeChallenge: null,
          codeChallengeMethod: null,
        },
        verifyPkceS256: (v, c) => v === "verifier" && c === "challenge",
      }),
    ).rejects.toThrow(/different client/i);
  });

  it("throws invalid_grant when redirect_uri mismatches", async () => {
    await expect(
      exchangeAuthorizationCode({
        code: "abc",
        redirectUri: "https://cb",
        codeVerifier: "v",
        clientId: "c1",
        authorizationCode: {
          userId: "u1",
          clientId: "c1",
          redirectUri: "https://other",
          scopes: "openid",
          expiresAt: FUTURE,
          usedAt: null,
          codeChallenge: null,
          codeChallengeMethod: null,
        },
        verifyPkceS256: (v, c) => v === "verifier" && c === "challenge",
      }),
    ).rejects.toThrow(/redirect_uri does not match/i);
  });

  it("throws invalid_request when codeChallenge present but verifier missing", async () => {
    await expect(
      exchangeAuthorizationCode({
        code: "abc",
        redirectUri: "https://cb",
        codeVerifier: null,
        clientId: "c1",
        authorizationCode: {
          userId: "u1",
          clientId: "c1",
          redirectUri: "https://cb",
          scopes: "openid",
          expiresAt: FUTURE,
          usedAt: null,
          codeChallenge: "challenge",
          codeChallengeMethod: "S256",
        },
        verifyPkceS256: (v, c) => v === "verifier" && c === "challenge",
      }),
    ).rejects.toThrow(/code_verifier is required/i);
  });

  it("throws invalid_grant when PKCE S256 verification fails", async () => {
    await expect(
      exchangeAuthorizationCode({
        code: "abc",
        redirectUri: "https://cb",
        codeVerifier: "wrong-verifier",
        clientId: "c1",
        authorizationCode: {
          userId: "u1",
          clientId: "c1",
          redirectUri: "https://cb",
          scopes: "openid",
          expiresAt: FUTURE,
          usedAt: null,
          codeChallenge: "challenge",
          codeChallengeMethod: "S256",
        },
        verifyPkceS256: (v, c) => v === "verifier" && c === "challenge",
      }),
    ).rejects.toThrow(/PKCE verification failed/i);
  });

  it("throws invalid_grant when code already used (CAS returns 0)", async () => {
    prismaMock.authorizationCode.updateMany.mockResolvedValue({ count: 0 });
    await expect(
      exchangeAuthorizationCode({
        code: "abc",
        redirectUri: "https://cb",
        codeVerifier: "v",
        clientId: "c1",
        authorizationCode: {
          userId: "u1",
          clientId: "c1",
          redirectUri: "https://cb",
          scopes: "openid",
          expiresAt: FUTURE,
          usedAt: null,
          codeChallenge: null,
          codeChallengeMethod: null,
        },
        verifyPkceS256: (v, c) => v === "verifier" && c === "challenge",
      }),
    ).rejects.toThrow(/code already used/i);
  });
});

// ────────────────────────────────────────────────────────────────────
// exchangeRefreshToken
// ────────────────────────────────────────────────────────────────────

describe("exchangeRefreshToken", () => {
  it("throws invalid_grant when expired", async () => {
    await expect(
      exchangeRefreshToken({
        refreshToken: "rt-old",
        clientId: "c1",
        refreshTokenRecord: {
          userId: "u1",
          clientId: "c1",
          scopes: "openid",
          expiresAt: new Date(Date.now() - 1000),
          revokedAt: null,
        },
      }),
    ).rejects.toThrow(/refresh token expired/i);
  });

  it("throws invalid_grant when clientId mismatches", async () => {
    await expect(
      exchangeRefreshToken({
        refreshToken: "rt-old",
        clientId: "c1",
        refreshTokenRecord: {
          userId: "u1",
          clientId: "other-client",
          scopes: "openid",
          expiresAt: FUTURE,
          revokedAt: null,
        },
      }),
    ).rejects.toThrow(/belongs to a different client/i);
  });

  it("throws invalid_grant when CAS revoke returns 0 (already rotated)", async () => {
    prismaMock.refreshToken.updateMany.mockResolvedValue({ count: 0 });
    await expect(
      exchangeRefreshToken({
        refreshToken: "rt-old",
        clientId: "c1",
        refreshTokenRecord: {
          userId: "u1",
          clientId: "c1",
          scopes: "openid",
          expiresAt: FUTURE,
          revokedAt: null,
        },
      }),
    ).rejects.toThrow(/revoked or already rotated/i);
  });
});
