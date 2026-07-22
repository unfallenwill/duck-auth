/**
 * Unit tests for lib/oauth/errors.ts.
 */
import { describe, it, expect } from "vitest";
import {
  authorizeError,
  tokenError,
  OAuthError,
  type OAuthErrorCode,
} from "@/lib/oauth/errors";

describe("authorizeError", () => {
  it("builds a redirect URL with error + state", () => {
    const u = authorizeError(
      "https://client.example/cb",
      "xyz",
      "invalid_scope",
      "out of scope",
    );
    expect(u.host).toBe("client.example");
    expect(u.pathname).toBe("/cb");
    expect(u.searchParams.get("error")).toBe("invalid_scope");
    expect(u.searchParams.get("error_description")).toBe("out of scope");
    expect(u.searchParams.get("state")).toBe("xyz");
  });

  it("uses default description when not provided", () => {
    const u = authorizeError(
      "https://x/cb",
      undefined,
      "access_denied",
    );
    expect(u.searchParams.get("error")).toBe("access_denied");
    expect(u.searchParams.get("error_description")).toBeTruthy();
    expect(u.searchParams.has("state")).toBe(false);
  });

  it("preserves existing query params on the redirect_uri", () => {
    const u = authorizeError(
      "https://x/cb?foo=bar",
      "s",
      "server_error",
    );
    expect(u.searchParams.get("foo")).toBe("bar");
    expect(u.searchParams.get("error")).toBe("server_error");
  });
});

describe("tokenError", () => {
  it("returns 400 JSON by default with code + description", async () => {
    const res = tokenError("invalid_grant", "Token expired");
    expect(res.status).toBe(400);
    expect(res.headers.get("content-type")).toMatch(/json/);
    const body = await res.json();
    expect(body).toEqual({
      error: "invalid_grant",
      error_description: "Token expired",
    });
  });

  it("accepts a custom status code (e.g. 500 for server_error)", async () => {
    const res = tokenError("server_error", "oops", 500);
    expect(res.status).toBe(500);
  });

  it("uses default description when omitted", async () => {
    const res = tokenError("invalid_request");
    const body = await res.json();
    expect(body["error_description"]).toBeTruthy();
  });

  it("supports every OAuthErrorCode value without crashing", () => {
    const codes: OAuthErrorCode[] = [
      "invalid_request",
      "invalid_client",
      "invalid_grant",
      "unauthorized_client",
      "unsupported_grant_type",
      "unsupported_response_type",
      "invalid_scope",
      "access_denied",
      "server_error",
      "temporarily_unavailable",
    ];
    for (const c of codes) {
      const res = tokenError(c);
      expect(res.status).toBeGreaterThanOrEqual(400);
    }
  });
});

describe("OAuthError", () => {
  it("is an Error subclass with code, status, and the default description", () => {
    const err = new OAuthError("invalid_grant");
    expect(err).toBeInstanceOf(Error);
    expect(err.name).toBe("OAuthError");
    expect(err.code).toBe("invalid_grant");
    expect(err.status).toBe(400);
    expect(err.message).toBeTruthy();
  });

  it("server_error defaults to 500", () => {
    expect(new OAuthError("server_error").status).toBe(500);
  });

  it("temporarily_unavailable defaults to 503 (RFC 6749 §5.2 SHOULD)", () => {
    expect(new OAuthError("temporarily_unavailable").status).toBe(503);
  });

  it("all client-class error codes default to 400", () => {
    const clientClassCodes = [
      "invalid_request",
      "invalid_client",
      "invalid_grant",
      "unauthorized_client",
      "unsupported_grant_type",
      "unsupported_response_type",
      "invalid_scope",
      "access_denied",
    ] as const;
    for (const code of clientClassCodes) {
      expect(new OAuthError(code).status).toBe(400);
    }
  });

  it("lets the caller override the status (e.g. 503 for service unavailable)", () => {
    const err = new OAuthError("server_error", "DB is down", 503);
    expect(err.status).toBe(503);
    expect(err.message).toBe("DB is down");
    expect(err.code).toBe("server_error");
  });

  it("falls back to the default description when none is provided", () => {
    const err = new OAuthError("invalid_grant");
    // The default description comes from ERROR_DESCRIPTIONS — must be
    // a non-empty string, not the literal error code.
    expect(err.message).not.toBe("invalid_grant");
    expect(err.message.length).toBeGreaterThan(10);
  });
});