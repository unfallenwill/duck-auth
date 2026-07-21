/**
 * Unit tests for lib/oauth/errors.ts.
 */
import { describe, it, expect } from "vitest";
import { authorizeError, tokenError, type OAuthErrorCode } from "@/lib/oauth/errors";

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