/**
 * Unit tests for lib/oauth/discovery.ts.
 */
import { describe, it, expect } from "vitest";
import {
  SUPPORTED_SCOPES,
  discoveryDocument,
  filterScopes,
  parseScopes,
} from "@/lib/oauth/discovery";

describe("SUPPORTED_SCOPES", () => {
  it("is the canonical list", () => {
    expect([...SUPPORTED_SCOPES]).toEqual(["openid", "profile", "email"]);
  });
});

describe("parseScopes", () => {
  it("splits space-separated scope strings", () => {
    expect(parseScopes("openid profile email")).toEqual([
      "openid",
      "profile",
      "email",
    ]);
  });

  it("dedupes", () => {
    expect(parseScopes("openid openid profile")).toEqual(["openid", "profile"]);
  });

  it("filters empty segments", () => {
    expect(parseScopes("  openid   profile  ")).toEqual(["openid", "profile"]);
  });

  it("returns empty for empty input", () => {
    expect(parseScopes("")).toEqual([]);
    expect(parseScopes("   ")).toEqual([]);
  });
});

describe("filterScopes", () => {
  it("returns valid scopes that are both supported AND in allowed", () => {
    const r = filterScopes(["openid", "profile"], "openid profile email");
    expect(r.valid).toEqual(["openid", "profile"]);
    expect(r.invalid).toEqual([]);
  });

  it("rejects unsupported scopes", () => {
    const r = filterScopes(["openid", "admin"], "openid admin");
    // 'admin' is not in SUPPORTED_SCOPES
    expect(r.valid).toEqual(["openid"]);
    expect(r.invalid).toEqual(["admin"]);
  });

  it("rejects scopes not in client's allowed list", () => {
    const r = filterScopes(["openid", "email"], "openid");
    expect(r.valid).toEqual(["openid"]);
    expect(r.invalid).toEqual(["email"]);
  });

  it("reports all invalid in one pass", () => {
    const r = filterScopes(["bogus", "admin", "openid"], "openid");
    expect(r.valid).toEqual(["openid"]);
    expect(r.invalid).toEqual(["bogus", "admin"]);
  });
});

describe("discoveryDocument", () => {
  it("advertises all required endpoints with the issuer prefix", () => {
    const d = discoveryDocument() as unknown as Record<string, unknown>;
    expect(d["issuer"]).toMatch(/^https?:\/\//);
    expect(d["authorization_endpoint"]).toMatch(/\/oauth\/authorize$/);
    expect(d["token_endpoint"]).toMatch(/\/oauth\/token$/);
    expect(d["userinfo_endpoint"]).toMatch(/\/oauth\/userinfo$/);
    expect(d["jwks_uri"]).toMatch(/\/oauth\/jwks$/);
    expect(d["revocation_endpoint"]).toMatch(/\/oauth\/revoke$/);
    expect(d["end_session_endpoint"]).toMatch(/\/api\/auth\/logout$/);
  });

  it("declares only supported features (no implicit / hybrid / etc.)", () => {
    const d = discoveryDocument() as unknown as Record<string, string[]>;
    expect(d["response_types_supported"]).toEqual(["code"]);
    expect(d["grant_types_supported"]).toContain("authorization_code");
    expect(d["grant_types_supported"]).toContain("refresh_token");
    expect(d["code_challenge_methods_supported"]).toEqual(["S256"]);
    expect(d["id_token_signing_alg_values_supported"]).toEqual(["RS256"]);
  });

  it("includes the union of all supported scopes", () => {
    const d = discoveryDocument() as unknown as { scopes_supported: string[] };
    expect(d.scopes_supported).toEqual([...SUPPORTED_SCOPES]);
  });
});