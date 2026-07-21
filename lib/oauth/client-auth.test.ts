/**
 * Unit tests for lib/oauth/client-auth.ts.
 *
 * Prisma is mocked via vi.mock so these tests run without a real DB.
 * The mock replaces the entire prisma export with stubs whose findUnique
 * returns whatever we configure for each test case.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// vi.hoisted is required to share a mutable mock function between the
// vi.mock factory (which runs at hoist time, before any other code) and
// the test bodies (which run later and need to configure the mock).
const { mockFindUnique } = vi.hoisted(() => ({
  mockFindUnique: vi.fn(),
}));

vi.mock("@/lib/generated/prisma-client", () => ({
  prisma: {
    client: {
      findUnique: mockFindUnique,
    },
  },
}));

// We do NOT mock crypto.ts — instead we ensure our test's mock client
// records a secretHash that's syntactically valid AND uses a real
// hash so verifyClientSecret can match it. The function under test
// needs the real crypto to work.

// Now import the modules under test (the mock has been registered).
import { hashClientSecret } from "@/lib/oauth/crypto";
import {
  authenticateClient,
  readFormBody,
  tokenResponse,
} from "@/lib/oauth/client-auth";

function makeReq(headers: Record<string, string> = {}): Request {
  return new Request("http://x/test", { headers });
}

// Precompute the encoded basic header at module load for debugging.
console.log(
  "[debug] basic auth for c1:VALID-SECRET:",
  "Basic " + Buffer.from("c1:VALID-SECRET").toString("base64"),
);

function basicAuth(id: string, secret: string): Record<string, string> {
  return {
    Authorization:
      "Basic " + Buffer.from(`${id}:${secret}`).toString("base64"),
  };
}

beforeEach(() => {
  mockFindUnique.mockReset();
});

describe("authenticateClient — Basic auth header", () => {
  it("accepts valid Basic credentials", async () => {
    const secretHash = hashClientSecret("VALID-SECRET");
    mockFindUnique.mockResolvedValueOnce({ id: "c1", secretHash });
    const req = makeReq(basicAuth("c1", "VALID-SECRET"));
    const r = await authenticateClient(req, new URLSearchParams());
    expect(r).toEqual({ clientId: "c1" });
    expect(mockFindUnique).toHaveBeenCalledWith({ where: { id: "c1" } });
  });

  it("returns null when header doesn't start with 'basic '", async () => {
    const req = makeReq({ Authorization: "Bearer foo" });
    expect(
      await authenticateClient(req, makeForm({ client_id: "c1", client_secret: "x" })),
    ).toBeNull();
  });

  it("returns null on malformed base64 in header", async () => {
    const req = makeReq({ Authorization: "Basic !!!not-base64!!!" });
    // atob throws → caught → return null
    expect(await authenticateClient(req, new URLSearchParams())).toBeNull();
  });

  it("returns null when decoded payload has no colon", async () => {
    const req = makeReq({
      Authorization: "***" + Buffer.from("nocolonhere").toString("base64"),
    });
    expect(await authenticateClient(req, new URLSearchParams())).toBeNull();
  });

  it("returns null when client doesn't exist in DB", async () => {
    mockFindUnique.mockResolvedValueOnce(null);
    const req = makeReq(basicAuth("missing", "x"));
    expect(await authenticateClient(req, new URLSearchParams())).toBeNull();
  });

  it("returns null when secret hash doesn't match", async () => {
    const secretHash = hashClientSecret("VALID-SECRET");
    mockFindUnique.mockResolvedValueOnce({ id: "c1", secretHash });
    const req = makeReq(basicAuth("c1", "wrong-secret"));
    expect(await authenticateClient(req, new URLSearchParams())).toBeNull();
  });

  it("returns null when secret portion is empty", async () => {
    // id="c1", secret="" — both fields populated but secret empty.
    const req = makeReq(basicAuth("c1", ""));
    expect(await authenticateClient(req, new URLSearchParams())).toBeNull();
  });
});

describe("authenticateClient — body credentials", () => {
  it("falls back to form body when no Authorization header", async () => {
    const secretHash = hashClientSecret("VALID-SECRET");
    mockFindUnique.mockResolvedValueOnce({ id: "c2", secretHash });
    const req = makeReq();
    const form = makeForm({ client_id: "c2", client_secret: "VALID-SECRET" });
    expect(await authenticateClient(req, form)).toEqual({ clientId: "c2" });
  });

  it("uses Authorization header when both are present (header wins)", async () => {
    const secretHash = hashClientSecret("VALID-SECRET");
    mockFindUnique.mockResolvedValueOnce({ id: "c3", secretHash });
    const req = makeReq(basicAuth("c3", "VALID-SECRET"));
    const form = makeForm({ client_id: "c3", client_secret: "body-secret" });
    expect(await authenticateClient(req, form)).toEqual({ clientId: "c3" });
  });

  it("returns null when neither header nor body provide credentials", async () => {
    const req = makeReq();
    expect(await authenticateClient(req, new URLSearchParams())).toBeNull();
  });

  it("returns null when body has only client_id (no secret)", async () => {
    const req = makeReq();
    const form = makeForm({ client_id: "c4" });
    expect(await authenticateClient(req, form)).toBeNull();
  });
});

function makeForm(data: Record<string, string>): URLSearchParams {
  return new URLSearchParams(data);
}

describe("readFormBody", () => {
  it("parses application/x-www-form-urlencoded body", async () => {
    const req = new Request("http://x/", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "grant_type=authorization_code&code=abc",
    });
    const form = await readFormBody(req);
    expect(form.get("grant_type")).toBe("authorization_code");
    expect(form.get("code")).toBe("abc");
  });

  it("parses application/json body into URLSearchParams", async () => {
    const req = new Request("http://x/", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: "abc", token_type_hint: "access_token" }),
    });
    const form = await readFormBody(req);
    expect(form.get("token")).toBe("abc");
    expect(form.get("token_type_hint")).toBe("access_token");
  });

  it("falls back to text() for unknown content types", async () => {
    const req = new Request("http://x/", {
      method: "POST",
      body: "foo=bar&baz=qux",
    });
    const form = await readFormBody(req);
    expect(form.get("foo")).toBe("bar");
    expect(form.get("baz")).toBe("qux");
  });
});

describe("tokenResponse", () => {
  it("sets the no-cache headers required by RFC 6749 §5.1", async () => {
    const res = tokenResponse({ access_token: "abc" });
    expect(res.status).toBe(200);
    expect(res.headers.get("cache-control")).toBe("no-store");
    expect(res.headers.get("pragma")).toBe("no-cache");
    expect(res.headers.get("content-type")).toMatch(/json/);
    expect(await res.json()).toEqual({ access_token: "abc" });
  });

  it("handles empty body objects", async () => {
    const res = tokenResponse({});
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({});
  });
});