/**
 * Browser-simulation test: follows every redirect with a cookie jar, just
 * like a real browser. Checks that Set-Cookie headers actually arrive on
 * each response (the bug was cookies being lost on Response.redirect).
 */
import { SignJWT } from "jose";

const BASE = "http://localhost:3000";

class Jar {
  store = new Map<string, string>();
  capture(headers: Headers) {
    const setCookies = headers.getSetCookie?.() ?? [];
    for (const sc of setCookies) {
      const [pair] = sc.split(";");
      const eq = pair.indexOf("=");
      if (eq > 0) {
        this.store.set(pair.slice(0, eq).trim(), pair.slice(eq + 1).trim());
      }
    }
  }
  header() {
    return Array.from(this.store.entries())
      .map(([k, v]) => `${k}=${v}`)
      .join("; ");
  }
  names() {
    return Array.from(this.store.keys());
  }
}

/** Fetch with automatic redirect following + cookie capture. */
async function go(
  jar: Jar,
  url: string,
  init: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (jar.store.size > 0) headers.set("Cookie", jar.header());
  const res = await fetch(url, { ...init, headers, redirect: "manual" });
  jar.capture(res.headers);
  return res;
}

async function main() {
  const jar = new Jar();

  // ----- Inject session cookie directly (same way e2e/flow.ts does) -----
  const sessionSecret = new TextEncoder().encode(
    process.env["OAUTH_SESSION_SECRET"] ??
      "dev-only-change-me-32-bytes-please-please",
  );
  const userId = process.argv[2] ?? "cmruhiqi30000xctf72q918j1";
  const sessionJwt = await new SignJWT({ uid: userId })
    .setProtectedHeader({ alg: "HS256", typ: "session" })
    .setIssuedAt(Math.floor(Date.now() / 1000))
    .setExpirationTime(Math.floor(Date.now() / 1000) + 3600)
    .sign(sessionSecret);
  jar.store.set("oauth_session", sessionJwt);
  console.log(`✓ injected session cookie (uid=${userId})`);

  // ----- 1. /api/auth/login -----
  let res = await go(jar, `${BASE}/api/auth/login`);
  console.log(`✓ /api/auth/login → ${res.status} (location: ${res.headers.get("location")})`);
  console.log(`  cookies after: [${jar.names().join(", ")}]`);
  if (!res.headers.get("location")?.includes("/oauth/authorize")) {
    console.error("Expected redirect to /oauth/authorize");
    process.exit(1);
  }

  // ----- 2. /oauth/authorize -----
  // Note: alice already has consent for demo-client from previous runs.
  res = await go(jar, res.headers.get("location")!);
  console.log(`✓ /oauth/authorize → ${res.status} (location: ${res.headers.get("location")?.slice(0, 80)}...)`);
  if (res.status !== 302) {
    console.error("Expected 302 from authorize");
    process.exit(1);
  }

  // ----- 3. /api/auth/callback -----
  res = await go(jar, res.headers.get("location")!);
  console.log(`✓ /api/auth/callback → ${res.status} (location: ${res.headers.get("location")})`);
  console.log(`  cookies after callback: [${jar.names().join(", ")}]`);

  // KEY CHECK: must have oauth_access_token in jar.
  if (!jar.store.has("oauth_access_token")) {
    console.error("✗ BUG: oauth_access_token not set on callback response!");
    process.exit(1);
  }
  console.log(`✓ oauth_access_token present (${jar.store.get("oauth_access_token")!.slice(0, 20)}...)`);

  if (!jar.store.has("oauth_refresh_token")) {
    console.error("✗ BUG: oauth_refresh_token not set on callback response!");
    process.exit(1);
  }
  console.log(`✓ oauth_refresh_token present`);

  // ----- 4. / (homepage) -----
  res = await go(jar, res.headers.get("location")!);
  console.log(`✓ / → ${res.status}`);
  const html = await res.text();
  if (html.includes("alice@example.com")) {
    console.log("✓ home page renders userinfo (alice@example.com visible)");
  } else {
    console.error("✗ home page does NOT render userinfo");
    console.error("  cookies in jar:", jar.names());
    process.exit(1);
  }

  console.log("\n✅ Browser-flow regression: all cookies delivered correctly.");
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});