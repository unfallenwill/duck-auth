/**
 * Quick security-extra regression checks:
 *   - PKCE required: /oauth/authorize without code_challenge → 400
 *   - Rate limit: 25 rapid /oauth/token requests with bad client_secret →
 *     eventually returns 429.
 *   - Discovery doc advertises end_session_endpoint.
 */
const BASE = "http://localhost:3000";

let pass = 0;
let fail = 0;
function ok(label: string, cond: boolean, detail = "") {
  if (cond) {
    console.log(`  ✓ ${label}`);
    pass++;
  } else {
    console.error(`  ✗ ${label}${detail ? "  — " + detail : ""}`);
    fail++;
  }
}

async function main() {
  console.log("=== Security-Extra Regression ===\n");

  // --- PKCE required ---
  const pkceRes = await fetch(
    `${BASE}/oauth/authorize?response_type=code&client_id=demo-client&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Fcallback&state=x`,
  );
  const body = await pkceRes.text();
  ok(
    "PKCE required: authorize without code_challenge → 400",
    pkceRes.status === 400 && body.includes("code_challenge"),
    `status=${pkceRes.status} body=${body.slice(0, 80)}`,
  );

  // --- Discovery doc ---
  const disc = await (await fetch(`${BASE}/.well-known/openid-configuration`)).json();
  ok(
    "discovery advertises end_session_endpoint",
    typeof disc["end_session_endpoint"] === "string",
    `end_session_endpoint=${disc["end_session_endpoint"]}`,
  );

  // --- Rate limit ---
  // Token bucket is 20 req/min per (IP, client_id). Fire 25 and count statuses.
  let okCount = 0;
  let limitedCount = 0;
  for (let i = 0; i < 25; i++) {
    const r = await fetch(`${BASE}/oauth/token`, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Authorization:
          "***" + Buffer.from("demo-client:wrong-secret").toString("base64"),
      },
      body: "grant_type=authorization_code",
    });
    if (r.status === 429) limitedCount++;
    else okCount++;
  }
  ok(
    "rate limit: ≥1 of 25 rapid bad-auth requests gets 429",
    limitedCount > 0,
    `ok=${okCount} limited=${limitedCount}`,
  );

  console.log(
    `\n${pass === 3 ? "✅" : "❌"} ${pass}/3 security-extra checks passed.` +
      (fail > 0 ? ` (${fail} failed)` : ""),
  );
  if (fail > 0) process.exit(1);
}

main();