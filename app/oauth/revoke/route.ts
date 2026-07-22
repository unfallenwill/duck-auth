import { authenticateClient } from "@/lib/oauth/client-auth";
import { readFormBody } from "@/lib/oauth/http";
import { revokeRateLimit } from "@/lib/oauth/rate-limit";
import { revokeToken } from "@/lib/oauth/token-service";

/**
 * POST /oauth/revoke (RFC 7009).
 *
 * Client authentication is REQUIRED per RFC 7009 §2.1. If auth fails, we
 * silently return 200 (per RFC 7009 §2.2 we never leak whether a token
 * existed).
 *
 * Either token type can be revoked. The revocation logic is shared with
 * the in-process oauth-client wrapper (see lib/oauth-client.ts) — same
 * CAS guards, same cross-client boundary.
 *
 * Per RFC 7009 §2.2 we always return 200, even for unknown tokens, to
 * avoid leaking information.
 */
export async function POST(req: Request) {
  if (!revokeRateLimit(req)) {
    return new Response(
      JSON.stringify({ error: "rate_limited", error_description: "Too many requests" }),
      { status: 429, headers: { "Retry-After": "60" } },
    );
  }
  const form = await readFormBody(req);

  // Client authentication is required. If it fails, we return 200 without
  // revoking anything — silently rejecting prevents enumeration attacks.
  const auth = await authenticateClient(req, form);
  if (!auth) {
    return new Response(null, { status: 200 });
  }

  const token = form.get("token");
  if (typeof token !== "string" || !token) {
    return Response.json(
      { error: "invalid_request", error_description: "token is required" },
      { status: 400 },
    );
  }

  const hintRaw = form.get("token_type_hint");
  const hint =
    hintRaw === "access_token" || hintRaw === "refresh_token"
      ? hintRaw
      : undefined;

  await revokeToken(token, hint, auth.clientId);

  return new Response(null, { status: 200 });
}
