import { z } from "zod";
import { prisma } from "@/lib/generated/prisma-client";
import {
  hashClientSecret,
  randomToken,
} from "@/lib/oauth/crypto";
import { tokenError } from "@/lib/oauth/errors";
import { SUPPORTED_SCOPES } from "@/lib/oauth/discovery";
import { registerRateLimit } from "@/lib/oauth/rate-limit";

const RegisterSchema = z.object({
  client_name: z.string().min(1).max(100),
  redirect_uris: z.array(z.string().url()).min(1),
  allowed_scopes: z
    .array(z.enum(SUPPORTED_SCOPES))
    .min(1)
    .default(["openid", "profile", "email"]),
});

/**
 * POST /oauth/register (RFC 7591 — Dynamic Client Registration).
 *
 * If `DCR_INITIAL_TOKEN` env var is set, the request must include a
 * matching `Authorization: Bearer <token>` header. This implements
 * RFC 7591 §3 "Initial Access Token" protection.
 *
 * If `DCR_INITIAL_TOKEN` is not set (dev/demo mode), registration is open.
 * The discovery document advertises this via `dcr_protected` = false.
 */
export async function POST(req: Request) {
  // Rate limit: 5 registrations per minute per IP.
  if (!registerRateLimit(req)) {
    return new Response(
      JSON.stringify({ error: "rate_limited", error_description: "Too many registration requests" }),
      { status: 429, headers: { "Retry-After": "60" } },
    );
  }

  // --- Initial Access Token check (if configured) ---
  const dcrToken = process.env["DCR_INITIAL_TOKEN"];
  if (dcrToken) {
    const auth = req.headers.get("authorization") ?? "";
    const match = auth.match(/^Bearer\s+(.+)$/i);
    const presented = match?.[1];
    if (!presented || presented !== dcrToken) {
      return new Response(
        JSON.stringify({
          error: "invalid_token",
          error_description: "Initial Access Token required for registration",
        }),
        {
          status: 401,
          headers: {
            "Content-Type": "application/json",
            "WWW-Authenticate": 'Bearer realm="oauth/register"',
          },
        },
      );
    }
  }

  let body: unknown;
  try {
    body = await req.json();
  } catch {
    return tokenError("invalid_request", "Body must be JSON", 400);
  }

  const parsed = RegisterSchema.safeParse(body);
  if (!parsed.success) {
    return tokenError(
      "invalid_request",
      `Validation failed: ${parsed.error.issues.map((i) => i.message).join(", ")}`,
      400,
    );
  }

  const clientId = `cli_${randomToken(16)}`;
  const clientSecret = `sec_${randomToken(24)}`;
  const secretHash = hashClientSecret(clientSecret);

  try {
    await prisma.client.create({
      data: {
        id: clientId,
        name: parsed.data.client_name,
        secretHash,
        redirectUris: JSON.stringify(parsed.data.redirect_uris),
        allowedScopes: parsed.data.allowed_scopes.join(" "),
      },
    });
  } catch (err) {
    return tokenError(
      "server_error",
      `Failed to register client: ${err instanceof Error ? err.message : String(err)}`,
      500,
    );
  }

  // client_secret is returned ONCE in the registration response (RFC 7591 §3.2.1).
  return Response.json(
    {
      client_id: clientId,
      client_secret: clientSecret,
      client_secret_expires_at: 0, // 0 = never expires (RFC 7591 §3.2.1)
      client_name: parsed.data.client_name,
      redirect_uris: parsed.data.redirect_uris,
      allowed_scopes: parsed.data.allowed_scopes,
    },
    { status: 201 },
  );
}