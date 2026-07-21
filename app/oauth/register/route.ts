import { z } from "zod";
import { prisma } from "@/lib/generated/prisma-client";
import {
  hashClientSecret,
  randomToken,
} from "@/lib/oauth/crypto";
import { tokenError } from "@/lib/oauth/errors";
import { SUPPORTED_SCOPES } from "@/lib/oauth/discovery";

const RegisterSchema = z.object({
  client_name: z.string().min(1).max(100),
  redirect_uris: z.array(z.string().url()).min(1),
  allowed_scopes: z
    .array(z.enum(SUPPORTED_SCOPES))
    .min(1)
    .default(["openid", "profile", "email"]),
});

export async function POST(req: Request) {
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