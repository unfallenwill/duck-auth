/**
 * Shared client authentication for /oauth/token and /oauth/revoke.
 *
 * Per RFC 6749 §2.3.1 + RFC 7009 §2.1, supports BOTH:
 *   - Authorization: Basic base64(client_id:client_secret)
 *   - application/x-www-form-urlencoded body (client_id, client_secret)
 */
import { prisma } from "@/lib/generated/prisma-client";
import { verifyClientSecret } from "@/lib/oauth/crypto";

export interface AuthenticatedClient {
  clientId: string;
}

export async function authenticateClient(
  req: Request,
  form: URLSearchParams,
): Promise<AuthenticatedClient | null> {
  const authHeader = req.headers.get("authorization") ?? "";
  let clientId: string | null = null;
  let clientSecret: string | null = null;

  if (authHeader.toLowerCase().startsWith("basic ")) {
    try {
      const decoded = atob(authHeader.slice(6).trim());
      const idx = decoded.indexOf(":");
      if (idx > 0) {
        clientId = decoded.slice(0, idx);
        clientSecret = decoded.slice(idx + 1);
      }
    } catch {
      return null;
    }
  }

  if (!clientId) clientId = form.get("client_id");
  if (!clientSecret) clientSecret = form.get("client_secret");

  if (!clientId || !clientSecret) return null;

  const client = await prisma.client.findUnique({ where: { id: clientId } });
  if (!client) return null;
  if (!verifyClientSecret(clientSecret, client.secretHash)) return null;

  return { clientId };
}

/**
 * Read form-urlencoded OR JSON body into URLSearchParams. Used by token and
 * revoke endpoints.
 */
export async function readFormBody(req: Request): Promise<URLSearchParams> {
  const ct = req.headers.get("content-type") ?? "";
  if (ct.includes("application/json")) {
    const obj = (await req.json()) as Record<string, string>;
    return new URLSearchParams(Object.entries(obj));
  }
  return new URLSearchParams(await req.text());
}

/** Build a token response with the no-cache headers required by RFC 6749 §5.1. */
export function tokenResponse(body: Record<string, unknown>): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Pragma": "no-cache",
    },
  });
}