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