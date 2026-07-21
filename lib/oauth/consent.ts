/**
 * Pure consent-writing logic. Extracted from the server action so it can
 * be unit-tested independently of Next.js context (cookies, redirects).
 *
 * The server action (app/consent/actions.ts) calls this before redirecting
 * the user back to /oauth/authorize.
 */
import { prisma } from "@/lib/generated/prisma-client";

export async function recordConsent(
  userId: string,
  clientId: string,
  scopes: string,
): Promise<void> {
  await prisma.consent.upsert({
    where: {
      userId_clientId: { userId, clientId },
    },
    update: { scopes },
    create: {
      userId,
      clientId,
      scopes,
    },
  });
}

/**
 * Check if an existing consent row covers the requested scopes.
 *
 * Direction: every REQUESTED scope must already be in the existing
 * consent. A consent for {openid} does NOT satisfy a request for
 * {openid profile email} — the user must explicitly approve the
 * additional scopes.
 */
export function consentCoversScopes(
  existingScopes: string | null | undefined,
  requestedScopes: string,
): boolean {
  if (!existingScopes) return false;
  const consented = new Set(existingScopes.split(/\s+/).filter(Boolean));
  const requested = requestedScopes.split(/\s+/).filter(Boolean);
  return requested.every((s) => consented.has(s));
}