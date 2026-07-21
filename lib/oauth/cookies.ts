/**
 * Shared cookie helpers. Centralizes the Secure flag decision so HTTP
 * testing works without breaking production security.
 *
 * The rule: Secure flag = (issuer scheme is https). This is correct
 * because:
 *   - HTTPS issuers MUST have Secure cookies (cross-origin redirect safety)
 *   - HTTP issuers CANNOT use Secure cookies (browsers reject them)
 *
 * Tying Secure to NODE_ENV=production breaks HTTP testing (browsers
 * drop Secure cookies over plain HTTP). Tying it to issuer scheme works
 * for both.
 */
import { ISSUER } from "@/lib/oauth/discovery";

export function secureCookie(): boolean {
  return ISSUER.startsWith("https://");
}

/** Cookie flags shared by every oauth_* cookie. Caller adds maxAge. */
export function cookieDefaults() {
  return {
    httpOnly: true,
    sameSite: "lax" as const,
    secure: secureCookie(),
    path: "/",
  };
}