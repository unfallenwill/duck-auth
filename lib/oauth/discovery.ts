import { config } from "@/lib/config";

export const SUPPORTED_SCOPES = ["openid", "profile", "email"] as const;
export type SupportedScope = (typeof SUPPORTED_SCOPES)[number];

export const ISSUER = config.issuer;

export function discoveryDocument() {
  return {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/oauth/authorize`,
    token_endpoint: `${ISSUER}/oauth/token`,
    userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
    jwks_uri: `${ISSUER}/oauth/jwks`,
    revocation_endpoint: `${ISSUER}/oauth/revoke`,
    registration_endpoint: `${ISSUER}/oauth/register`,
    end_session_endpoint: `${ISSUER}/api/auth/logout`,
    response_types_supported: ["code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    scopes_supported: [...SUPPORTED_SCOPES],
    token_endpoint_auth_methods_supported: [
      "client_secret_basic",
      "client_secret_post",
    ],
    claims_supported: ["sub", "email", "name", "iss", "aud", "exp", "iat"],
  };
}

/** Filter a user's scopes against a client's allowed scopes. */
export function filterScopes(
  requested: string[],
  allowed: string,
): { valid: string[]; invalid: string[] } {
  const allowedSet = new Set(allowed.split(/\s+/).filter(Boolean));
  const supported = new Set<string>(SUPPORTED_SCOPES);
  const valid: string[] = [];
  const invalid: string[] = [];
  for (const s of requested) {
    if (!supported.has(s)) {
      invalid.push(s);
      continue;
    }
    if (!allowedSet.has(s)) {
      invalid.push(s);
      continue;
    }
    valid.push(s);
  }
  return { valid, invalid };
}

/** Split a space-separated scopes string into an array, deduped. */
export function parseScopes(scopes: string): string[] {
  return Array.from(new Set(scopes.split(/\s+/).filter(Boolean)));
}