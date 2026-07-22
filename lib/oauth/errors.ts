/**
 * RFC 6749 §4.1.2.1 + §5.2 error codes.
 * Plus RFC 6749 §4.2.2.1 implicit (not used here).
 */
export type OAuthErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "unsupported_response_type"
  | "invalid_scope"
  | "access_denied"
  | "server_error"
  | "temporarily_unavailable";

const ERROR_DESCRIPTIONS: Record<OAuthErrorCode, string> = {
  invalid_request: "The request is missing a required parameter or is malformed",
  invalid_client: "Client authentication failed",
  invalid_grant: "The provided grant is invalid, expired, or revoked",
  unauthorized_client: "The client is not authorized to use this grant type",
  unsupported_grant_type: "The grant type is not supported by the server",
  unsupported_response_type: "The authorization server does not support the response_type",
  invalid_scope: "The requested scope is invalid or exceeds granted scope",
  access_denied: "The resource owner denied the request",
  server_error: "The server encountered an unexpected error",
  temporarily_unavailable: "The server is temporarily unavailable",
};

/** Build a redirect-URI error response for authorize errors (RFC 6749 §4.1.2.1). */
export function authorizeError(
  redirectUri: string,
  state: string | undefined,
  code: OAuthErrorCode,
  description?: string,
): URL {
  const url = new URL(redirectUri);
  url.searchParams.set("error", code);
  url.searchParams.set(
    "error_description",
    description ?? ERROR_DESCRIPTIONS[code],
  );
  if (state) url.searchParams.set("state", state);
  return url;
}

/**
 * Derive the default HTTP status for an OAuth error code, per RFC 6749 §5.2:
 * - `server_error`, `temporarily_unavailable` → 5xx
 * - everything else → 400
 *
 * `temporarily_unavailable` SHOULD be 503 per RFC, so we give it 503 to
 * allow callers to set `Retry-After`. `server_error` stays 500.
 */
function defaultStatusForCode(code: OAuthErrorCode): number {
  if (code === "temporarily_unavailable") return 503;
  if (code === "server_error") return 500;
  return 400;
}

/** JSON error for token endpoint (RFC 6749 §5.2). */
export function tokenError(
  code: OAuthErrorCode,
  description?: string,
  status?: number,
): Response {
  const finalStatus = status ?? defaultStatusForCode(code);
  const responseInit: ResponseInit = { status: finalStatus };
  // RFC 6749 §5.2 SHOULD: temporarily_unavailable responses include
  // Retry-After. We default to a short retry hint; callers can override.
  if (code === "temporarily_unavailable") {
    responseInit.headers = { "Retry-After": "1" };
  }
  return Response.json(
    {
      error: code,
      error_description: description ?? ERROR_DESCRIPTIONS[code],
    },
    responseInit,
  );
}

/**
 * Throwable OAuth error. Use inside interactive transactions so a CAS failure
 * or other expected error condition aborts the transaction and rolls back
 * any writes. Catch at the request boundary and convert to `tokenError(...)`.
 *
 * The `status` defaults to 500 for server-class errors (server_error,
 * temporarily_unavailable) and 400 for client-class errors, matching RFC
 * 6749 §5.2.
 */
export class OAuthError extends Error {
  public readonly code: OAuthErrorCode;
  public readonly status: number;
  constructor(code: OAuthErrorCode, description?: string, status?: number) {
    super(description ?? ERROR_DESCRIPTIONS[code]);
    this.name = "OAuthError";
    this.code = code;
    this.status = status ?? defaultStatusForCode(code);
  }
}