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

/** JSON error for token endpoint (RFC 6749 §5.2). */
export function tokenError(
  code: OAuthErrorCode,
  description?: string,
  status = 400,
): Response {
  return Response.json(
    {
      error: code,
      error_description: description ?? ERROR_DESCRIPTIONS[code],
    },
    { status },
  );
}