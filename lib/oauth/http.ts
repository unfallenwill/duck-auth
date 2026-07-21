/**
 * HTTP utilities shared across OAuth route handlers.
 */

/**
 * Read form-urlencoded OR JSON body into URLSearchParams. Used by token,
 * revoke, and consent endpoints.
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