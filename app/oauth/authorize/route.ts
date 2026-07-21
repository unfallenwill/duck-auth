import { cookies } from "next/headers";
import { prisma } from "@/lib/generated/prisma-client";
import { consentCoversScopes } from "@/lib/oauth/consent";
import {
  authorizeError,
  type OAuthErrorCode,
} from "@/lib/oauth/errors";
import {
  filterScopes,
  parseScopes,
} from "@/lib/oauth/discovery";
import {
  randomToken,
} from "@/lib/oauth/crypto";
import { verifySessionCookie } from "@/lib/oauth/session";

const CODE_TTL_SECONDS = 60 * 10; // 10 minutes

/**
 * GET /oauth/authorize
 * Implements RFC 6749 §4.1.1 + RFC 7636 (PKCE S256).
 */
export async function GET(req: Request) {
  const url = new URL(req.url);
  const params = url.searchParams;

  const responseType = params.get("response_type");
  const clientId = params.get("client_id");
  const redirectUri = params.get("redirect_uri");
  const state = params.get("state") ?? undefined;
  const codeChallenge = params.get("code_challenge") ?? undefined;
  const codeChallengeMethod = params.get("code_challenge_method") ?? undefined;
  const scopeParam = params.get("scope") ?? "openid";
  const requestedScopes = parseScopes(scopeParam);

  // --- Step 1: pre-client-lookup validation ---
  // For these we return JSON 400 because we don't yet know the client and
  // can't safely redirect to a (possibly attacker-controlled) redirect_uri.
  // (RFC 6749 §4.1.2.1: MUST NOT redirect when client/redirect_uri is bad.)
  if (!clientId) return badRequest("client_id is required");
  if (!redirectUri) return badRequest("redirect_uri is required");
  if (!state) return badRequest("state is required (CSRF protection)");
  // PKCE is REQUIRED for all clients (OAuth 2.1 §4.1.1).
  if (!codeChallenge) {
    return badRequest("code_challenge is required (PKCE)");
  }
  if (codeChallengeMethod !== "S256") {
    return badRequest("code_challenge_method must be 'S256'");
  }

  // --- Step 2: look up client ---
  const client = await prisma.client.findUnique({ where: { id: clientId } });
  if (!client) {
    return badRequest("unknown client_id");
  }

  // --- Step 3: validate redirect_uri against the registered list ---
  // We never redirect to an unregistered URI (open-redirect safety), even
  // though the client is known.
  const allowedRedirects: string[] = JSON.parse(client.redirectUris);
  if (!allowedRedirects.includes(redirectUri)) {
    return badRequest("redirect_uri not registered for this client");
  }

  // --- Step 4: errors that should redirect back to the client ---
  // From here on, the client is known + redirect_uri is registered, so per
  // RFC 6749 §4.1.2.1 we redirect with error=...&state=... rather than
  // rendering JSON.
  if (responseType !== "code") {
    return redirect(
      authorizeError(
        redirectUri,
        state,
        "unsupported_response_type" satisfies OAuthErrorCode,
      ),
    );
  }

  // --- Step 5: validate scopes against client's allowed list ---
  const { valid, invalid } = filterScopes(
    requestedScopes,
    client.allowedScopes,
  );
  if (invalid.length > 0) {
    return redirect(
      authorizeError(
        redirectUri,
        state,
        "invalid_scope" satisfies OAuthErrorCode,
        `Unknown or disallowed scopes: ${invalid.join(", ")}`,
      ),
    );
  }
  const finalScopes = valid.join(" ");

  // --- Authentication: session cookie required ---
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("oauth_session")?.value;
  const session = sessionCookie
    ? await verifySessionCookie(sessionCookie)
    : null;

  if (!session) {
    // Not logged in → redirect to /login with current request as next.
    const nextUrl = new URL("/login", req.url);
    nextUrl.searchParams.set("next", url.pathname + url.search);
    return Response.redirect(nextUrl, 302);
  }

  // --- Consent: skip if user already consented to (client, scopes) ---
  const existingConsent = await prisma.consent.findUnique({
    where: { userId_clientId: { userId: session.uid, clientId } },
  });

  // Consent only valid if it covers all scopes requested now.
  const hasAllScopes = consentCoversScopes(existingConsent?.scopes, finalScopes);

  if (!hasAllScopes) {
    const consentUrl = new URL("/consent", req.url);
    consentUrl.searchParams.set("client_id", clientId);
    consentUrl.searchParams.set("redirect_uri", redirectUri);
    consentUrl.searchParams.set("scope", finalScopes);
    consentUrl.searchParams.set("state", state);
    if (codeChallenge) {
      consentUrl.searchParams.set("code_challenge", codeChallenge);
      consentUrl.searchParams.set("code_challenge_method", codeChallengeMethod ?? "S256");
    }
    return Response.redirect(consentUrl, 302);
  }

  // --- Issue authorization code ---
  const code = randomToken(32);
  await prisma.authorizationCode.create({
    data: {
      code,
      clientId,
      userId: session.uid,
      redirectUri,
      scopes: finalScopes,
      ...(codeChallenge
        ? {
            codeChallenge,
            codeChallengeMethod: codeChallengeMethod ?? "S256",
          }
        : {}),
      expiresAt: new Date(Date.now() + CODE_TTL_SECONDS * 1000),
    },
  });

  // --- Redirect back to client with code + state ---
  const callbackUrl = new URL(redirectUri);
  callbackUrl.searchParams.set("code", code);
  if (state) callbackUrl.searchParams.set("state", state);
  return Response.redirect(callbackUrl, 302);
}

function badRequest(description: string): Response {
  return Response.json(
    { error: "invalid_request", error_description: description },
    { status: 400 },
  );
}

function redirect(url: URL): Response {
  return Response.redirect(url, 302);
}