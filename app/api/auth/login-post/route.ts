import { NextResponse } from "next/server";
import { prisma } from "@/lib/generated/prisma-client";
import { verifyPassword } from "@/lib/oauth/crypto";
import { signSessionCookie } from "@/lib/oauth/jwt";
import { cookieDefaults } from "@/lib/oauth/cookies";

/**
 * POST /api/auth/login-post
 *
 * Plain route handler equivalent of the previous loginAction server
 * action. Switched to this form because Server Actions + Set-Cookie +
 * redirect in Playwright/Chromium had reliability issues — the cookie
 * wasn't always carried to the next request. Route handlers emit
 * Set-Cookie via NextResponse in a way that all browsers (and test
 * harnesses) handle predictably.
 */
export async function POST(req: Request) {
  const form = await req.formData();
  const email = String(form.get("email") ?? "").trim().toLowerCase();
  const password = String(form.get("password") ?? "");
  const next = String(form.get("next") ?? "/");

  if (!email || !password) {
    return NextResponse.redirect(
      new URL(`/login?error=missing&next=${encodeURIComponent(next)}`, req.url),
      303,
    );
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user || !verifyPassword(password, user.passwordHash)) {
    return NextResponse.redirect(
      new URL(`/login?error=invalid&next=${encodeURIComponent(next)}`, req.url),
      303,
    );
  }

  const { value, expiresAt } = await signSessionCookie(user.id);

  // Issue the session cookie via the response (not via cookies() helper)
  // so Set-Cookie is guaranteed to ride the 303 redirect.
  const redirectUrl = new URL(next, req.url);
  const res = NextResponse.redirect(redirectUrl, 303);
  res.cookies.set({
    name: "oauth_session",
    value,
    ...cookieDefaults(),
    expires: expiresAt,
  });
  return res;
}