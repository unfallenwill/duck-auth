/**
 * GET    /api/me/sessions        — list my active sessions
 * DELETE /api/me/sessions        — revoke all my sessions ("sign out
 *                                   everywhere")
 *
 * Issue #34, Phase 3 of #30. User self-service session management.
 *
 * Auth: session cookie (existing `verifySessionCookie` pattern).
 * Authorization: the cookie's userId IS the actor — no separate admin
 * check. The caller is acting on their own data.
 */
import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { verifySessionCookie } from "@/lib/oauth/session";
import {
  listActiveSessionsForUser,
  revokeAllSessionsForUser,
} from "@/lib/oauth/admin-actions";
import { audit } from "@/lib/audit";

export async function GET() {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("oauth_session")?.value;

  if (!sessionCookie) {
    return NextResponse.json(
      { error: "unauthorized", error_description: "No session cookie." },
      { status: 401 },
    );
  }
  const session = await verifySessionCookie(sessionCookie);
  if (!session) {
    return NextResponse.json(
      { error: "unauthorized", error_description: "Invalid or expired session." },
      { status: 401 },
    );
  }

  const sessions = await listActiveSessionsForUser(session.uid);
  return NextResponse.json({
    sessions: sessions.map((s) => ({
      jti: s.jti,
      userAgent: s.userAgent,
      ipAddress: s.ipAddress,
      createdAt: s.createdAt.toISOString(),
      expiresAt: s.expiresAt.toISOString(),
    })),
  });
}

export async function DELETE() {
  const cookieStore = await cookies();
  const sessionCookie = cookieStore.get("oauth_session")?.value;

  if (!sessionCookie) {
    return NextResponse.json(
      { error: "unauthorized", error_description: "No session cookie." },
      { status: 401 },
    );
  }
  const session = await verifySessionCookie(sessionCookie);
  if (!session) {
    return NextResponse.json(
      { error: "unauthorized", error_description: "Invalid or expired session." },
      { status: 401 },
    );
  }

  const { count } = await revokeAllSessionsForUser(session.uid);

  audit({
    actor: "self",
    action: "user.sessions.revoke_all",
    target: session.uid,
    metadata: { revoked: count },
  });

  return NextResponse.json({ revoked: count });
}
