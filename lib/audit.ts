/**
 * Structured audit logging for admin/security-sensitive actions.
 *
 * Writes a single JSON line to stdout per event. Format is stable enough
 * to be ingested by a log shipper later (CloudWatch, Loki, Datadog, etc.)
 * without code changes — just swap the transport. No external dependency.
 *
 * Usage:
 *   audit({
 *     actor: "env-token",  // "env-token" for Option A; future: admin user id
 *     action: "admin.sessions.revoke_all",
 *     target: userId,
 *     metadata: { revoked: 3 },
 *   });
 *
 * Do NOT use this for high-volume or non-sensitive events (use console.log
 * directly). Audit logs are for security review and incident response —
 * they should be rare and structured.
 */

export interface AuditEvent {
  /** Who performed the action. For Option A: "env-token". */
  actor: string;
  /** Dotted action name, e.g. "admin.sessions.revoke_all". */
  action: string;
  /** Primary target identifier (e.g., userId, clientId). */
  target: string;
  /** Optional structured context (counts, ids, etc.). Never include secrets. */
  metadata?: Record<string, unknown>;
}

export interface AuditRecord extends AuditEvent {
  /** ISO 8601 timestamp. */
  ts: string;
}

export function audit(event: AuditEvent): void {
  const record: AuditRecord = {
    ts: new Date().toISOString(),
    actor: event.actor,
    action: event.action,
    target: event.target,
    ...(event.metadata !== undefined ? { metadata: event.metadata } : {}),
  };
  // JSON.stringify cannot throw on the shape above (no circular refs, all
  // primitives + plain objects). If a future caller passes weird types, a
  // throw here would crash the calling route handler — that's intentional,
  // it surfaces accidental misuse.
  console.log(JSON.stringify({ audit: record }));
}
