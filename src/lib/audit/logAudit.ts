import "server-only";
/**
 * Append-only audit trail for privileged / data-touching actions.
 *
 * WHY: תקנות הגנת הפרטיות (אבטחת מידע) התשע"ז-2017 treat תיעוד (logging of access
 * and security events) as a core control. `public.audit_log` existed in the
 * schema from day one but nothing wrote to it — so there was no record of who
 * did what. This is the single chokepoint that fills it.
 *
 * INTEGRITY: writes go through the SERVICE-ROLE client, and migration 0007 locks
 * `audit_log` to no client access at all (RLS on, no anon/authenticated policy).
 * A student — even a signed-in one — therefore cannot read, forge, or delete
 * audit entries; only trusted server code appends them.
 *
 * FAIL-SAFE, NEVER FAIL-LOUD: audit logging must never break the action it is
 * recording. Every failure is swallowed after being mirrored to stderr, so a
 * missing service-role key or a transient DB error degrades to a console trail
 * rather than a 500. That is the correct trade-off for a cross-cutting logger.
 */
import { getSupabaseAdminClient } from "@/lib/supabase/admin";

export interface AuditEntry {
  /** The acting user's id (profiles.id / auth uid), or null for system actions. */
  actorId: string | null;
  /** Stable machine action label, e.g. "lesson.generate", "scenario.generate". */
  action: string;
  /** The table the action touched, when applicable. */
  targetTable?: string;
  /** The row the action touched, when applicable. */
  targetId?: string | null;
  /** Small, non-sensitive context. NEVER put secrets or full PII payloads here. */
  metadata?: Record<string, unknown>;
}

export async function logAudit(entry: AuditEntry): Promise<void> {
  const admin = getSupabaseAdminClient();

  // No service-role key configured → keep a server-side trail so the action is
  // still recorded somewhere, and return without throwing.
  if (!admin) {
    console.info("[audit]", entry.action, {
      actor: entry.actorId, target: entry.targetTable, id: entry.targetId,
    });
    return;
  }

  try {
    const { error } = await admin.from("audit_log").insert({
      actor_id: entry.actorId,
      action: entry.action,
      target_table: entry.targetTable ?? null,
      target_id: entry.targetId ?? null,
      metadata: entry.metadata ?? {},
    });
    if (error) console.error("[audit] insert failed:", error.message);
  } catch (err) {
    console.error("[audit] insert threw:", err instanceof Error ? err.message : String(err));
  }
}
