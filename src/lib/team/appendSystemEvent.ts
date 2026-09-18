import { getSupabaseAdminClient } from "@/lib/supabase/admin";

/**
 * Append a SYSTEM session_event (session.started / paused / resumed / ended) from
 * a route, the way apply_session_action does it in the DB (0062): recompute the
 * next seq and retry on a unique(session_id, seq) collision, instead of the
 * one-shot `max(seq)+1` insert whose error the routes used to swallow.
 *
 * Without this, a concurrent player action or the 5-second pg_cron promote tick
 * can take the same seq; the insert fails, the status flip has already committed,
 * and the matching lifecycle event is never appended or broadcast — so every
 * client is left on the wrong screen. The broadcast trigger fans the row out on
 * success, and we mirror the seq into session_state like the other writers.
 */
export async function appendSystemEvent(
  sessionId: string,
  type: string,
  payload: Record<string, unknown>,
): Promise<{ ok: true; seq: number } | { ok: false; error: string }> {
  const admin = getSupabaseAdminClient();
  if (!admin) return { ok: false, error: "Server not configured." };
  for (let attempt = 0; attempt < 6; attempt++) {
    const { data: head } = await admin.from("session_events")
      .select("seq").eq("session_id", sessionId).order("seq", { ascending: false }).limit(1).maybeSingle();
    const nextSeq = (head?.seq ?? 0) + 1;
    const { error } = await admin.from("session_events")
      .insert({ session_id: sessionId, seq: nextSeq, type, payload });
    if (!error) {
      await admin.from("session_state").upsert({ session_id: sessionId, seq: nextSeq, updated_at: new Date().toISOString() });
      return { ok: true, seq: nextSeq };
    }
    // 23505 = unique_violation on (session_id, seq): another writer grabbed it — retry.
    if ((error as { code?: string }).code !== "23505") return { ok: false, error: error.message };
    await new Promise(r => setTimeout(r, 50 + attempt * 50));
  }
  return { ok: false, error: "Could not append the event (seq contention)." };
}
