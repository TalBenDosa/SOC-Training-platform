import type { SupabaseClient } from "@supabase/supabase-js";
import { buildServerReport, type ServerReport } from "./report/serverReport";
import { REPORT_VERSION } from "./report/computeReport";
import { teamXpFor, TEAM_XP_VERSION } from "./teamXp";

/** The cached after-action report when it is current, else a fresh build (cached back). */
export async function loadOrBuildReport(admin: SupabaseClient, sessionId: string): Promise<{ report: ServerReport; fresh: boolean }> {
  const { data: cached } = await admin.from("team_session_reports").select("report").eq("session_id", sessionId).maybeSingle();
  if (cached?.report && (cached.report as { team?: { version?: number } }).team?.version === REPORT_VERSION) {
    return { report: cached.report as ServerReport, fresh: false };
  }
  const report = await buildServerReport(admin, sessionId);
  const { error } = await admin.from("team_session_reports").upsert({ session_id: sessionId, report, computed_at: new Date().toISOString() });
  if (error) console.error("[team report] cache write failed:", error.message);
  return { report, fresh: true };
}

/**
 * Award every player of an ENDED session their team-training XP (0087). Safe to
 * call again: the value is deterministic and the row is replaced, never added.
 * Returns user_id → XP.
 */
export async function awardTeamXp(admin: SupabaseClient, sessionId: string, report?: ServerReport): Promise<Record<string, number>> {
  const r = report ?? (await loadOrBuildReport(admin, sessionId)).report;
  const rows = r.perUser.map(u => ({ user_id: u.user_id, xp: teamXpFor(u) }));
  const { error } = await admin.rpc("award_team_session_xp", { p_session: sessionId, p_rows: rows, p_version: TEAM_XP_VERSION });
  if (error) throw new Error(`award_team_session_xp: ${error.message}`);
  return Object.fromEntries(rows.map(x => [x.user_id, x.xp]));
}

/** XP already awarded for a session (user_id → xp), or null when none / unreadable. */
export async function awardedTeamXp(admin: SupabaseClient, sessionId: string): Promise<Record<string, number> | null> {
  const { data, error } = await admin.from("team_session_xp").select("user_id, xp, formula_version").eq("session_id", sessionId);
  if (error || !data || data.length === 0) return null;
  if (data.some(d => d.formula_version !== TEAM_XP_VERSION)) return null;   // formula changed → re-award
  return Object.fromEntries(data.map(d => [d.user_id as string, d.xp as number]));
}

/** Ended sessions (newest first) that have no XP rows yet — for the daily sweep / backfill. */
export async function sessionsMissingXp(admin: SupabaseClient, limit = 20): Promise<string[]> {
  const { data: ended, error } = await admin.from("team_sessions").select("id").in("status", ["ended", "debriefed"])
    .order("ended_at", { ascending: false }).limit(200);
  if (error || !ended?.length) return [];
  const ids = ended.map(s => s.id as string);
  const { data: have } = await admin.from("team_session_xp").select("session_id").in("session_id", ids);
  const done = new Set((have ?? []).map(h => h.session_id as string));
  return ids.filter(id => !done.has(id)).slice(0, limit);
}
