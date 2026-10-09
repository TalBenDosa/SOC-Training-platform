import type { SupabaseClient } from "@supabase/supabase-js";
import { buildServerReport, type ServerReport } from "./report/serverReport";
import { REPORT_VERSION } from "./report/computeReport";
import { teamXpFor, TEAM_XP_VERSION } from "./teamXp";

/** Thrown when another request is building the report and it didn't land in time — the caller asks the client to retry. */
export class ReportBuildingError extends Error {
  constructor() { super("report_building"); this.name = "ReportBuildingError"; }
}

/**
 * A short per-(session, kind) lease (0088 team_try_lease) so a whole class opening the
 * after-action report at once triggers ONE build, not one per browser (QA M5). Before the
 * migration is deployed the function is missing → behave as before (everyone may build).
 */
export async function tryLease(admin: SupabaseClient, sessionId: string, kind: "report" | "xp", ttlS = 60): Promise<boolean> {
  try {
    const { data, error } = await admin.rpc("team_try_lease", { p_session: sessionId, p_kind: kind, p_ttl_s: ttlS });
    if (error) return true;
    return data === true;
  } catch { return true; }
}
export async function releaseLease(admin: SupabaseClient, sessionId: string, kind: "report" | "xp"): Promise<void> {
  try { await admin.rpc("team_release_lease", { p_session: sessionId, p_kind: kind }); } catch { /* it expires on its own */ }
}

async function cachedReport(admin: SupabaseClient, sessionId: string): Promise<ServerReport | null> {
  const { data: cached } = await admin.from("team_session_reports").select("report").eq("session_id", sessionId).maybeSingle();
  return cached?.report && (cached.report as { team?: { version?: number } }).team?.version === REPORT_VERSION ? cached.report as ServerReport : null;
}

const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

/**
 * The cached after-action report when it is current, else a fresh build (cached back).
 * Single-flight: only the lease holder builds; everyone else waits for the cached row
 * (polling up to `waitMs`) and gets ReportBuildingError if it still isn't there.
 */
export async function loadOrBuildReport(admin: SupabaseClient, sessionId: string, opts: { waitMs?: number; pollMs?: number } = {}): Promise<{ report: ServerReport; fresh: boolean }> {
  const hit = await cachedReport(admin, sessionId);
  if (hit) return { report: hit, fresh: false };

  if (!(await tryLease(admin, sessionId, "report", 90))) {
    const waitMs = opts.waitMs ?? 20_000, pollMs = opts.pollMs ?? 1_000;
    for (let waited = 0; waited < waitMs; waited += pollMs) {
      await sleep(pollMs);
      const r = await cachedReport(admin, sessionId);
      if (r) return { report: r, fresh: false };
    }
    throw new ReportBuildingError();
  }
  try {
    const again = await cachedReport(admin, sessionId);   // built while we were taking the lease
    if (again) return { report: again, fresh: false };
    const report = await buildServerReport(admin, sessionId);
    const { error } = await admin.from("team_session_reports").upsert({ session_id: sessionId, report, computed_at: new Date().toISOString() });
    if (error) console.error("[team report] cache write failed:", error.message);
    return { report, fresh: true };
  } finally {
    await releaseLease(admin, sessionId, "report");
  }
}

/** user_id → XP for every player of a report (deterministic — the same numbers the award writes). */
/** The SOC Manager's performance is the Command Review score (same formula, PLAN §10.8). */
function xpOf(report: ServerReport, u: ServerReport["perUser"][number]): number {
  const mr = report.managerReview;
  if (mr && mr.managerId === u.user_id && mr.score != null) return teamXpFor({ ...u, rubricPct: mr.score, insufficientEvidence: false });
  return teamXpFor(u);
}

export function xpFromReport(report: ServerReport): Record<string, number> {
  return Object.fromEntries(report.perUser.map(u => [u.user_id, xpOf(report, u)]));
}

/**
 * Award every player of an ENDED session their team-training XP (0087). Safe to
 * call again: the value is deterministic and the row is replaced, never added.
 * Returns user_id → XP.
 */
export async function awardTeamXp(admin: SupabaseClient, sessionId: string, report?: ServerReport): Promise<Record<string, number>> {
  const r = report ?? (await loadOrBuildReport(admin, sessionId)).report;
  const rows = r.perUser.map(u => ({ user_id: u.user_id, xp: xpOf(r, u) }));
  const { error } = await admin.rpc("award_team_session_xp", { p_session: sessionId, p_rows: rows, p_version: TEAM_XP_VERSION });
  if (error) throw new Error(`award_team_session_xp: ${error.message}`);
  return Object.fromEntries(rows.map(x => [x.user_id, x.xp]));
}

/**
 * The request-path form (end / report routes, run from `after()`): one award per
 * session at a time — a herd of report viewers doesn't each re-run the award RPC.
 * Returns null when another request holds the award lease (it is doing the work).
 */
export async function awardTeamXpOnce(admin: SupabaseClient, sessionId: string, report?: ServerReport): Promise<Record<string, number> | null> {
  if (!(await tryLease(admin, sessionId, "xp", 120))) return null;
  try { return await awardTeamXp(admin, sessionId, report); }
  finally { await releaseLease(admin, sessionId, "xp"); }
}

/** XP already awarded for a session (user_id → xp), or null when none / unreadable. */
export async function awardedTeamXp(admin: SupabaseClient, sessionId: string): Promise<Record<string, number> | null> {
  const { data, error } = await admin.from("team_session_xp").select("user_id, xp, formula_version").eq("session_id", sessionId);
  if (error || !data || data.length === 0) return null;
  if (data.some(d => d.formula_version !== TEAM_XP_VERSION)) return null;   // formula changed → re-award
  return Object.fromEntries(data.map(d => [d.user_id as string, d.xp as number]));
}

/**
 * Ended sessions (newest first) that have never been awarded — for the daily sweep /
 * backfill. 0088 stamps team_sessions.xp_awarded_at on every award, even one that
 * scored nobody, so a zero-player session leaves the list for good and there is no
 * 200-newest window to starve older ones (QA L5). Before 0088 is deployed the column
 * is missing → the old "no XP rows among the newest 200" rule.
 */
export async function sessionsMissingXp(admin: SupabaseClient, limit = 20): Promise<string[]> {
  const { data, error } = await admin.from("team_sessions").select("id").in("status", ["ended", "debriefed"])
    .is("xp_awarded_at", null).order("ended_at", { ascending: false }).limit(limit);
  if (!error) return (data ?? []).map(s => s.id as string);

  const { data: ended, error: e2 } = await admin.from("team_sessions").select("id").in("status", ["ended", "debriefed"])
    .order("ended_at", { ascending: false }).limit(200);
  if (e2 || !ended?.length) return [];
  const ids = ended.map(s => s.id as string);
  const { data: have } = await admin.from("team_session_xp").select("session_id").in("session_id", ids);
  const done = new Set((have ?? []).map(h => h.session_id as string));
  return ids.filter(id => !done.has(id)).slice(0, limit);
}
