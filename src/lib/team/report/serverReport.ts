/**
 * Server-authoritative after-action report (audit A1/S4/S9).
 *
 * The live room never receives the answer key any more (v2 sessions): feed
 * payloads carry no expected_verdict / fp_explanation and curveballs carry a
 * neutral kind. After the session ENDS, the server joins the staff-only answers
 * (session_injects.expected_action, keyed by the payload's inject_id) back onto
 * the event log, folds in click telemetry (session_clicks — kept off the log),
 * and runs the SAME isomorphic `computeReport` the client used to run. Result:
 * one report for everyone (no per-browser divergence from missed events or a
 * stale roster), computed once and cached.
 *
 * Legacy v1 sessions still carry the key in their payloads; `mergeAnswers` leaves
 * those untouched, so their reports are unchanged.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Ev, RosterMember } from "@/lib/team/types";
import { computeReport } from "./computeReport";

export type AnswerMap = Record<string, Record<string, unknown>>;
export type ServerReport = ReturnType<typeof computeReport> & { answers: AnswerMap };

// incident_id (per-incident detection) and supports_inject (which MSEL inject a feed log
// backs) are needed to SCORE the shift; original_id / expected_decision let a curveball be
// matched to its supporting telemetry and a help-desk ticket be judged on its decision.
// All are reveal-safe once the session has ended (the report is only served then).
const FEED_ANSWER_KEYS = ["expected_verdict", "fp_explanation", "incident_id", "supports_inject", "mitre_technique", "mitre_tactic"] as const;
const INJECT_ANSWER_KEYS = ["kind", "expected_response", "linked_objective", "original_id", "expected_decision"] as const;
// A SOC-Manager decision card's grading (ranks, notes, indicator deltas, critical options) — the
// Command Review needs all of it, and it is only served after the session ended.
const CARD_ANSWER_KEYS = ["card", "ranks", "notes", "deltas", "best", "timeout_delta", "objective", "critical"] as const;
// A stakeholder question's checks and model answer (graded in the Command Review after the session).
const QUESTION_ANSWER_KEYS = ["qid", "checks", "model", "objective", "facts"] as const;

function pick(src: Record<string, unknown>, keys: readonly string[]): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const k of keys) if (src[k] !== undefined && src[k] !== null) out[k] = src[k];
  return out;
}

/** Reveal-safe answers only (what the debrief needs), keyed by inject id. */
export function publicAnswers(rows: { id: string; channel: string | null; expected_action: unknown }[]): AnswerMap {
  const out: AnswerMap = {};
  for (const r of rows) {
    const a = (r.expected_action ?? null) as Record<string, unknown> | null;
    if (!a) continue;
    out[r.id] = pick(a, r.channel === "inject" ? (typeof a.card === "string" ? CARD_ANSWER_KEYS : typeof a.qid === "string" ? QUESTION_ANSWER_KEYS : INJECT_ANSWER_KEYS) : FEED_ANSWER_KEYS);
  }
  return out;
}

/** Join answers onto the log by payload.inject_id. Events without an answer (v1, player actions) pass through. */
export function mergeAnswers(events: Ev[], answers: AnswerMap): Ev[] {
  return events.map(e => {
    const iid = (e.payload as { inject_id?: unknown } | null)?.inject_id;
    const a = typeof iid === "string" ? answers[iid] : undefined;
    if (!a) return e;
    if (e.type === "feed.event") return { ...e, payload: { ...e.payload, ...pick(a, FEED_ANSWER_KEYS) } };
    if (e.type === "staff.inject" && typeof a.card === "string") return { ...e, payload: { ...e.payload, key: pick(a, CARD_ANSWER_KEYS) } };
    if (e.type === "stakeholder.asked" && typeof a.qid === "string") return { ...e, payload: { ...e.payload, key: pick(a, QUESTION_ANSWER_KEYS) } };
    if (e.type === "staff.inject") return { ...e, payload: { ...e.payload, ...pick(a, INJECT_ANSWER_KEYS) } };
    return e;
  });
}

/** One player's reads of one log (0088 team_session_click_totals): opens, longest and total dwell. */
export interface ClickTotal { user_id: string; event_id: string | null; opens: number; max_dwell_ms: number; sum_dwell_ms: number; first_at: string }

/**
 * Click totals → the click rows computeReport reads. It counts DISTINCT logs opened and
 * the LONGEST read of each, so one row per (player, log) carrying the max dwell scores
 * exactly like the raw clicks did — and can never outgrow the report's row cap (QA M2).
 */
export function totalsAsClicks(totals: ClickTotal[]): { user_id: string; event_id: string | null; dwell_ms: number; occurred_at: string }[] {
  return totals.map(t => ({ user_id: t.user_id, event_id: t.event_id, dwell_ms: Number(t.max_dwell_ms) || 0, occurred_at: t.first_at }));
}

/** Click telemetry (v2, off the log) → synthetic `event.opened` events for computeReport. */
export function clicksAsEvents(clicks: { user_id: string; event_id: string | null; dwell_ms: number; occurred_at: string }[], afterSeq: number): Ev[] {
  return clicks.map((c, i) => ({
    seq: afterSeq + 1 + i, type: "event.opened", actor_id: c.user_id, role: null,
    payload: { event_id: c.event_id ?? "", dwell_ms: c.dwell_ms }, occurred_at: c.occurred_at,
  }));
}

// Throws — never returns a partial list: the report built from it is cached for
// good (team_session_reports), so a truncated log would be a permanent wrong score.
export async function pageAll<T>(fetchPage: (from: number, to: number) => PromiseLike<{ data: T[] | null; error: { message: string } | null }>, pageSize = 1000, maxRows = 60000): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; ; from += pageSize) {
    const { data, error } = await fetchPage(from, from + pageSize - 1);
    if (error) throw new Error(error.message);
    out.push(...(data ?? []));
    if (!data || data.length < pageSize) return out;
    if (out.length >= maxRows) throw new Error(`more than ${maxRows} rows — report not built`);
  }
}

/**
 * The session's click telemetry, aggregated per (player, log) in the DB (0088). Falls
 * back to the raw rows only while that function isn't deployed yet.
 */
async function loadClicks(admin: SupabaseClient, sessionId: string) {
  try {
    const totals = await pageAll<ClickTotal>((from, to) => admin.rpc("team_session_click_totals", { p_session: sessionId }).range(from, to), 1000, 250_000);
    return totalsAsClicks(totals);
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    if (!/team_session_click_totals|function|schema cache/i.test(msg)) throw e;
    return pageAll<{ user_id: string; event_id: string | null; dwell_ms: number; occurred_at: string }>((from, to) => admin.from("session_clicks")
      .select("user_id, event_id, dwell_ms, occurred_at").eq("session_id", sessionId).order("id").range(from, to));
  }
}

/** Build the full report for an ended session (service-role client). */
export async function buildServerReport(admin: SupabaseClient, sessionId: string): Promise<ServerReport> {
  const events = await pageAll<Ev>((from, to) => admin.from("session_events")
    .select("seq, type, actor_id, role, payload, occurred_at").eq("session_id", sessionId).order("seq").range(from, to));
  const injects = await pageAll<{ id: string; channel: string | null; expected_action: unknown }>((from, to) => admin.from("session_injects")
    .select("id, channel, expected_action").eq("session_id", sessionId).order("id").range(from, to));
  const clicks = await loadClicks(admin, sessionId);

  // Roster incl. members who LEFT — their actions still count in the debrief.
  // Errors THROW (P4-07): an empty roster makes computeReport score nobody, and
  // that report would be cached and served forever.
  const { data: mem, error: memErr } = await admin.from("team_session_members").select("user_id, role, status").eq("session_id", sessionId);
  if (memErr) throw new Error(`roster: ${memErr.message}`);
  if (!mem || mem.length === 0) throw new Error("roster is empty — report not built");
  const ids = mem.map(m => m.user_id);
  const { data: profs, error: profErr } = await admin.from("profiles").select("id, handle, display_name").in("id", ids);
  if (profErr) throw new Error(`profiles: ${profErr.message}`);
  const pmap = new Map((profs ?? []).map(p => [p.id as string, p as { handle?: string; display_name?: string }]));
  const roster: RosterMember[] = mem.map(m => {
    const p = pmap.get(m.user_id);
    return { user_id: m.user_id, role: m.role, status: m.status, name: p?.display_name || p?.handle || m.user_id.slice(0, 8), handle: p?.handle ?? null };
  });

  const answers = publicAnswers(injects);
  const maxSeq = events.reduce((m, e) => Math.max(m, e.seq), 0);
  const revealed = [...mergeAnswers(events, answers), ...clicksAsEvents(clicks, maxSeq)];
  return { ...computeReport(revealed, roster), answers };
}
