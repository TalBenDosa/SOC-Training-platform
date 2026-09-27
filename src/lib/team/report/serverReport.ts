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
const FEED_ANSWER_KEYS = ["expected_verdict", "fp_explanation", "incident_id", "supports_inject"] as const;
const INJECT_ANSWER_KEYS = ["kind", "expected_response", "linked_objective", "original_id", "expected_decision"] as const;

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
    out[r.id] = pick(a, r.channel === "inject" ? INJECT_ANSWER_KEYS : FEED_ANSWER_KEYS);
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
    if (e.type === "staff.inject") return { ...e, payload: { ...e.payload, ...pick(a, INJECT_ANSWER_KEYS) } };
    return e;
  });
}

/** Click telemetry (v2, off the log) → synthetic `event.opened` events for computeReport. */
export function clicksAsEvents(clicks: { user_id: string; event_id: string | null; dwell_ms: number; occurred_at: string }[], afterSeq: number): Ev[] {
  return clicks.map((c, i) => ({
    seq: afterSeq + 1 + i, type: "event.opened", actor_id: c.user_id, role: null,
    payload: { event_id: c.event_id ?? "", dwell_ms: c.dwell_ms }, occurred_at: c.occurred_at,
  }));
}

async function pageAll<T>(fetchPage: (from: number, to: number) => PromiseLike<{ data: T[] | null; error: { message: string } | null }>, pageSize = 1000, maxRows = 60000): Promise<T[]> {
  const out: T[] = [];
  for (let from = 0; from < maxRows; from += pageSize) {
    const { data, error } = await fetchPage(from, from + pageSize - 1);
    if (error) throw new Error(error.message);
    out.push(...(data ?? []));
    if (!data || data.length < pageSize) break;
  }
  return out;
}

/** Build the full report for an ended session (service-role client). */
export async function buildServerReport(admin: SupabaseClient, sessionId: string): Promise<ServerReport> {
  const events = await pageAll<Ev>((from, to) => admin.from("session_events")
    .select("seq, type, actor_id, role, payload, occurred_at").eq("session_id", sessionId).order("seq").range(from, to));
  const injects = await pageAll<{ id: string; channel: string | null; expected_action: unknown }>((from, to) => admin.from("session_injects")
    .select("id, channel, expected_action").eq("session_id", sessionId).order("id").range(from, to));
  const clicks = await pageAll<{ user_id: string; event_id: string | null; dwell_ms: number; occurred_at: string }>((from, to) => admin.from("session_clicks")
    .select("user_id, event_id, dwell_ms, occurred_at").eq("session_id", sessionId).order("id").range(from, to));

  // Roster incl. members who LEFT — their actions still count in the debrief.
  const { data: mem } = await admin.from("team_session_members").select("user_id, role, status").eq("session_id", sessionId);
  const ids = (mem ?? []).map(m => m.user_id);
  const { data: profs } = await admin.from("profiles").select("id, handle, display_name")
    .in("id", ids.length ? ids : ["00000000-0000-0000-0000-000000000000"]);
  const pmap = new Map((profs ?? []).map(p => [p.id as string, p as { handle?: string; display_name?: string }]));
  const roster: RosterMember[] = (mem ?? []).map(m => {
    const p = pmap.get(m.user_id);
    return { user_id: m.user_id, role: m.role, status: m.status, name: p?.display_name || p?.handle || m.user_id.slice(0, 8), handle: p?.handle ?? null };
  });

  const answers = publicAnswers(injects);
  const maxSeq = events.reduce((m, e) => Math.max(m, e.seq), 0);
  const revealed = [...mergeAnswers(events, answers), ...clicksAsEvents(clicks, maxSeq)];
  return { ...computeReport(revealed, roster), answers };
}
