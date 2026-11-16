/**
 * Tier-3 own work (T3 interface spec, stage C), derived from the session events:
 *   - the open lead from the previous shift (a `t3_lead` inject, see shiftLead.ts)
 *   - closure review: alerts Tier-1 / Tier-2 closed as benign or false positive, for a second look
 *   - consults: Tier-2 asks Tier-3 "is this host infected?" without handing the case over
 *
 * Events (migration 0113):
 *   consult.asked     (Tier-2)  { event_id, question, host? }
 *   consult.answered  (Tier-3)  { consult_seq, answer: "infected"|"not_infected"|"need_evidence", reason, cites? }
 *   review.verdict    (Tier-3)  { event_id, decision: "agree"|"reopen", reason }
 * PURE and client-safe; nothing here knows the truth. The report judges them (computeReport).
 */
import type { Ev } from "./types";
import { asStr, hostKey } from "./format";
import { LEAD_KIND } from "./shiftLead";
import { buildRegister } from "./t3Case";

export interface ShiftLead { seq: number; host: string; text: string; opened: boolean; resolved: boolean }

/** The open lead, if the session has one, and how far the Tier-3 took it. */
export function shiftLeadOf(events: Ev[]): ShiftLead | null {
  const e = events.find(x => x.type === "staff.inject" && (x.payload as { kind?: unknown }).kind === LEAD_KIND);
  if (!e) return null;
  const host = asStr((e.payload as { host?: unknown }).host);
  if (!host) return null;
  const entry = buildRegister(events).find(r => r.kind === "host" && r.key === hostKey(host));
  return { seq: e.seq, host, text: asStr((e.payload as { text?: unknown }).text), opened: !!entry, resolved: !!entry && entry.state !== "suspected" };
}

const CLOSED = new Set(["benign", "false_positive"]);

export interface ClosedCase { eventId: string; verdict: string; atSeq: number; summary: string; host: string }

/**
 * Alerts the team closed as benign / false positive and nobody escalated or reported as an attack
 * afterwards: the closure-review queue. The closer's name is left out on purpose (quality control,
 * not a personal review). Newest first; already-reviewed ones drop out.
 */
export function closedCases(events: Ev[], feed: Ev[]): ClosedCase[] {
  const rowOf = new Map(feed.map(f => [asStr((f.payload as { id?: unknown }).id), f.payload as Record<string, unknown>]));
  const latest = new Map<string, { verdict: string; seq: number }>();
  const escalated = new Set<string>();
  const reviewed = new Set(events.filter(e => e.type === "review.verdict").map(e => asStr((e.payload as { event_id?: unknown }).event_id)));
  for (const e of events) {
    const p = e.payload as Record<string, unknown>;
    const eid = asStr(p.event_id);
    if (!eid) continue;
    if (e.type === "disposition.set") latest.set(eid, { verdict: asStr(p.verdict), seq: e.seq });
    else if (e.type === "report.submitted") latest.set(eid, { verdict: asStr(p.verdict), seq: e.seq });
    else if (e.type === "escalation.requested" || e.type === "elevation.requested" || e.type === "containment.requested") escalated.add(eid);
  }
  const out: ClosedCase[] = [];
  for (const [eid, v] of latest) {
    if (!CLOSED.has(v.verdict) || escalated.has(eid) || reviewed.has(eid)) continue;
    const row = rowOf.get(eid) ?? {};
    // Alerts only (high / critical, or a detection), not every quiet log someone marked benign.
    const sev = asStr(row.severity).toLowerCase();
    if (sev !== "high" && sev !== "critical" && row.is_detection !== true) continue;
    out.push({ eventId: eid, verdict: v.verdict, atSeq: v.seq, summary: asStr(row.description) || asStr(row.event_type) || "alert", host: asStr(row.hostname) });
  }
  return out.sort((a, b) => b.atSeq - a.atSeq);
}

export type ConsultAnswer = "infected" | "not_infected" | "need_evidence";
export const CONSULT_LABEL: Record<ConsultAnswer, string> = { infected: "Infected", not_infected: "Not infected", need_evidence: "Need more evidence" };

export interface Consult {
  seq: number; by: string | null; eventId: string; question: string; host: string;
  answer: { seq: number; by: string | null; value: ConsultAnswer; reason: string } | null;
}

export function consultsOf(events: Ev[]): Consult[] {
  const out = new Map<number, Consult>();
  for (const e of events) {
    const p = e.payload as Record<string, unknown>;
    if (e.type === "consult.asked") {
      out.set(e.seq, { seq: e.seq, by: e.actor_id, eventId: asStr(p.event_id), question: asStr(p.question).slice(0, 400), host: asStr(p.host), answer: null });
    } else if (e.type === "consult.answered") {
      const c = out.get(Number(p.consult_seq));
      const v = p.answer === "infected" || p.answer === "not_infected" || p.answer === "need_evidence" ? p.answer : null;
      if (c && v && !c.answer) c.answer = { seq: e.seq, by: e.actor_id, value: v, reason: asStr(p.reason).slice(0, 400) };
    }
  }
  return [...out.values()];
}

/** What waits for the Tier-3 now (for the status bar and the inbox badge). */
export function t3Waiting(events: Ev[], feed: Ev[]): { lead: ShiftLead | null; consults: number; reviews: number } {
  const lead = shiftLeadOf(events);
  return {
    lead: lead && !lead.opened ? lead : null,
    consults: consultsOf(events).filter(c => !c.answer).length,
    reviews: Math.min(3, closedCases(events, feed).length),
  };
}
