/**
 * Injects that need an answer from THIS player (2026-10-18 review: across four Team Training
 * exercises no help-desk ticket, decoy or management request was ever handled; they sat in a
 * card at the bottom of the column, and an "update" had no way to answer it).
 *
 *  - help-desk ticket → Tier-1 (answered with ticket.answered, as before)
 *  - update (a decoy or a twist; the real kind stays hidden) → every analyst (inject.responded)
 *  - management request with no SOC Manager on the team → Tier-2 (Tier-3 if there is no Tier-2)
 *
 * An item leaves the box once this player answered it, or once a teammate answered a ticket /
 * management request (one answer is the team's). Updates stay until this player has made a call:
 * a decoy must be judged by everyone it reaches.
 */
import type { Ev } from "./types";

export type InboxKind = "ticket" | "update" | "mgmt";
export interface InboxItem { seq: number; injectId: string; kind: InboxKind; text: string }

export const UPDATE_DECISIONS = [
  { id: "benign", label: "Not an incident", hint: "Verified as approved or benign" },
  { id: "investigate", label: "Real, I'm investigating", hint: "Escalate or work it in your console" },
  { id: "rescope", label: "Changes our case", hint: "Re-scope the incident we are working" },
] as const;
export type UpdateDecision = (typeof UPDATE_DECISIONS)[number]["id"];

/** A response must say what was checked: at least this many characters. */
export const MIN_RESPONSE_CHARS = 15;

const str = (v: unknown) => (typeof v === "string" ? v : "");

export function actionInbox(events: Ev[], me: { id: string; role: string | null }, roster: { role: string; status: string }[]): InboxItem[] {
  const role = me.role ?? "";
  const active = roster.filter(m => m.status !== "left");
  const hasManager = active.some(m => m.role === "mgr" || m.role === "lead");
  const hasT2 = active.some(m => m.role === "t2");
  const answeredTickets = new Set(events.filter(e => e.type === "ticket.answered").map(e => String((e.payload as { ticket_seq?: unknown }).ticket_seq)));
  const responded = events.filter(e => e.type === "inject.responded");
  const iResponded = new Set(responded.filter(e => e.actor_id === me.id).map(e => String((e.payload as { inject_seq?: unknown }).inject_seq)));
  const anyResponded = new Set(responded.map(e => String((e.payload as { inject_seq?: unknown }).inject_seq)));
  const sitreps = events.filter(e => e.type === "sitrep.sent").map(e => e.seq);
  const analyst = ["t1", "t2", "t3", "de", "ti"].includes(role);
  const ownsMgmt = !hasManager && (role === "t2" || (role === "t3" && !hasT2));

  const out: InboxItem[] = [];
  for (const e of events) {
    if (e.type !== "staff.inject") continue;
    const p = e.payload as { kind?: unknown; text?: unknown; inject_id?: unknown };
    const kind = str(p.kind);
    const base = { seq: e.seq, injectId: str(p.inject_id), text: str(p.text) };
    if (kind === "ticket") {
      if (role === "t1" && !answeredTickets.has(String(e.seq))) out.push({ ...base, kind: "ticket" });
    } else if (kind === "update") {
      if (analyst && !iResponded.has(String(e.seq))) out.push({ ...base, kind: "update" });
    } else if (kind === "mgmt_request" || kind === "mgmt_pressure") {
      if (ownsMgmt && !anyResponded.has(String(e.seq)) && !sitreps.some(s => s > e.seq)) out.push({ ...base, kind: "mgmt" });
    }
  }
  return out;
}
