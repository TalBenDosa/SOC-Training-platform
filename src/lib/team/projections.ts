import type { Ev } from "@/lib/team/types";
import { pausedSpans, activeMs } from "@/lib/team/pauses";

/**
 * ONE claims / open-work projection for the whole room (audit A3). It used to be
 * reconstructed four times with different rules — the feed badges, the Tier-1
 * console and the Situation Board expired a claim after 5 minutes, while the
 * after-action replay never did — so the AAR could penalise a Manager for "not
 * nudging" an overload the Situation Board had correctly stopped showing.
 * Pure: pass the reference time explicitly (serverNow() live, event time in a replay).
 */
export const CLAIM_TTL_MS = 5 * 60 * 1000;

export interface Claim { by: string; at: number }

const eidOf = (e: Ev) => String((e.payload as { event_id?: unknown } | null)?.event_id ?? "");
const tsOf = (e: Ev, fallback: number) => (e.occurred_at ? Date.parse(e.occurred_at) : fallback);

/**
 * Active Tier-1 soft-claims at time `now`: the latest claimed / released /
 * disposition / escalation event per alert decides — a claim holds only while it IS
 * the latest — and it expires after `ttlMs`. Same rule the server enforces for
 * `claim_held` (migration 0073), so the 🔒 you see is the lock the server applies.
 * (Tier-1 re-claims right after a true-positive / suspicious call, so the lock stays
 * while the escalation is being written.) The TTL counts RUNNING time: paused spans in
 * `events` are skipped (QA M3) — the DB claim check does the same (0088 team_active_ms).
 */
export function activeClaims(events: Ev[], now: number, ttlMs = CLAIM_TTL_MS): Map<string, Claim> {
  const m = new Map<string, Claim>();
  for (const e of events) {
    if (e.type !== "alert.claimed" && e.type !== "alert.released" && e.type !== "disposition.set" && e.type !== "escalation.requested") continue;
    const eid = eidOf(e); if (!eid) continue;
    if (e.type === "alert.claimed") m.set(eid, { by: e.actor_id ?? "", at: tsOf(e, now) });
    else m.delete(eid);
  }
  const spans = pausedSpans(events, now);
  for (const [eid, c] of m) if (activeMs(c.at, now, spans) > ttlMs) m.delete(eid);
  return m;
}

/**
 * Open work per analyst at time `now`: active T1 claims + T2/T3 escalations they
 * own (first acknowledger, or whoever explicitly took it over) that aren't resolved
 * or bounced yet.
 */
export function openLoadByUser(events: Ev[], now: number, ttlMs = CLAIM_TTL_MS): Map<string, number> {
  const load = new Map<string, number>();
  const bump = (u: string) => { if (u) load.set(u, (load.get(u) ?? 0) + 1); };
  for (const c of activeClaims(events, now, ttlMs).values()) bump(c.by);
  for (const st of escalationStates(events).values()) if (st.owner && !st.resolved && !st.bounced) bump(st.owner);
  return load;
}

// ── Escalation state machine (per escalated log) ─────────────────────────────
// The server now allows a log to be escalated AGAIN after a bounce/resolve
// (`already_escalated` only while one is open) and lets a backup take a case over
// (`takeover: true`). State is therefore per ROUND: a new escalation.requested after
// a bounce/resolve opens a fresh round; ack/bounce/resolve apply to the current one.
export interface EscalationState {
  eid: string;
  request: Ev;              // the latest escalation.requested (the current round)
  rounds: number;           // how many times this log has been escalated (0 = request not in view)
  owner: string | null;     // first acknowledger — or the latest explicit take-over
  acked: boolean;
  bounced: boolean;
  bounceReason: string;
  resolved: boolean;
}
export function escalationStates(events: Ev[]): Map<string, EscalationState> {
  const m = new Map<string, EscalationState>();
  for (const e of events) {
    const eid = eidOf(e);
    if (!eid) continue;
    const p = (e.payload ?? {}) as { takeover?: unknown; reason?: unknown };
    let st = m.get(eid);
    if (!st && (e.type === "escalation.acknowledged" || e.type === "escalation.bounced" || e.type === "escalation.resolved")) {
      // an ack/bounce/resolve with no request in view (partial log) — still track it
      st = { eid, request: e, rounds: 0, owner: null, acked: false, bounced: false, bounceReason: "", resolved: false };
      m.set(eid, st);
    }
    if (e.type === "escalation.requested") {
      if (!st) m.set(eid, { eid, request: e, rounds: 1, owner: null, acked: false, bounced: false, bounceReason: "", resolved: false });
      else if (st.bounced || st.resolved) m.set(eid, { eid, request: e, rounds: st.rounds + 1, owner: null, acked: false, bounced: false, bounceReason: "", resolved: false });
      // else: a (legacy) duplicate while open — same round, keep its owner/status
    } else if (!st) {
      continue;
    } else if (e.type === "escalation.acknowledged") {
      if (!st.owner || p.takeover === true) st.owner = e.actor_id ?? "";
      st.acked = true;
    } else if (e.type === "escalation.bounced") {
      st.bounced = true; st.bounceReason = typeof p.reason === "string" ? p.reason : "";
    } else if (e.type === "escalation.resolved") {
      st.resolved = true;
    }
  }
  return m;
}
/** Open = escalated, not yet taken, not bounced back, not resolved (Situation Board / Lead backlog). */
export const isOpenEscalation = (s: EscalationState) => !s.acked && !s.bounced && !s.resolved;

// ── Containment requests (keyed by REQUEST seq, not by event id) ──────────────
// After a DENY the analyst may request again (new target / justification), so one
// escalated log can carry several requests. A decision/execution applies to the
// request it names (`request_seq`), else to the waiting request with the same
// `target`, else — a legacy decision with neither — to every waiting request on that
// log (the server's matching rule in 0073).
export type ContainmentStatus = "pending" | "approved" | "denied" | "executed";
export interface ContainmentRequest {
  seq: number; eid: string; request: Ev; status: ContainmentStatus;
  decidedBy: string | null; decisionReason: string; executedBy: string | null;
}
export function containmentRequests(events: Ev[]): ContainmentRequest[] {
  const out: ContainmentRequest[] = [];
  const latestOf = (eid: string, want: ContainmentStatus) => {
    for (let i = out.length - 1; i >= 0; i--) if (out[i].eid === eid && out[i].status === want) return out[i];
    return null;
  };
  for (const e of events) {
    const eid = eidOf(e);
    if (!eid) continue;
    const p = (e.payload ?? {}) as { reason?: unknown; request_seq?: unknown };
    if (e.type === "containment.requested") { out.push({ seq: e.seq, eid, request: e, status: "pending", decidedBy: null, decisionReason: "", executedBy: null }); continue; }
    if (e.type !== "containment.approved" && e.type !== "containment.denied" && e.type !== "containment.executed") continue;
    const want: ContainmentStatus = e.type === "containment.executed" ? "approved" : "pending";
    const target = typeof (p as { target?: unknown }).target === "string" ? String((p as { target?: unknown }).target).trim() : "";
    const bySeq = typeof p.request_seq === "number" ? out.find(r => r.seq === p.request_seq && r.eid === eid && r.status === want) : undefined;
    let byTarget: ContainmentRequest | undefined;
    if (!bySeq && target) for (let i = out.length - 1; i >= 0; i--) { const r = out[i]; if (r.eid === eid && r.status === want && String((r.request.payload as { target?: unknown }).target ?? "").trim() === target) { byTarget = r; break; } }
    const hits = bySeq ? [bySeq] : byTarget ? [byTarget]
      : e.type === "containment.executed" ? [latestOf(eid, want)].filter((x): x is ContainmentRequest => !!x)
      : out.filter(r => r.eid === eid && r.status === want);
    for (const r of hits) {
      if (e.type === "containment.executed") { r.status = "executed"; r.executedBy = e.actor_id; }
      else { r.status = e.type === "containment.approved" ? "approved" : "denied"; r.decidedBy = e.actor_id; r.decisionReason = typeof p.reason === "string" ? p.reason : ""; }
    }
  }
  return out;
}

// ── Incidents (per-incident case view) ────────────────────────────────────────
// A free `incident` label can ride on scope.set / report.submitted /
// containment.requested / hunt.logged. Every escalated log belongs to the incident
// named by the latest labelled action on it; unlabelled logs are their own incident
// (the escalation's root event) — so old sessions without labels still group.
const labelOf = (e: Ev) => { const v = (e.payload as { incident?: unknown } | null)?.incident; return typeof v === "string" ? v.trim().slice(0, 80) : ""; };
export function incidentByEvent(events: Ev[]): Map<string, string> {
  const m = new Map<string, string>();
  for (const e of events) {
    const lab = labelOf(e); if (!lab) continue;
    const eid = eidOf(e);
    if (eid && (e.type === "report.submitted" || e.type === "containment.requested" || e.type === "hunt.logged" || e.type === "scope.set" || e.type === "scope.confirmed")) m.set(eid, lab);
  }
  return m;
}
/** Every incident label used so far (for a pick-list), first-seen order. */
export function incidentLabels(events: Ev[]): string[] {
  const seen: string[] = [];
  for (const e of events) { const lab = labelOf(e); if (lab && !seen.includes(lab)) seen.push(lab); }
  return seen;
}
export interface ScopeSnapshot { hosts: string[]; users: string[]; techniques: string[]; confirmed: boolean; by: string | null; seq: number }
/**
 * Latest scope per incident label ("" = the unlabelled / shift-wide scope).
 * `confirmed` is true only while the LATEST scope event is a Tier-3 confirmation —
 * a later scope.set re-opens it (the "sticky confirmed" bug).
 */
export function scopeByIncident(events: Ev[]): Map<string, ScopeSnapshot> {
  const m = new Map<string, ScopeSnapshot>();
  for (const e of events) {
    if (e.type !== "scope.set" && e.type !== "scope.confirmed") continue;
    const p = (e.payload ?? {}) as { hosts?: unknown; users?: unknown; techniques?: unknown };
    const arr = (v: unknown) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : []);
    m.set(labelOf(e), { hosts: arr(p.hosts), users: arr(p.users), techniques: arr(p.techniques), confirmed: e.type === "scope.confirmed", by: e.actor_id, seq: e.seq });
  }
  return m;
}
/** The most recent scope of any incident (what the header/legacy single-scope views show). */
export function latestScope(events: Ev[]): ScopeSnapshot | null {
  let best: ScopeSnapshot | null = null;
  for (const s of scopeByIncident(events).values()) if (!best || s.seq > best.seq) best = s;
  return best;
}

/** EDR network containment of one host (0082): the latest isolate / release decides. */
export interface HostIsolation { host: string; isolated: boolean; by: string | null; at: string | null; seq: number }
export const EDR_ISOLATION_TYPES = ["edr.host_isolated", "edr.host_released"] as const;
/** Which hosts are isolated right now — keyed by the lower-cased host name (host names are case-insensitive). */
export function isolationState(events: Ev[]): Map<string, HostIsolation> {
  const m = new Map<string, HostIsolation>();
  for (const e of events) {
    if (e.type !== "edr.host_isolated" && e.type !== "edr.host_released") continue;
    const host = String((e.payload as { host?: unknown } | null)?.host ?? "").trim();
    if (!host) continue;
    const prev = m.get(host.toLowerCase());
    if (prev && prev.seq > e.seq) continue;
    m.set(host.toLowerCase(), { host, isolated: e.type === "edr.host_isolated", by: e.actor_id, at: e.occurred_at ?? null, seq: e.seq });
  }
  return m;
}
