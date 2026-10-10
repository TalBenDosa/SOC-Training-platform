/**
 * The live picture the SOC-Manager incident director reads to decide which decision card (if
 * any) to fire. It is built ONLY from what the team can see in the session log: escalations,
 * acknowledgements, containment requests and decisions, isolations, scope, declarations,
 * SITREPs, who is seated, and the text the team wrote. Never from the answer key: a card that
 * fired because a log was secretly an attack would tell the manager the answer.
 *
 * Pure and isomorphic, so the director route and the tests share it.
 */
import type { Ev } from "@/lib/team/types";
import { asStr, hostKey } from "@/lib/team/format";
import { containmentRequests, escalationStates, isOpenEscalation, latestScope, openLoadByUser, isolationState } from "@/lib/team/projections";
import { LATE_GRACE_S } from "./timing";

export type Difficulty = "easy" | "medium" | "hard";
export interface Member { user_id: string; role: string; status: string; name: string }

export interface DirectorInput {
  events: Ev[];
  roster: Member[];
  nowMs: number;
  difficulty: Difficulty;
  /** Hosts the company treats as critical (DC, file server): from the asset fabric. */
  criticalHosts?: string[];
}

export interface FiredCard {
  card: string; injectId: string; seq: number; atMs: number; deadlineS: number;
  answered: { option: string; confidence: string; atMs: number } | null;
  expired: boolean;
}

export interface EscalationView { eid: string; seq: number; atMs: number; by: string | null; byRole: string | null; host: string; summary: string; open: boolean; owner: string | null }
export interface AdviceView { by: string | null; role: string | null; stance: "support" | "object"; reason: string; atMs: number; via: "advice" | "chat" }
export interface ContainmentView { seq: number; eid: string; target: string; type: string; criticality: string; owner: string; requester: string | null; requesterRole: string | null; atMs: number; status: string; critical: boolean; reason: string; advice: AdviceView[] }
/** Two analysts on record with opposite calls on the same log (attack vs benign). */
export interface VerdictConflict { eid: string; host: string; label: string; attack: { by: string; role: string; how: string }; benign: { by: string; role: string; how: string }; atMs: number }
/** Tier-2 bounced an escalation back and Tier-1 escalated the same log again. */
export interface BounceDispute { eid: string; host: string; summary: string; bouncedBy: string; bounceReason: string; reEscalatedBy: string; atMs: number }
export interface FiredQuestion { qid: string; injectId: string; seq: number; atMs: number; deadlineS: number; replied: { text: string; atMs: number } | null; expired: boolean }

export interface MgrState {
  nowMs: number;
  difficulty: Difficulty;
  manager: Member | null;
  seated: Record<string, Member[]>;
  escalations: EscalationView[];
  firstEscalationMs: number | null;
  containments: ContainmentView[];
  isolatedHosts: { host: string; atMs: number }[];
  scopeConfirmed: boolean;
  declared: { severity: number; atMs: number } | null;
  sitrepTimes: number[];
  loadByUser: Map<string, number>;
  lastActionMs: Map<string, number>;
  /** The team's own words (escalation summaries, reports, notes, chat), lower-cased. */
  teamText: string;
  cards: FiredCard[];
  verdictConflicts: VerdictConflict[];
  bounceDisputes: BounceDispute[];
  questions: FiredQuestion[];
  /** Severity changes after the declaration (oldest first). */
  severityChanges: { severity: number; reason: string; atMs: number }[];
  /** The manager's updates to management: SITREPs and stakeholder reports. */
  updateTimes: number[];
  reports: { atMs: number; dataImpact: string; status: string }[];
}

const ms = (e: Ev) => (e.occurred_at ? Date.parse(e.occurred_at) : NaN);
const ACTIVE = (m: Member) => m.status !== "left";
/** Names a critical asset: a domain controller, payment, ERP, EMR, core banking, SWIFT, backup. */
export const CRITICAL_NAME = /(^|[-_])(dc\d*|pay|payment|gw|erp|emr|ehr|pacs|core|swift|bkp|backup|sap|db|sql)([-_\d]|$)/i;

export function buildMgrState(input: DirectorInput): MgrState {
  const { events, roster, nowMs, difficulty } = input;
  const active = roster.filter(ACTIVE);
  const seated: Record<string, Member[]> = {};
  for (const m of active) (seated[m.role] ??= []).push(m);
  const manager = seated.mgr?.[0] ?? seated.lead?.[0] ?? null;

  const feedById = new Map<string, Record<string, unknown>>();
  for (const e of events) if (e.type === "feed.event") feedById.set(String((e.payload as { id?: unknown }).id ?? ""), e.payload);

  const states = escalationStates(events);
  const escalations: EscalationView[] = [];
  for (const s of states.values()) {
    if (s.rounds === 0) continue;
    const p = s.request.payload as { event_id?: string; summary?: string; what?: string; hostname?: string; snapshot?: { hostname?: unknown } };
    const host = asStr(p.hostname) || asStr(p.snapshot?.hostname) || asStr((feedById.get(s.eid) ?? {}).hostname);
    escalations.push({
      eid: s.eid, seq: s.request.seq, atMs: ms(s.request), by: s.request.actor_id, byRole: s.request.role,
      host, summary: asStr(p.summary) || asStr(p.what) || "an escalated alert", open: isOpenEscalation(s), owner: s.owner,
    });
  }
  escalations.sort((a, b) => a.seq - b.seq);

  const critical = new Set((input.criticalHosts ?? []).map(hostKey));
  const containments: ContainmentView[] = containmentRequests(events).map(r => {
    const p = r.request.payload as { target?: string; containment_type?: string; asset_criticality?: string; business_owner?: string };
    const target = asStr(p.target);
    const criticality = asStr(p.asset_criticality);
    return {
      seq: r.seq, eid: r.eid, target, type: asStr(p.containment_type) || "isolate", criticality, owner: asStr(p.business_owner),
      requester: r.request.actor_id, requesterRole: r.request.role, atMs: ms(r.request), status: r.status,
      critical: criticality === "crown_jewel" || criticality === "high" || critical.has(hostKey(target)) || CRITICAL_NAME.test(target),
      reason: asStr((r.request.payload as { reason?: unknown }).reason) || asStr((r.request.payload as { justification?: unknown }).justification),
      advice: [],
    };
  });
  // Second opinions on a request: an explicit Support / Object, or a teammate's own words in the
  // chat or a note that name the target and say to hold off. Only REAL objections make a card.
  const roleOfUser = new Map(roster.map(m => [m.user_id, m.role]));
  for (const e of events) {
    if (e.type !== "containment.advised") continue;
    const p = e.payload as { request_seq?: unknown; stance?: unknown; reason?: unknown };
    const c = containments.find(x => x.seq === Number(p.request_seq));
    if (c) c.advice.push({ by: e.actor_id, role: e.role ?? roleOfUser.get(e.actor_id ?? "") ?? null, stance: p.stance === "object" ? "object" : "support", reason: asStr(p.reason), atMs: ms(e), via: "advice" });
  }
  for (const e of events) {
    if ((e.type !== "message.sent" && e.type !== "note.added") || !e.actor_id) continue;
    const role = e.role ?? roleOfUser.get(e.actor_id) ?? "";
    if (role !== "t2" && role !== "t3") continue;
    const text = asStr((e.payload as { text?: unknown }).text);
    if (!HOLD_WORDS.test(text)) continue;
    const t = ms(e);
    const low = text.toLowerCase();
    for (const c of containments) {
      if (c.requester === e.actor_id || !c.target || t < c.atMs || c.advice.some(a => a.by === e.actor_id)) continue;
      if (low.includes(c.target.toLowerCase()) || low.includes(hostKey(c.target))) c.advice.push({ by: e.actor_id, role, stance: "object", reason: text.slice(0, 200), atMs: t, via: "chat" });
    }
  }

  const isolatedHosts = [...isolationState(events).values()].filter(h => h.isolated).map(h => ({ host: h.host, atMs: h.at ? Date.parse(h.at) : nowMs }));
  for (const c of containments) if (c.status === "executed" && !isolatedHosts.some(h => hostKey(h.host) === hostKey(c.target))) isolatedHosts.push({ host: c.target, atMs: c.atMs });

  const decl = events.find(e => e.type === "incident.declared");
  let declared = decl ? { severity: Number((decl.payload as { severity?: unknown }).severity), atMs: ms(decl) } : null;
  for (const e of events) if (e.type === "incident.severity_changed" && declared) declared = { ...declared, severity: Number((e.payload as { severity?: unknown }).severity) };

  const lastActionMs = new Map<string, number>();
  for (const e of events) if (e.actor_id && e.type !== "event.opened") lastActionMs.set(e.actor_id, ms(e));

  const textOf = (e: Ev) => {
    const p = e.payload as Record<string, unknown>;
    return [p.summary, p.what, p.why, p.observations, p.assessment, p.findings, p.text, p.reason, p.recommendation].map(asStr).join(" ");
  };
  const teamText = events.filter(e => e.actor_id && ["escalation.requested", "report.submitted", "note.added", "message.sent", "containment.requested", "hunt.logged", "elevation.requested"].includes(e.type))
    .map(textOf).join(" ").toLowerCase();

  const answers = new Map<string, Ev>();
  for (const e of events) if (e.type === "decision.answered") answers.set(String((e.payload as { inject_id?: unknown }).inject_id), e);
  const cards: FiredCard[] = events.filter(e => e.type === "staff.inject" && (e.payload as { kind?: unknown }).kind === "decision").map(e => {
    const p = e.payload as { card?: unknown; inject_id?: unknown; deadline_s?: unknown };
    const injectId = String(p.inject_id ?? "");
    const a = answers.get(injectId);
    const atMs = ms(e);
    const deadlineS = Number(p.deadline_s) || 240;
    const ap = a?.payload as { option?: unknown; confidence?: unknown } | undefined;
    return {
      card: String(p.card ?? ""), injectId, seq: e.seq, atMs, deadlineS,
      answered: a ? { option: String(ap?.option ?? ""), confidence: String(ap?.confidence ?? ""), atMs: ms(a) } : null,
      // Closed = past the deadline AND the late window (a late card is still on the desk).
      expired: !a && nowMs > atMs + (deadlineS + LATE_GRACE_S) * 1000,
    };
  });

  // ── Real disagreements on the record ──
  const nameOf = (u: string | null) => roster.find(m => m.user_id === u)?.name || "a teammate";
  const calls = new Map<string, Map<string, { cls: "attack" | "benign"; role: string; how: string; atMs: number }>>();
  const putCall = (e: Ev, eid: string, cls: "attack" | "benign" | null, how: string) => {
    if (!cls || !eid || !e.actor_id) return;
    if (!calls.has(eid)) calls.set(eid, new Map());
    calls.get(eid)!.set(e.actor_id, { cls, role: e.role ?? roleOfUser.get(e.actor_id) ?? "", how, atMs: ms(e) });
  };
  for (const e of events) {
    const p = e.payload as { event_id?: unknown; verdict?: unknown };
    const eid = asStr(p.event_id);
    if (e.type === "disposition.set") {
      const v = asStr(p.verdict);
      putCall(e, eid, v === "true_positive" ? "attack" : v === "false_positive" || v === "benign" ? "benign" : null, v === "true_positive" ? "marked it a true positive" : "closed it as benign / false positive");
    } else if (e.type === "escalation.requested") putCall(e, eid, "attack", "escalated it");
    else if (e.type === "report.submitted") {
      const v = asStr(p.verdict).toLowerCase();
      putCall(e, eid, ["true_positive", "tp", "escalate"].includes(v) ? "attack" : ["false_positive", "benign", "fp"].includes(v) ? "benign" : null, `reported it as ${v.replace("_", " ")}`);
    }
  }
  const verdictConflicts: VerdictConflict[] = [];
  for (const [eid, byUser] of calls) {
    const list = [...byUser.entries()];
    const atk = list.filter(([, c]) => c.cls === "attack").sort((a, b) => b[1].atMs - a[1].atMs)[0];
    const ben = list.filter(([, c]) => c.cls === "benign").sort((a, b) => b[1].atMs - a[1].atMs)[0];
    if (!atk || !ben) continue;
    const f = feedById.get(eid) ?? {};
    verdictConflicts.push({
      eid, host: asStr(f.hostname), label: asStr(f.description) || asStr(f.event_type) || "a log",
      attack: { by: nameOf(atk[0]), role: atk[1].role, how: atk[1].how }, benign: { by: nameOf(ben[0]), role: ben[1].role, how: ben[1].how },
      atMs: Math.max(atk[1].atMs, ben[1].atMs),
    });
  }
  verdictConflicts.sort((a, b) => a.atMs - b.atMs);
  const bounceDisputes: BounceDispute[] = [];
  for (const e of events) {
    if (e.type !== "escalation.bounced") continue;
    const eid = asStr((e.payload as { event_id?: unknown }).event_id);
    const again = events.find(x => x.type === "escalation.requested" && x.seq > e.seq && asStr((x.payload as { event_id?: unknown }).event_id) === eid);
    if (!again) continue;
    const esc = escalations.find(x => x.eid === eid);
    bounceDisputes.push({ eid, host: esc?.host ?? asStr((feedById.get(eid) ?? {}).hostname), summary: esc?.summary ?? "an escalated alert", bouncedBy: nameOf(e.actor_id), bounceReason: asStr((e.payload as { reason?: unknown }).reason), reEscalatedBy: nameOf(again.actor_id), atMs: ms(again) });
  }
  const replies = new Map<string, Ev>();
  for (const e of events) if (e.type === "stakeholder.replied") replies.set(String((e.payload as { inject_id?: unknown }).inject_id), e);
  const questions: FiredQuestion[] = events.filter(e => e.type === "stakeholder.asked").map(e => {
    const p = e.payload as { qid?: unknown; inject_id?: unknown; deadline_s?: unknown };
    const injectId = String(p.inject_id ?? "");
    const r = replies.get(injectId);
    const atMs = ms(e); const deadlineS = Number(p.deadline_s) || 240;
    return { qid: String(p.qid ?? ""), injectId, seq: e.seq, atMs, deadlineS, replied: r ? { text: asStr((r.payload as { text?: unknown }).text), atMs: ms(r) } : null, expired: !r && nowMs > atMs + (deadlineS + LATE_GRACE_S) * 1000 };
  });
  const severityChanges = events.filter(e => e.type === "incident.severity_changed").map(e => ({ severity: Number((e.payload as { severity?: unknown }).severity), reason: asStr((e.payload as { reason?: unknown }).reason), atMs: ms(e) }));
  const reports = events.filter(e => e.type === "stakeholder.report_sent").map(e => ({ atMs: ms(e), dataImpact: asStr((e.payload as { data_impact?: unknown }).data_impact), status: asStr((e.payload as { status?: unknown }).status) }));
  const updateTimes = [...events.filter(e => e.type === "sitrep.sent").map(ms), ...reports.map(r => r.atMs)].sort((a, b) => a - b);

  return {
    verdictConflicts, bounceDisputes, questions, severityChanges, reports, updateTimes,
    nowMs, difficulty, manager, seated, escalations,
    firstEscalationMs: escalations.length ? Math.min(...escalations.map(e => e.atMs)) : null,
    containments, isolatedHosts, scopeConfirmed: latestScope(events)?.confirmed ?? false, declared,
    sitrepTimes: events.filter(e => e.type === "sitrep.sent").map(ms),
    loadByUser: openLoadByUser(events, nowMs), lastActionMs, teamText, cards,
  };
}

/** A teammate saying to hold off on a containment ("wait", "not yet", "keep watching it"). */
export const HOLD_WORDS = /\b(wait|hold (off|on)|don'?t isolate|do not isolate|not yet|keep (watching|monitoring|it (up|online))|watch (it|first)|monitor (it|first)|observe|too early|let'?s see)\b/i;

/** Words the team uses when it believes data is leaving the network. */
export const DATA_WORDS = /\b(exfil\w*|upload\w*|rclone|megasync|mega\.nz|7z|7-zip|archiv\w*|staged|staging|transfer\w*|leak\w*|stolen|dump\w*|pii|personal data|customer data|patient)\b/;
export const teamSuspectsData = (s: MgrState) => DATA_WORDS.test(s.teamText);
export const firstName = (m: Member | undefined | null, fallback: string) => (m?.name?.trim() || fallback);
