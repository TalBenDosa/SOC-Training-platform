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
export interface ContainmentView { seq: number; eid: string; target: string; type: string; criticality: string; owner: string; requester: string | null; requesterRole: string | null; atMs: number; status: string; critical: boolean }

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
    };
  });

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
      expired: !a && nowMs > atMs + deadlineS * 1000,
    };
  });

  return {
    nowMs, difficulty, manager, seated, escalations,
    firstEscalationMs: escalations.length ? Math.min(...escalations.map(e => e.atMs)) : null,
    containments, isolatedHosts, scopeConfirmed: latestScope(events)?.confirmed ?? false, declared,
    sitrepTimes: events.filter(e => e.type === "sitrep.sent").map(ms),
    loadByUser: openLoadByUser(events, nowMs), lastActionMs, teamText, cards,
  };
}

/** Words the team uses when it believes data is leaving the network. */
export const DATA_WORDS = /\b(exfil\w*|upload\w*|rclone|megasync|mega\.nz|7z|7-zip|archiv\w*|staged|staging|transfer\w*|leak\w*|stolen|dump\w*|pii|personal data|customer data|patient)\b/;
export const teamSuspectsData = (s: MgrState) => DATA_WORDS.test(s.teamText);
export const firstName = (m: Member | undefined | null, fallback: string) => (m?.name?.trim() || fallback);
