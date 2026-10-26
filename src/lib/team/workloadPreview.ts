/**
 * Workload preview: run the exercise ahead of time and measure the work it asks of the team
 * (Tal, 2026-10-25, after the Sdema exercise where one Tier-1 got 73 logs in 17 minutes).
 *
 * The timeline is the one /start would seed (same plan, roster, shift, products). From it:
 *  - Tier-1 work: every feed log read (WORK.READ_SEC_PER_LOG), every high/critical alert triaged
 *    (WORK.TRIAGE_MIN) and every incident escalated well (ESCALATIONS_PER_INCIDENT x WORK.ESCALATION_MIN);
 *  - Tier-2/3 work: every incident taken as a case (CASE_MIN: acknowledge, walk the EDR, contain, write it up);
 * each against that tier's capacity (people x shift x WORK.UTILIZATION). Pure: no I/O.
 */
import { WORK, type TeamLoad } from "./load";

export const ESCALATIONS_PER_INCIDENT = 1.5;
export const CASE_MIN = 10;
/** A further alert of an incident already identified: read, link it to the case, move on. */
export const LINKED_ALERT_MIN = 0.33;

export interface TimelineRow { channel: string; due_offset_ms: number; body?: unknown; answer?: unknown }
export type WorkloadLevel = "ok" | "busy" | "over";
export interface TierLoad { people: number; workMin: number; capacityMin: number; pct: number | null; level: WorkloadLevel | null }
export interface WorkloadPreview {
  shiftMin: number;
  feedRows: number;
  logsPerMin: number;
  attackRows: number;
  attackShare: number;
  alertRows: number;
  incidents: number;
  tier1: TierLoad;
  tier2: TierLoad;
  level: WorkloadLevel;
}

const levelOf = (pct: number): WorkloadLevel => (pct <= 0.85 ? "ok" : pct <= 1 ? "busy" : "over");

function tier(people: number, workMin: number, shiftMin: number): TierLoad {
  const capacityMin = people * shiftMin * WORK.UTILIZATION;
  if (!people) return { people, workMin: Math.round(workMin), capacityMin: 0, pct: null, level: null };
  const pct = Math.round((workMin / capacityMin) * 100) / 100;
  return { people, workMin: Math.round(workMin), capacityMin: Math.round(capacityMin), pct, level: levelOf(pct) };
}

export function measureWorkload(timeline: TimelineRow[], load: Pick<TeamLoad, "shiftMin" | "triageAnalysts">, roster: { role: string; status?: string }[]): WorkloadPreview {
  const feed = timeline.filter(r => r.channel === "feed");
  const body = (r: TimelineRow) => (r.body ?? {}) as { severity?: unknown };
  const ans = (r: TimelineRow) => (r.answer ?? {}) as { origin?: unknown; incident_id?: unknown };
  const attack = feed.filter(r => ans(r).origin === "story" || ans(r).origin === "pool_attack" || ans(r).origin === "pool");
  const isAlert = (r: TimelineRow) => ["high", "critical"].includes(String(body(r).severity ?? "").toLowerCase());
  const alerts = feed.filter(isAlert);
  const alertRows = alerts.length;
  const incidentOf = (r: TimelineRow) => String(ans(r).incident_id ?? "");
  const incidents = new Set(attack.map(incidentOf).filter(Boolean)).size;
  // An incident's first alert is a full triage; its later alerts link to the case already open.
  const attackAlertIncidents = new Set(alerts.filter(r => attack.includes(r) && incidentOf(r)).map(incidentOf));
  const linkedAlerts = alerts.filter(r => attack.includes(r) && incidentOf(r)).length - attackAlertIncidents.size;
  const fullTriage = alertRows - Math.max(0, linkedAlerts);
  const shiftMin = load.shiftMin;
  const active = roster.filter(m => m.status !== "left");
  const caseTeam = active.filter(m => m.role === "t2" || m.role === "t3").length;

  const t1Work = (feed.length * WORK.READ_SEC_PER_LOG) / 60 + fullTriage * WORK.TRIAGE_MIN + Math.max(0, linkedAlerts) * LINKED_ALERT_MIN
    + incidents * ESCALATIONS_PER_INCIDENT * WORK.ESCALATION_MIN;
  const tier1 = tier(Math.max(1, load.triageAnalysts), t1Work, shiftMin);
  const tier2 = tier(caseTeam, incidents * CASE_MIN, shiftMin);
  const worst = Math.max(tier1.pct ?? 0, tier2.pct ?? 0);
  return {
    shiftMin, feedRows: feed.length, logsPerMin: Math.round((feed.length / shiftMin) * 10) / 10,
    attackRows: attack.length, attackShare: feed.length ? Math.round((100 * attack.length) / feed.length) : 0,
    alertRows, incidents, tier1, tier2, level: levelOf(worst),
  };
}
