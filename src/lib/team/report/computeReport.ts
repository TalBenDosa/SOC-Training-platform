import type { RosterMember, Ev } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";

// ── After-action report (Phase 0.5) — derived entirely from the event log ────
const ATTACK_VERDICTS = new Set(["tp", "escalate"]);
export interface UserReport {
  user_id: string; name: string; role: string;
  opened: number; avgDwellS: number | null; dispCount: number; dispCorrect: number; dispAcc: number | null;
  escCount: number; escQuality: number | null; acks: number; contReq: number; contDecided: number;
  roleActions: number; firstActionS: number | null; contribution: number;
  rubric: RubricCell[]; rubricPct: number | null;
}
const ROLE_ACTION_TYPES = new Set(["hunt.logged", "rule.published", "rule.tuned", "intel.published", "handover.noted", "decision.logged", "evidence.pinned", "case.status_set", "case.assigned", "note.added", "containment.executed", "scope.set", "scope.confirmed", "sitrep.sent", "ticket.answered", "escalation.resolved", "elevation.requested", "report.submitted"]);
function escQualityScore(p: Record<string, unknown>): number {
  // T1-4/5: structured report quality — summary + mechanism-bearing observations
  // (word count) + requested_action + severity + at least one IOC. `what`/`why`
  // are back-compat aliases of summary/observations.
  let s = 0;
  if (String(p.summary ?? p.what ?? "").trim()) s += 30;
  const whyWords = String(p.observations ?? p.why ?? "").trim().split(/\s+/).filter(Boolean).length;
  s += whyWords >= 20 ? 25 : whyWords >= 10 ? 15 : whyWords > 0 ? 8 : 0;
  if (String(p.requested_action ?? "").trim()) s += 15;
  if (p.severity || p.impact) s += 15;
  if (Array.isArray(p.iocs) ? p.iocs.length > 0 : false) s += 15;
  return Math.min(100, s);
}
/** T3 hunt quality (deterministic, B9) — rewards substance over count so one deep,
 *  evidence-cited hunt beats three 8-char stubs. Hypothesis that names a real case
 *  entity (25) · finding that cites case entities/indicators (35) · a valid MITRE
 *  technique, bonus if it's one the case actually involves (25) · an explicit
 *  conclusion (15). A REFUTED hypothesis with evidence scores full — disproving is
 *  real hunting. */
function huntQualityScore(p: Record<string, unknown>, caseEntities: Set<string>, caseTechniques: Set<string>): number {
  const hyp = String(p.hypothesis ?? "").trim();
  const finding = String(p.finding ?? "").trim();
  const tech = String(p.technique ?? "").trim().toUpperCase();
  const conclusion = String(p.conclusion ?? "").trim();
  const ents = [...caseEntities].map(e => e.toLowerCase()).filter(Boolean);
  let s = 0;
  const hypWords = hyp.split(/\s+/).filter(Boolean).length;
  const hypRefs = ents.some(en => hyp.toLowerCase().includes(en));
  if (hypWords >= 12 && hypRefs) s += 25; else if (hypWords >= 8) s += 12;
  const findWords = finding.split(/\s+/).filter(Boolean).length;
  const findCited = ents.filter(en => finding.toLowerCase().includes(en)).length;
  if (findWords >= 15 && findCited >= 2) s += 35; else if (findWords >= 10 && findCited >= 1) s += 18; else if (finding) s += 5;
  const techValid = /^T\d{4}(\.\d{3})?$/.test(tech);
  if (techValid && caseTechniques.has(tech)) s += 25; else if (techValid) s += 12;
  if (["confirmed", "refuted", "inconclusive"].includes(conclusion)) s += 15;
  return Math.min(100, s);
}
/** T2 incident-report quality (deterministic, same spirit as escQualityScore):
 *  a substantive summary + findings (word count) + an explicit verdict + a
 *  recommendation. Feeds the T2 "Incident report" rubric cell (was un-measured). */
function reportQualityScore(p: Record<string, unknown>): number {
  // Spread the score so the 0/4/8/12 bands are all reachable ABOVE the submit floor
  // (summary + ≥12-word findings + recommendation). A bare-but-valid report lands
  // in the low band; depth (longer findings, a real recommendation, a cited
  // indicator) climbs it (G2). Substance beyond word-count is rewarded lightly by
  // requiring an indicator-looking token in the findings (G5, partial).
  let s = 0;
  if (String(p.summary ?? "").trim()) s += 15;
  const findings = String(p.findings ?? "").trim();
  const findingWords = findings.split(/\s+/).filter(Boolean).length;
  s += findingWords >= 60 ? 40 : findingWords >= 35 ? 30 : findingWords >= 20 ? 20 : findingWords >= 12 ? 12 : findingWords > 0 ? 5 : 0;
  if (String(p.verdict ?? "").trim()) s += 10;
  const recWords = String(p.recommendation ?? "").trim().split(/\s+/).filter(Boolean).length;
  s += recWords >= 12 ? 20 : recWords > 0 ? 10 : 0;
  // A cited indicator (IP / hash / domain / hostname) in the findings → substance bonus.
  const hasIoc = /(?:\d{1,3}\.){3}\d{1,3}|\b[a-f0-9]{16,}\b|\b[a-z0-9-]+\.[a-z]{2,}\b|\b[A-Z]{2,}[-_][A-Z0-9-]+\b/i.test(findings);
  if (hasIoc) s += 15;
  return Math.min(100, s);
}
// ── G-11: per-role success rubric (0/4/8/12), §3.f–§9.f ──────────────────────
// Each role has 5 criteria. We score only the criteria whose source events exist
// today; criteria still awaiting instrumentation (🔜 in the spec) score `null`
// and are excluded from the % so a role isn't penalised for un-built plumbing.
export interface RubricCell { label: string; score: number | null; note?: string }
const bandHigh = (v: number, a: number, b: number, c: number) => (v >= a ? 12 : v >= b ? 8 : v >= c ? 4 : 0);
const bandLow = (v: number, a: number, b: number, c: number) => (v <= a ? 12 : v <= b ? 8 : v <= c ? 4 : 0);
function median(xs: number[]): number | null { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); const m = Math.floor(s.length / 2); return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; }
const TODO: RubricCell = { label: "", score: null, note: "not yet measured" };
function rubricPercent(cells: RubricCell[]): number | null {
  const scored = cells.filter(c => c.score != null);
  if (!scored.length) return null;
  return Math.round((scored.reduce((s, c) => s + (c.score ?? 0), 0) / (scored.length * 12)) * 100);
}

interface RubricCtx {
  role: string; dispAcc: number | null; escAckRate: number | null; escPrecision: number | null; escRecall: number | null; escQuality: number | null;
  triageMin: number | null; ackLatencyMin: number | null; approvalLatencyMin: number | null;
  huntCount: number; huntTech: number; huntQuality: number | null; noteCount: number;
  rulePublished: number; ruleMatched: number; ruleTechniques: number; ruleDocRate: number | null;
  intelAttrib: number | null; intelNext: number | null;
  handoverComplete: number | null; reopens: number; workloadSkew: number | null;
  contReason: number | null; contTargetOk: number | null;
  scopeSetDims: number; scopeConfirmDims: number; scopeConfirmed: boolean;
  decisionCount: number; decisionRationaleRate: number | null;
  ticketsAnswered: number; sitrepCount: number; reportQuality: number | null;
  huntToConfirmMin: number | null; caseOwnedMin: number | null; mgmtRespondedRate: number | null;
  backupCount: number; loadBalanceRate: number | null; correctionsCount: number;
}
function roleRubric(c: RubricCtx): RubricCell[] {
  switch (c.role) {
    case "t1": return [
      { label: "Disposition accuracy", score: c.dispAcc == null ? null : bandHigh(c.dispAcc, 90, 75, 50) },
      { label: "Escalation precision", score: c.escPrecision == null ? null : bandHigh(c.escPrecision, 80, 60, 40), note: "of what you escalated, how much was a real attack (vs ground truth)" },
      { label: "Attack recall (team)", score: c.escRecall == null ? null : bandHigh(c.escRecall, 80, 50, 25), note: "share of real attacks the T1 team escalated at all" },
      { label: "Card completeness", score: c.escQuality == null ? null : bandHigh(c.escQuality, 90, 70, 40) },
      { label: "Handoff coordination", score: c.escAckRate == null ? null : bandHigh(c.escAckRate, 80, 60, 40), note: "share of your escalations Tier-2 acknowledged" },
      { label: "Time-to-triage", score: c.triageMin == null ? null : bandLow(c.triageMin, 5, 10, 15) },
      { label: "Backup & load-balancing", score: c.backupCount ? bandHigh(c.backupCount, 2, 1, 1) : null, note: "took an alert off an overloaded teammate" },
      { label: "Self-correction", score: c.correctionsCount ? bandHigh(c.correctionsCount, 2, 1, 1) : null, note: "caught and fixed your own verdict — no-fault, scores for you" },
      { label: "Help-desk tickets", score: c.ticketsAnswered === 0 ? null : bandHigh(c.ticketsAnswered, 3, 2, 1) },
    ];
    case "t2": return [
      { label: "Ack latency", score: c.ackLatencyMin == null ? null : bandLow(c.ackLatencyMin, 2, 5, 10) },
      { ...TODO, label: "Timeline accuracy" },
      { label: "Scoping completeness", score: c.scopeSetDims >= 3 ? 12 : c.scopeSetDims >= 2 ? 8 : c.scopeSetDims >= 1 ? 4 : null },
      { label: "Containment recommendation", score: c.contReason == null ? null : bandHigh(c.contReason, 90, 60, 30) },
      { label: "Backup & load-balancing", score: c.backupCount ? bandHigh(c.backupCount, 2, 1, 1) : null, note: "picked up a case while a teammate was overloaded" },
      { label: "Incident report", score: c.reportQuality == null ? null : bandHigh(c.reportQuality, 85, 60, 35) },
    ];
    case "t3": return [
      { label: "Final scope (confirmed)", score: c.scopeConfirmed ? (c.scopeConfirmDims >= 2 ? 8 : 4) : null, note: c.scopeConfirmed ? undefined : "not confirmed" },
      { label: "Hunt quality", score: c.huntQuality == null ? null : bandHigh(c.huntQuality, 75, 55, 30), note: "substance + cited evidence + valid technique + conclusion (not raw count)" },
      { label: "Hypothesis→conclusion time", score: c.huntToConfirmMin == null ? null : bandLow(c.huntToConfirmMin, 5, 12, 20) },
      { label: "Technique attribution", score: c.huntCount ? bandHigh(Math.round((c.huntTech / c.huntCount) * 100), 90, 60, 30) : null },
      // Secondary cell → null when there's nothing to measure (consistent with the
      // other quality cells; "Hunt yield" already carries the did-the-core-job signal) — G4.
      { label: "Guidance to T2", score: c.noteCount ? bandHigh(c.noteCount, 3, 2, 1) : null },
    ];
    case "lead": return [
      { label: "Team organised", score: c.caseOwnedMin == null ? null : bandLow(c.caseOwnedMin, 3, 8, 15) },
      { label: "Time-to-approval", score: c.approvalLatencyMin == null ? null : bandLow(c.approvalLatencyMin, 3, 7, 12) },
      { label: "Decision log", score: c.decisionCount === 0 ? null : c.decisionRationaleRate == null ? 4 : bandHigh(c.decisionRationaleRate, 90, 60, 30) },
      { label: "Cadence + SITREP", score: c.sitrepCount === 0 ? null : bandHigh(c.sitrepCount, 3, 2, 1) },
      { label: "Management pressure", score: c.mgmtRespondedRate == null ? null : bandHigh(c.mgmtRespondedRate, 100, 50, 1) },
    ];
    case "de": return [
      { label: "Verifiable rule", score: c.rulePublished ? bandHigh(c.ruleMatched, 3, 2, 1) : 0 },
      { ...TODO, label: "FP-rate" },
      { ...TODO, label: "Time-to-publish" },
      { label: "ATT&CK coverage-delta", score: c.rulePublished ? bandHigh(c.ruleTechniques, 3, 2, 1) : null },
      { label: "Documentation", score: c.ruleDocRate == null ? null : bandHigh(c.ruleDocRate, 90, 60, 30) },
    ];
    case "ti": return [
      { ...TODO, label: "Actionable-rate" },
      { ...TODO, label: "Time-to-action" },
      { label: "Attribution accuracy", score: c.intelAttrib == null ? null : bandHigh(c.intelAttrib, 90, 60, 30) },
      { label: "Next-step prediction", score: c.intelNext == null ? null : bandHigh(c.intelNext, 90, 60, 30) },
      { ...TODO, label: "IOC precision" },
    ];
    // In the 4-role model the SOC Manager IS the incident coordinator (approves
    // containment, logs decisions, sends SITREPs, organises the team), so the
    // rubric measures that coordinator work — all instrumented today.
    case "mgr": return [
      { label: "Team organised", score: c.caseOwnedMin == null ? null : bandLow(c.caseOwnedMin, 3, 8, 15) },
      { label: "Time-to-approval", score: c.approvalLatencyMin == null ? null : bandLow(c.approvalLatencyMin, 3, 7, 12) },
      { label: "Decision log", score: c.decisionCount === 0 ? null : c.decisionRationaleRate == null ? 4 : bandHigh(c.decisionRationaleRate, 90, 60, 30) },
      { label: "Cadence + SITREP", score: c.sitrepCount === 0 ? null : bandHigh(c.sitrepCount, 3, 2, 1) },
      { label: "Load balancing", score: c.loadBalanceRate == null ? null : bandHigh(c.loadBalanceRate, 100, 50, 1), note: "nudged overloaded analysts so the team rebalanced" },
      { label: "Management pressure", score: c.mgmtRespondedRate == null ? null : bandHigh(c.mgmtRespondedRate, 100, 50, 1) },
    ];
    default: return [];
  }
}

export function computeReport(events: Ev[], roster: RosterMember[]) {
  const started = events.find(e => e.type === "session.started");
  const startedMs = started?.occurred_at ? Date.parse(started.occurred_at)
    : events.length ? Math.min(...events.filter(e => e.occurred_at).map(e => Date.parse(e.occurred_at!))) : Date.now();
  const feed = events.filter(e => e.type === "feed.event");
  const gt = new Map<string, string | undefined>(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), (e.payload as { expected_verdict?: string }).expected_verdict]));
  const attackIds = new Set([...gt.entries()].filter(([, v]) => v && ATTACK_VERDICTS.has(v)).map(([k]) => k));
  // A4: team-wide recall — share of real attacks the T1 team escalated at all. A shared
  // metric (the queue is shared), so it doesn't unfairly punish one T1 for a teammate's catch.
  const teamEscalatedAttackIds = new Set(events.filter(e => e.type === "escalation.requested" && attackIds.has(String((e.payload as { event_id?: string }).event_id))).map(e => String((e.payload as { event_id?: string }).event_id)));
  const teamRecall = attackIds.size ? Math.round((teamEscalatedAttackIds.size / attackIds.size) * 100) : null;
  // B9: the real entities/techniques of THIS incident (from the attack feed events),
  // so hunt quality can be scored on whether a hunt actually cites the case.
  const caseEntities = new Set<string>(); const caseTechniques = new Set<string>();
  for (const fe of feed) {
    const p = fe.payload as { expected_verdict?: string; hostname?: string; user?: { email?: string; full_name?: string }; user_email?: string; network?: { domain?: string; ip?: string }; mitre_technique?: string; src_ip?: string; dest_ip?: string };
    if (!(p.expected_verdict === "tp" || p.expected_verdict === "escalate")) continue;
    if (p.hostname) caseEntities.add(p.hostname);
    const u = p.user?.email || p.user?.full_name || p.user_email; if (u) caseEntities.add(u);
    if (p.network?.domain) caseEntities.add(p.network.domain);
    if (p.network?.ip) caseEntities.add(p.network.ip);
    if (p.src_ip) caseEntities.add(p.src_ip); if (p.dest_ip) caseEntities.add(p.dest_ip);
    if (p.mitre_technique) caseTechniques.add(String(p.mitre_technique).toUpperCase());
  }

  // Shared timing maps for the G-11 rubric (latencies derived from paired events).
  const feedTs = new Map<string, number | null>(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), e.occurred_at ? Date.parse(e.occurred_at) : null]));
  const feedSev = new Map<string, string>(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), String((e.payload as { severity?: string }).severity ?? "")]));
  const escReqTs = new Map<string, number | null>(events.filter(e => e.type === "escalation.requested").map(e => [String((e.payload as { event_id?: string }).event_id), e.occurred_at ? Date.parse(e.occurred_at) : null]));
  const contReqTs = new Map<string, number | null>(events.filter(e => e.type === "containment.requested").map(e => [String((e.payload as { event_id?: string }).event_id), e.occurred_at ? Date.parse(e.occurred_at) : null]));

  const players = roster.filter(r => r.role !== "instructor" && r.role !== "observer");
  // Team-wide action counts (for the Mgr workload-balance criterion).
  const actionCountByUser = players.map(pl => events.filter(e => e.actor_id === pl.user_id && e.type !== "member.ready" && e.type !== "event.opened").length);
  const maxAction = Math.max(1, ...actionCountByUser);
  const avgAction = actionCountByUser.length ? actionCountByUser.reduce((s, n) => s + n, 0) / actionCountByUser.length : 0;

  // ── Work-division / backup metrics (one ordered pass over the log) ────────────
  // Reconstructs each analyst's live load over the shift to detect: (a) T1 take-overs
  // (claiming an alert a teammate held), (b) T2/T3 backup (acking a case while a
  // teammate is already overloaded), and (c) which analysts ever hit overload (for the
  // Manager's load-balancing score). All from EXISTING events — no new telemetry.
  const roleByUser = new Map(players.map(p => [p.user_id, p.role]));
  const takeoverByUser = new Map<string, number>();   // T1 backup
  const backupAckByUser = new Map<string, number>();  // T2/T3 backup
  const everOverloaded = new Set<string>();
  const liveLoad = new Map<string, number>();
  const claimHolder = new Map<string, string>();      // eid -> current claimer
  const caseOwner = new Map<string, string>();        // eid -> first acker (owner)
  const eidOfP = (e: Ev) => String((e.payload as { event_id?: string }).event_id ?? "");
  const bump = (u: string, d: number) => { if (!u) return; const v = Math.max(0, (liveLoad.get(u) ?? 0) + d); liveLoad.set(u, v); if (v >= OVERLOAD_CASES) everOverloaded.add(u); };
  for (const e of events) {
    if (e.type === "alert.claimed") {
      const eid = eidOfP(e); if (!eid) continue; const who = e.actor_id ?? ""; const prev = claimHolder.get(eid);
      if (prev && prev !== who) { takeoverByUser.set(who, (takeoverByUser.get(who) ?? 0) + 1); bump(prev, -1); }
      if (prev !== who) { claimHolder.set(eid, who); bump(who, 1); }
    } else if (e.type === "alert.released" || e.type === "disposition.set") {
      const eid = eidOfP(e); const prev = eid ? claimHolder.get(eid) : undefined;
      if (prev) { bump(prev, -1); claimHolder.delete(eid); }
    } else if (e.type === "escalation.acknowledged") {
      const eid = eidOfP(e); const who = e.actor_id ?? ""; if (!eid || caseOwner.has(eid)) continue;
      let teammateOverloaded = false; // a SAME-ROLE peer already drowning
      for (const [u, l] of liveLoad) if (u !== who && l >= OVERLOAD_CASES && roleByUser.get(u) === roleByUser.get(who)) { teammateOverloaded = true; break; }
      if (teammateOverloaded) backupAckByUser.set(who, (backupAckByUser.get(who) ?? 0) + 1);
      caseOwner.set(eid, who); bump(who, 1);
    } else if (e.type === "escalation.resolved") {
      const eid = eidOfP(e); const owner = eid ? caseOwner.get(eid) : undefined;
      if (owner) { bump(owner, -1); caseOwner.delete(eid); }
    }
  }
  const backupByUser = new Map<string, number>();
  for (const p of players) backupByUser.set(p.user_id, (takeoverByUser.get(p.user_id) ?? 0) + (backupAckByUser.get(p.user_id) ?? 0));
  // Manager load-balancing: of the analysts that ever overloaded, how many did the
  // coordinator nudge? Scores RESPONDING to overload, not raw nudge volume (no spam).
  const nudgeTargets = new Set(events.filter(e => e.type === "coordination.nudge").map(e => String((e.payload as { target?: string }).target)));
  const overloadedTargets = [...everOverloaded];
  const loadBalanceRate = overloadedTargets.length ? Math.round((overloadedTargets.filter(u => nudgeTargets.has(u)).length / overloadedTargets.length) * 100) : null;

  const perUser: UserReport[] = players.map(m => {
    const mine = events.filter(e => e.actor_id === m.user_id);
    // G-01: event.opened now carries { event_id, dwell_ms }. Count DISTINCT feed
    // events opened (the row fires open+close for the same id), and take the max
    // dwell per id (the close transition carries the real expand→collapse time).
    const openedEvents = mine.filter(e => e.type === "event.opened");
    const dwellByEid = new Map<string, number>();
    for (const e of openedEvents) {
      const eid = String((e.payload as { event_id?: string }).event_id ?? "");
      if (!eid) continue;
      const d = Number((e.payload as { dwell_ms?: number }).dwell_ms ?? 0);
      dwellByEid.set(eid, Math.max(dwellByEid.get(eid) ?? 0, Number.isFinite(d) ? d : 0));
    }
    // Distinct ids opened; fall back to raw count for legacy empty-payload rows.
    const opened = dwellByEid.size || openedEvents.length;
    const dwellVals = [...dwellByEid.values()].filter(d => d > 0);
    const avgDwellS = dwellVals.length ? Math.round(dwellVals.reduce((s, d) => s + d, 0) / dwellVals.length / 1000) : null;
    const disp = mine.filter(e => e.type === "disposition.set");
    const isCorrectVerdict = (eid: string, v: string) => attackIds.has(eid) ? v === "true_positive" : (v === "false_positive" || v === "benign");
    // Accuracy is scored over DISTINCT events keeping the LATEST verdict — a
    // wrong→right self-correction must not cost score (Edmondson). corrections =
    // events this analyst got wrong first and then fixed (rewarded, never penalised).
    const latestVerdict = new Map<string, string>();
    const everWrong = new Set<string>(); const wrongThenRight = new Set<string>();
    for (const d of disp) {
      const eid = String((d.payload as { event_id?: string }).event_id);
      const v = String((d.payload as { verdict?: string }).verdict);
      if (!isCorrectVerdict(eid, v)) everWrong.add(eid);
      else if (everWrong.has(eid)) wrongThenRight.add(eid);
      latestVerdict.set(eid, v);
    }
    const distinctDisp = latestVerdict.size;
    const dispCorrect = [...latestVerdict].filter(([eid, v]) => isCorrectVerdict(eid, v)).length;
    const correctionsCount = wrongThenRight.size;
    const esc = mine.filter(e => e.type === "escalation.requested");
    const escQuality = esc.length ? Math.round(esc.reduce((s, e) => s + escQualityScore(e.payload), 0) / esc.length) : null;
    const acks = mine.filter(e => e.type === "escalation.acknowledged").length;
    const contReq = mine.filter(e => e.type === "containment.requested").length;
    const contDecided = mine.filter(e => e.type === "containment.approved" || e.type === "containment.denied").length;
    const roleActions = mine.filter(e => ROLE_ACTION_TYPES.has(e.type)).length;
    const actionTimes = mine.filter(e => e.occurred_at && e.type !== "member.ready").map(e => Date.parse(e.occurred_at!));
    const firstActionS = actionTimes.length ? Math.max(0, Math.round((Math.min(...actionTimes) - startedMs) / 1000)) : null;
    const contribution = Math.min(100, opened * 3 + disp.length * 6 + esc.length * 15 + acks * 10 + contReq * 15 + contDecided * 20 + roleActions * 15);
    const dispAcc = distinctDisp ? Math.round((dispCorrect / distinctDisp) * 100) : null;

    // ── G-11 rubric context — measurable deltas for THIS user ──────────────────
    // A4: Escalation PRECISION vs ground truth — of this analyst's escalations, how many
    // were real attacks (scored at debrief only, so it never leaks live).
    const escPrecision = esc.length ? Math.round((esc.filter(e => attackIds.has(String((e.payload as { event_id?: string }).event_id))).length / esc.length) * 100) : null;
    // Handoff coordination (was mislabelled "precision"): share of this analyst's escalations
    // that a Tier-2 acknowledged. A coordination signal, not a correctness one.
    const escAckedIds = new Set(events.filter(e => e.type === "escalation.acknowledged").map(e => String((e.payload as { event_id?: string }).event_id)));
    const escAckRate = esc.length ? Math.round((esc.filter(e => escAckedIds.has(String((e.payload as { event_id?: string }).event_id))).length / esc.length) * 100) : null;
    // Time-to-triage: Δ(feed appearance → this user's disposition) for high/crit, minutes.
    const triageMin = median(disp.map(d => {
      const eid = String((d.payload as { event_id?: string }).event_id);
      const sev = feedSev.get(eid); if (sev !== "high" && sev !== "critical") return null;
      const ft = feedTs.get(eid); const dt = d.occurred_at ? Date.parse(d.occurred_at) : null;
      return ft != null && dt != null ? (dt - ft) / 60000 : null;
    }).filter((x): x is number => x != null && x >= 0));
    // Ack latency: Δ(escalation.requested → this user's ack), minutes.
    const ackLatencyMin = median(mine.filter(e => e.type === "escalation.acknowledged").map(e => {
      const eid = String((e.payload as { event_id?: string }).event_id);
      const rt = escReqTs.get(eid); const at = e.occurred_at ? Date.parse(e.occurred_at) : null;
      return rt != null && at != null ? (at - rt) / 60000 : null;
    }).filter((x): x is number => x != null && x >= 0));
    // Approval latency: Δ(containment.requested → this user's approve), minutes.
    const approvalLatencyMin = median(mine.filter(e => e.type === "containment.approved").map(e => {
      const eid = String((e.payload as { event_id?: string }).event_id);
      const rt = contReqTs.get(eid); const at = e.occurred_at ? Date.parse(e.occurred_at) : null;
      return rt != null && at != null ? (at - rt) / 60000 : null;
    }).filter((x): x is number => x != null && x >= 0));
    // Hunt / rule / intel / handover payload signals.
    const hunts = mine.filter(e => e.type === "hunt.logged");
    const huntTech = hunts.filter(e => String((e.payload as { technique?: string }).technique ?? "").trim()).length;
    // B9: average hunt QUALITY (substance/citation/technique/conclusion), not raw count.
    const huntQuality = hunts.length ? Math.round(hunts.reduce((s, e) => s + huntQualityScore(e.payload, caseEntities, caseTechniques), 0) / hunts.length) : null;
    const noteCount = mine.filter(e => e.type === "note.added").length;
    const rules = mine.filter(e => e.type === "rule.published");
    const ruleMatched = rules.reduce((s, e) => s + Number((e.payload as { matched?: number }).matched ?? 0), 0);
    const ruleTechniques = new Set(rules.map(e => String((e.payload as { technique?: string }).technique ?? "")).filter(Boolean)).size;
    const ruleDocRate = rules.length ? Math.round((rules.filter(e => String((e.payload as { keyword?: string }).keyword ?? "").trim()).length / rules.length) * 100) : null;
    const intel = mine.filter(e => e.type === "intel.published");
    const intelAttrib = intel.length ? Math.round((intel.filter(e => { const p = e.payload as { actor?: string; technique?: string }; return String(p.actor ?? "").trim() && String(p.technique ?? "").trim(); }).length / intel.length) * 100) : null;
    const intelNext = intel.length ? Math.round((intel.filter(e => String((e.payload as { next_expected?: string }).next_expected ?? "").trim()).length / intel.length) * 100) : null;
    const handovers = mine.filter(e => e.type === "handover.noted");
    const handoverComplete = handovers.length ? Math.round((handovers.filter(e => String((e.payload as { text?: string }).text ?? "").trim().length >= 20).length / handovers.length) * 100) : null;
    const reopens = mine.filter(e => e.type === "case.status_set" && ["new", "triaged", "investigating"].includes(String((e.payload as { status?: string }).status))).length;
    const contReqEvents = mine.filter(e => e.type === "containment.requested");
    const contReason = contReqEvents.length ? Math.round((contReqEvents.filter(e => String((e.payload as { reason?: string }).reason ?? "").trim().length >= 10).length / contReqEvents.length) * 100) : null;
    const myActions = events.filter(e => e.actor_id === m.user_id && e.type !== "member.ready" && e.type !== "event.opened").length;
    const workloadSkew = avgAction > 0 ? Math.round((Math.abs(myActions - avgAction) / maxAction) * 100) : null;
    // G-10 scope scoring: count filled dimensions (hosts/users/techniques) in this user's best scope event.
    const dimsOf = (e: Ev) => { const p = e.payload as { hosts?: string[]; users?: string[]; techniques?: string[] }; return (p.hosts?.length ? 1 : 0) + (p.users?.length ? 1 : 0) + (p.techniques?.length ? 1 : 0); };
    const scopeSets = mine.filter(e => e.type === "scope.set");
    const scopeConfirms = mine.filter(e => e.type === "scope.confirmed");
    const scopeSetDims = scopeSets.length ? Math.max(...scopeSets.map(dimsOf)) : 0;
    const scopeConfirmDims = scopeConfirms.length ? Math.max(...scopeConfirms.map(dimsOf)) : 0;
    // G-15 decision-log scoring: share of this user's decisions that carry a rationale.
    const decisions = mine.filter(e => e.type === "decision.logged");
    const decisionRationaleRate = decisions.length ? Math.round((decisions.filter(e => String((e.payload as { rationale?: string }).rationale ?? "").trim().length >= 5).length / decisions.length) * 100) : null;
    const ticketsAnswered = mine.filter(e => e.type === "ticket.answered").length;
    const sitrepCount = mine.filter(e => e.type === "sitrep.sent").length;
    const reports = mine.filter(e => e.type === "report.submitted");
    const reportQuality = reports.length ? Math.round(reports.reduce((s, e) => s + reportQualityScore(e.payload), 0) / reports.length) : null;
    // T3: hypothesis→conclusion latency — first hunt logged → first scope confirmed.
    const tms = (es: Ev[]) => es.map(e => e.occurred_at ? Date.parse(e.occurred_at) : NaN).filter(n => Number.isFinite(n));
    const firstHuntTs = tms(hunts).length ? Math.min(...tms(hunts)) : null;
    const firstConfirmTs = tms(scopeConfirms).length ? Math.min(...tms(scopeConfirms)) : null;
    const huntToConfirmMin = firstHuntTs != null && firstConfirmTs != null && firstConfirmTs >= firstHuntTs ? (firstConfirmTs - firstHuntTs) / 60000 : null;
    // Mgr "team organised": how soon the case got an explicit owner (case.assigned).
    const caseAssigns = mine.filter(e => e.type === "case.assigned");
    const caseOwnedMin = tms(caseAssigns).length ? Math.max(0, (Math.min(...tms(caseAssigns)) - startedMs) / 60000) : null;
    // Mgr "management pressure": share of mgmt-pressure injects answered by a SITREP.
    // G6: pair each inject to a DISTINCT following SITREP (one-to-one, within 15 min),
    // so one late/unrelated SITREP can't be counted as answering every inject.
    const mgmtInjects = events.filter(e => e.type === "staff.inject" && String((e.payload as { kind?: string }).kind) === "mgmt_pressure");
    const injTs = tms(mgmtInjects).sort((a, b) => a - b);
    const sitrepPool = tms(mine.filter(e => e.type === "sitrep.sent")).sort((a, b) => a - b);
    const MGMT_WINDOW = 15 * 60000;
    let mgmtAnswered = 0;
    for (const it of injTs) {
      const idx = sitrepPool.findIndex(st => st >= it && st - it <= MGMT_WINDOW);
      if (idx !== -1) { mgmtAnswered++; sitrepPool.splice(idx, 1); }
    }
    const mgmtRespondedRate = mgmtInjects.length ? Math.round((mgmtAnswered / mgmtInjects.length) * 100) : null;

    const rubric = roleRubric({
      role: m.role, dispAcc, escAckRate, escPrecision, escRecall: teamRecall, escQuality, triageMin, ackLatencyMin, approvalLatencyMin,
      huntCount: hunts.length, huntTech, huntQuality, noteCount, rulePublished: rules.length, ruleMatched, ruleTechniques, ruleDocRate,
      intelAttrib, intelNext, handoverComplete, reopens, workloadSkew, contReason, contTargetOk: null,
      scopeSetDims, scopeConfirmDims, scopeConfirmed: scopeConfirms.length > 0,
      decisionCount: decisions.length, decisionRationaleRate,
      ticketsAnswered, sitrepCount, reportQuality,
      huntToConfirmMin, caseOwnedMin, mgmtRespondedRate,
      backupCount: backupByUser.get(m.user_id) ?? 0, loadBalanceRate, correctionsCount,
    });
    const rubricPct = rubricPercent(rubric);

    return {
      user_id: m.user_id, name: m.name, role: m.role, opened, avgDwellS,
      dispCount: disp.length, dispCorrect, dispAcc,
      escCount: esc.length, escQuality, acks, contReq, contDecided, roleActions, firstActionS, contribution,
      rubric, rubricPct,
    };
  });

  const escReq = events.filter(e => e.type === "escalation.requested");
  const detectEsc = escReq.filter(e => attackIds.has(String((e.payload as { event_id?: string }).event_id)));
  const detected = detectEsc.length > 0;
  const firstDetect = detectEsc.map(e => e.occurred_at ? Date.parse(e.occurred_at) : Infinity).sort((a, b) => a - b)[0];
  const timeToDetectS = detected && isFinite(firstDetect) ? Math.max(0, Math.round((firstDetect - startedMs) / 1000)) : null;
  // Team disposition accuracy over DISTINCT events keeping the latest verdict (same
  // no-fault rule as per-user: a wrong→right correction must not drag the team score).
  const teamLatestVerdict = new Map<string, string>();
  for (const d of events.filter(e => e.type === "disposition.set")) teamLatestVerdict.set(String((d.payload as { event_id?: string }).event_id), String((d.payload as { verdict?: string }).verdict));
  const dispDistinct = teamLatestVerdict.size;
  const dispAllCorrect = [...teamLatestVerdict].filter(([eid, v]) => attackIds.has(eid) ? v === "true_positive" : (v === "false_positive" || v === "benign")).length;

  // Handoff loop closure: share of escalated cases that a Tier-2 actually acknowledged
  // (a closed loop). Set-based so duplicate acks can't push it over 100%.
  const escEidSet = new Set(escReq.map(e => String((e.payload as { event_id?: string }).event_id)));
  const ackedEidSet = new Set(events.filter(e => e.type === "escalation.acknowledged").map(e => String((e.payload as { event_id?: string }).event_id)));
  const loopClosurePct = escEidSet.size ? Math.round(([...escEidSet].filter(id => ackedEidSet.has(id)).length / escEidSet.size) * 100) : null;

  // ── Team MTTR + handoff latency (P1) ─────────────────────────────────────────
  // MTTR: median Δ(escalation.requested → escalation.resolved) per resolved case.
  const mttrS = median(events.filter(e => e.type === "escalation.resolved").map(e => {
    const eid = String((e.payload as { event_id?: string }).event_id);
    const rt = escReqTs.get(eid); const at = e.occurred_at ? Date.parse(e.occurred_at) : null;
    return rt != null && at != null ? (at - rt) / 1000 : null;
  }).filter((x): x is number => x != null && x >= 0));
  // Handoff latency (team MTTA): median Δ(escalation.requested → first acknowledge).
  const ackFirstTs = new Map<string, number>();
  for (const e of events.filter(e => e.type === "escalation.acknowledged")) { const eid = String((e.payload as { event_id?: string }).event_id); const at = e.occurred_at ? Date.parse(e.occurred_at) : null; if (at != null && !ackFirstTs.has(eid)) ackFirstTs.set(eid, at); }
  const handoffLatS = median([...escReqTs].map(([eid, rt]) => { const at = ackFirstTs.get(eid); return rt != null && at != null ? (at - rt) / 1000 : null; }).filter((x): x is number => x != null && x >= 0));

  // ── Evaluable MSEL injects (P1) ──────────────────────────────────────────────
  // Pair each scored inject to its expected response within 15 min, one-to-one, so
  // one SITREP can't answer every prompt. Announcements are informational (not scored).
  const INJECT_WINDOW = 15 * 60000;
  const atOf = (types: string[]) => events.filter(e => types.includes(e.type)).map(e => e.occurred_at ? Date.parse(e.occurred_at) : NaN).filter(Number.isFinite).sort((a, b) => a - b);
  const sitrepAts = atOf(["sitrep.sent"]); const ticketAts = atOf(["ticket.answered"]);
  // A 'twist' (adaptability) is handled by any re-scoping / re-activation action after it.
  const rescopeAts = atOf(["scope.set", "scope.confirmed", "case.status_set", "escalation.requested"]);
  const usedS = new Set<number>(); const usedT = new Set<number>(); const usedR = new Set<number>();
  const injectResults = events.filter(e => e.type === "staff.inject").map(e => {
    const p = e.payload as { id?: string; kind?: string; text?: string; expected_response?: string; linked_objective?: string };
    const kind = String(p.kind ?? ""); const at = e.occurred_at ? Date.parse(e.occurred_at) : null;
    const base = { kind, text: asStr(p.text), expected: asStr(p.expected_response), objective: asStr(p.linked_objective), decoy: false };
    // Announcements are informational; a false_lead is a DECOY — shown for reflection,
    // not scored on restraint we can't attribute to it (honest scoring).
    if (kind === "announcement") return { ...base, scored: false, handled: true };
    if (kind === "false_lead") return { ...base, scored: false, handled: false, decoy: true };
    const [pool, used] = kind === "ticket" ? [ticketAts, usedT] : kind === "twist" ? [rescopeAts, usedR] : [sitrepAts, usedS];
    let handled = false;
    if (at != null) { const idx = pool.findIndex((t, i) => !used.has(i) && t >= at && t - at <= INJECT_WINDOW); if (idx !== -1) { used.add(idx); handled = true; } }
    return { ...base, scored: true, handled };
  });
  const scoredInjects = injectResults.filter(i => i.scored);
  const injectsHandled = scoredInjects.filter(i => i.handled).length;

  // ── Shared-picture coherence (P2) ────────────────────────────────────────────
  // The team should converge on one picture. A case is CONTESTED when two different
  // analysts gave contradictory verdicts (attack-class vs benign-class) on the same
  // event — a divergent mental model worth reconciling at debrief. Log-derived.
  const vClass = (v: string) => v === "true_positive" ? "attack" : (v === "false_positive" || v === "benign") ? "benign" : "other";
  const feedLabel = new Map(feed.map(e => [String((e.payload as { id?: string }).id ?? e.seq), asStr((e.payload as { description?: string }).description) || asStr((e.payload as { event_type?: string }).event_type) || "event"]));
  const verdictsByEid = new Map<string, Map<string, string>>(); // eid -> actor -> latest class
  for (const d of events.filter(e => e.type === "disposition.set")) {
    const eid = String((d.payload as { event_id?: string }).event_id); const who = d.actor_id ?? "";
    if (!verdictsByEid.has(eid)) verdictsByEid.set(eid, new Map());
    verdictsByEid.get(eid)!.set(who, vClass(String((d.payload as { verdict?: string }).verdict)));
  }
  const contestedList: { eid: string; label: string; calls: { actor: string; cls: string }[] }[] = [];
  for (const [eid, m] of verdictsByEid) {
    const classes = new Set([...m.values()]);
    if (m.size >= 2 && classes.has("attack") && classes.has("benign")) {
      contestedList.push({ eid, label: feedLabel.get(eid) ?? "event", calls: [...m.entries()].map(([actor, cls]) => ({ actor, cls })) });
    }
  }

  const caseStatusEvt = [...events].reverse().find(e => e.type === "case.status_set");
  // G-09 MTTC: Δ(containment.requested → containment.executed) per event, median seconds.
  const execEvents = events.filter(e => e.type === "containment.executed");
  const mttcS = median(execEvents.map(e => {
    const eid = String((e.payload as { event_id?: string }).event_id);
    const rt = contReqTs.get(eid); const xt = e.occurred_at ? Date.parse(e.occurred_at) : null;
    return rt != null && xt != null ? (xt - rt) / 1000 : null;
  }).filter((x): x is number => x != null && x >= 0));
  const team = {
    logs: feed.length, attacks: attackIds.size, detected, timeToDetectS,
    escalations: escReq.length, acknowledged: events.filter(e => e.type === "escalation.acknowledged").length,
    containmentReq: events.filter(e => e.type === "containment.requested").length,
    contained: events.filter(e => e.type === "containment.approved").length,
    executed: execEvents.length, mttcS: mttcS != null ? Math.round(mttcS) : null,
    dispTotal: dispDistinct, dispAcc: dispDistinct ? Math.round((dispAllCorrect / dispDistinct) * 100) : null,
    loopClosure: loopClosurePct,
    mttrS: mttrS != null ? Math.round(mttrS) : null,
    handoffLatS: handoffLatS != null ? Math.round(handoffLatS) : null,
    injects: injectResults, injectsScored: scoredInjects.length, injectsHandled,
    contested: contestedList.length, contestedList: contestedList.slice(0, 6),
    caseStatus: (caseStatusEvt?.payload as { status?: string })?.status ?? "—",
    evidencePinned: events.filter(e => e.type === "evidence.pinned").length,
  };
  return { team, perUser };
}

// ── G-08: Lead/Mgr Situation Board — summaries only, never raw (§3.7) ─────────
// Work-division thresholds: an analyst is "overloaded" at ≥3 concurrent open cases
// (matches the existing amber load styling), and NIMS/ICS puts effective span of
// control at 3–7 direct reports — beyond 7 a single coordinator loses oversight.
export const OVERLOAD_CASES = 3;
