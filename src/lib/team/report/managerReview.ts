/**
 * Command Review: the SOC Manager's end-of-shift report (PLAN-soc-manager §10, §10א).
 *
 * The manager is judged differently from the analysts:
 * - on the QUALITY OF DECISIONS made with the information visible at the time (decision cards
 *   were ranked when they fired), not on hindsight;
 * - in three weighted pillars (team & incident 35 · stakeholders 25 · reporting 25) plus a 15%
 *   share of the team's outcome, because a manager owns the incident, not only his own clicks;
 * - with confidence calibration (an overconfident weak call scores lowest);
 * - and with CRITICAL ERRORS that cap the score at 69, whatever else went well.
 *
 * Isomorphic and pure: computeReport() calls it with the revealed event log (answer keys of the
 * decision cards merged into their staff.inject payloads as `key`).
 */
import type { Ev, RosterMember } from "@/lib/team/types";
import { asStr } from "@/lib/team/format";
import { cardScore, indicatorsAfter, type CardAnswerKey } from "@/lib/team/manager/director";
import { CRITICAL_NAME } from "@/lib/team/manager/state";
import type { Delta, Indicators, Rank } from "@/lib/team/manager/cards";
import { checkReply, NO_DATA_CLAIM as REPLY_NO_DATA, type QuestionKey } from "@/lib/team/manager/questions";

export const MANAGER_SCORE_CAP = 69;
export const PILLAR_WEIGHTS = { team: 0.35, stakeholders: 0.25, reporting: 0.25 } as const;
export const OUTCOME_WEIGHT = 0.15;

export interface CommandCell { label: string; score: number | null; note?: string }
export type PillarKey = "team" | "stakeholders" | "reporting" | "outcome";
export interface CommandPillar { key: PillarKey; label: string; weight: number; cells: CommandCell[]; score: number | null; measured: number }
export type Confidence = "low" | "medium" | "high";
export interface DecisionOption { id: string; label: string; rank: Rank | null; note: string; delta: Delta }
export interface DecisionRow {
  injectId: string; card: string; audience: string; pillar: string;
  from: { name: string; role: string }; channel: string; text: string; objective: string;
  firedS: number | null; deadlineS: number; decidedInS: number | null;
  state: "answered" | "late" | "expired";
  option: string | null; optionLabel: string | null; rank: Rank | null; confidence: Confidence | null;
  rationale: string | null; score: number; best: string; bestLabel: string;
  options: DecisionOption[]; delta: Delta; critical: string | null; indicatorsAfter: Indicators;
}
export interface QuestionRow {
  injectId: string; qid: string; from: { name: string; role: string }; text: string;
  askedS: number | null; deadlineS: number; repliedInS: number | null; state: "answered" | "late" | "expired";
  reply: string | null; score: number; checks: { id: string; label: string; ok: boolean }[]; model: string;
}
export interface ReportRow { atS: number | null; audience: string; status: string; dataImpact: string; title: string; completeness: number; nextUpdateMin: number; promiseKept: boolean | null }
export interface TimelineMark { t: number; lane: "attacker" | "manager" | "pressure"; label: string; tone: "good" | "bad" | "neutral" }
export interface CriticalError { label: string; detail: string; atS: number | null }
export interface ProfileTrait { style: string; evidence: string }
export interface ManagerReview {
  managerId: string; managerName: string;
  score: number | null; uncappedScore: number | null;
  level: "command_ready" | "proficient" | "developing" | "needs_coaching" | null; levelLabel: string;
  criticalErrors: CriticalError[];
  pillars: CommandPillar[];
  decisions: DecisionRow[];
  questions: QuestionRow[];
  reports: ReportRow[];
  calibration: { grid: Record<Rank, Record<Confidence, number>>; highTotal: number; highGreat: number; calibrated: boolean | null };
  indicators: Indicators;
  indicatorTrail: { t: number | null; card: string; ind: Indicators }[];
  timeline: TimelineMark[]; endS: number; gaps: string[];
  declared: { severity: number; atS: number | null } | null;
  finalSeverity: number | null; truthSeverity: 1 | 2 | 3 | null;
  profile: ProfileTrait[]; keep: string[]; improve: string[]; debrief: string[];
  /** true = the team's view (no grades). */
  redacted?: boolean;
}

export interface ReviewTruth { isAttack: boolean; incident: string | null; host: string; technique: string; tactic: string; label: string; severity: string; ts: number | null }
export interface ReviewCtx {
  events: Ev[]; roster: RosterMember[]; startedMs: number; endMs: number;
  runMs: (a: number, b: number) => number; relS: (t: number | null) => number | null;
  truthOf: (eid: string) => ReviewTruth | undefined;
  /** Real incidents (≥1 malicious log): id → max severity. */
  incidents: { id: string; maxSeverity: string }[];
  avgHandlingScore: number | null; handoffLatS: number | null;
  /** hostKey → first isolation time (ms) by anyone. */
  isolatedAt: Map<string, number>;
  hostKey: (h: string) => string;
  loadBalanceRate: number | null;
}

// ── helpers ──────────────────────────────────────────────────────────────────
const tsOf = (e: Ev): number | null => (e.occurred_at ? Date.parse(e.occurred_at) : null);
const eidOf = (e: Ev) => { const v = (e.payload as { event_id?: unknown }).event_id; return v == null ? "" : String(v); };
const words = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;
const bandHigh = (v: number, a: number, b: number, c: number) => (v >= a ? 12 : v >= b ? 8 : v >= c ? 4 : 0);
const bandLow = (v: number, a: number, b: number, c: number) => (v <= a ? 12 : v <= b ? 8 : v <= c ? 4 : 0);
const pct = (n: number, d: number) => (d ? Math.round((n / d) * 100) : null);
const median = (xs: number[]) => { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); const m = Math.floor(s.length / 2); return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; };
const mins = (ms: number) => Math.round(ms / 60000);
const fmtMin = (s: number | null) => (s == null ? "?" : `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`);

/** Exfiltration / data staging in the attack telemetry. */
const EXFIL = /exfil|rclone|megasync|mega\.nz|upload|cloud storage|staged archive|data transfer|T1041|T1048|T1567|T1537|TA0010/i;
/** Destructive impact (ransomware, inhibit recovery). */
const IMPACT = /ransom|encrypt|shadow cop|vssadmin|T1486|T1490|TA0040|\bimpact\b/i;
/** A SITREP that rules out data loss. */
const NO_DATA_CLAIM = /\bno (personal |customer |patient )?data (was |has been )?(lost|leaked|exfiltrated|stolen|affected|exposed|compromised)|\bdata (is |was )?(safe|not affected|unaffected)|\bno exfil/i;
/** A SITREP that declares the incident contained. */
const CONTAINED_CLAIM = /\b(fully |now )?contained\b/i;
const NOT_CONTAINED = /\bnot (yet )?(fully )?contained|partially contained|contain(ment)? (in progress|pending)/i;
const STATUS_CARDS = new Set(["ciso_status", "ciso_bypass", "board_paragraph"]);
const SEV_TRUTH_LABEL: Record<number, string> = { 1: "Sev-1 (critical)", 2: "Sev-2 (high)", 3: "Sev-3 (medium)", 4: "Sev-4 (low)" };

const KEEP_LINE: Record<string, string> = {
  "Incident declared on time": "You declared the incident quickly after the first real escalation.",
  "Severity accuracy": "Your severity matched what the incident really was.",
  "Containment calls": "Your containment approvals matched where the attack really was.",
  "Time to decide containment": "You decided containment requests without leaving the analysts waiting.",
  "Internal decision cards": "Your calls on the team's own dilemmas were sound.",
  "Team organised": "You gave the cases owners early.",
  "Load balancing": "You noticed overloaded analysts and rebalanced the work.",
  "External decision cards": "You handled the CISO, Legal and the business well.",
  "Answered before the deadline": "You answered every request before its deadline.",
  "SITREP cadence": "Management never went long without an update.",
  "SITREP completeness": "Your SITREPs answered all four questions with substance.",
  "Status requests answered": "Status requests got a SITREP within minutes.",
  "Decision log": "Your decisions carry a written reason.",
  "Accuracy to management": "Nothing you told management contradicted the facts.",
  "Stakeholder questions answered in time": "Stakeholders got answers before their deadlines.",
  "Quality of stakeholder answers": "Your answers to stakeholders were clear and honest about what was not known yet.",
  "Stakeholder report": "Your incident report reached stakeholders early and complete.",
  "Promised updates kept": "You kept the update times you promised.",
};
const IMPROVE_LINE: Record<string, string> = {
  "Incident declared on time": "Declare as soon as the first real escalation lands: a declaration can be downgraded later, a late one cannot be undone.",
  "Severity accuracy": "Set severity from impact (data, critical assets, spread). When unsure, go one level higher, not lower.",
  "Containment calls": "Check where the attack activity really is before approving or denying containment.",
  "Time to decide containment": "Decide containment requests within two minutes; the attacker keeps moving while the request waits.",
  "Internal decision cards": "On team dilemmas, get the facts from both sides, then decide and say why.",
  "Team organised": "Give every escalated case an owner in the first minutes.",
  "Load balancing": "Watch the load per analyst and move work before someone drowns.",
  "External decision cards": "With stakeholders: say what is confirmed, what is not, and when the next update comes.",
  "Answered before the deadline": "Answer before the deadline, even with partial information; silence is also a decision.",
  "SITREP cadence": "Send a SITREP at a fixed rhythm (about every 10 minutes) once the incident is live.",
  "SITREP completeness": "A SITREP answers four things: what is happening, what was done, the status, and what is next.",
  "Status requests answered": "When the CISO or executives ask for status, a short SITREP within five minutes beats a perfect one later.",
  "Decision log": "Write down the reason for every decision; the review and the regulator will ask.",
  "Accuracy to management": "Say 'no evidence so far' instead of 'not affected': never state what has not been verified.",
  "Stakeholder questions answered in time": "Answer every stakeholder before the deadline, even if the answer is 'not known yet, next update at 14:30'.",
  "Quality of stakeholder answers": "Answer the question asked: status, what is confirmed and what is not, and a time for the next update.",
  "Stakeholder report": "Send the first stakeholder report within 10 minutes of declaring, then update it as the picture changes.",
  "Promised updates kept": "When you promise the next update in 30 minutes, send it in 30 minutes.",
};

export function computeManagerReview(ctx: ReviewCtx): ManagerReview | null {
  const { events, runMs, relS } = ctx;
  const seats = ctx.roster.filter(r => r.role === "mgr" || r.role === "lead");
  if (!seats.length) return null;
  const mgrIds = new Set(seats.map(s => s.user_id));
  const lead = seats.find(s => s.status !== "left") ?? seats[0];
  const isMgr = (e: Ev) => !!e.actor_id && mgrIds.has(e.actor_id);
  const mine = events.filter(isMgr);
  const endS = relS(ctx.endMs) ?? 0;

  // ── Ground truth: severity of what really happened ─────────────────────────
  const feed = events.filter(e => e.type === "feed.event");
  const attackLogs = feed.map(e => ({ e, t: ctx.truthOf(String((e.payload as { id?: unknown }).id ?? e.seq)) })).filter(x => x.t?.isAttack) as { e: Ev; t: ReviewTruth }[];
  const blob = (t: ReviewTruth) => `${t.label} ${t.technique} ${t.tactic}`;
  const exfilTs = attackLogs.filter(x => EXFIL.test(blob(x.t))).map(x => x.t.ts).filter((x): x is number => x != null).sort((a, b) => a - b)[0] ?? null;
  const impactTs = attackLogs.filter(x => IMPACT.test(blob(x.t))).map(x => x.t.ts).filter((x): x is number => x != null).sort((a, b) => a - b)[0] ?? null;
  const criticalHit = attackLogs.some(x => x.t.host && CRITICAL_NAME.test(x.t.host));
  const sevs = ctx.incidents.map(i => i.maxSeverity.toLowerCase());
  const truthSeverity: 1 | 2 | 3 | null = !ctx.incidents.length ? null
    : (exfilTs != null || impactTs != null || criticalHit || sevs.includes("critical")) ? 1
      : sevs.includes("high") ? 2 : 3;

  // ── Declarations ────────────────────────────────────────────────────────────
  const sevEvents = mine.filter(e => e.type === "incident.declared" || e.type === "incident.severity_changed");
  const declEv = mine.find(e => e.type === "incident.declared");
  const declTs = declEv ? tsOf(declEv) : null;
  const declared = declEv ? { severity: Number((declEv.payload as { severity?: unknown }).severity), atS: relS(declTs) } : null;
  const finalSeverity = sevEvents.length ? Number((sevEvents[sevEvents.length - 1].payload as { severity?: unknown }).severity) : null;
  const isRealEid = (eid: string) => { const t = ctx.truthOf(eid); return !!t && (t.isAttack || !!t.incident); };
  const firstAttackEscTs = events.filter(e => e.type === "escalation.requested" && isRealEid(eidOf(e)))
    .map(tsOf).filter((x): x is number => x != null).sort((a, b) => a - b)[0] ?? null;

  // ── Decision cards ──────────────────────────────────────────────────────────
  const answers = new Map(events.filter(e => e.type === "decision.answered" && isMgr(e))
    .map(e => [String((e.payload as { inject_id?: unknown }).inject_id), e]));
  const cardEvents = events.filter(e => e.type === "staff.inject" && asStr((e.payload as { kind?: unknown }).kind) === "decision");
  const decided: { answer: CardAnswerKey; option: string | null }[] = [];
  const decisions: DecisionRow[] = [];
  const indicatorTrail: ManagerReview["indicatorTrail"] = [];
  for (const ce of cardEvents) {
    const p = ce.payload as { inject_id?: string; card?: string; audience?: string; pillar?: string; from?: { name?: string; role?: string }; channel?: string; text?: string; options?: { id: string; label: string }[]; deadline_s?: number; key?: CardAnswerKey };
    const key = p.key;
    if (!key || !p.inject_id) continue;                                           // not revealed: cannot grade
    const firedTs = tsOf(ce);
    const deadlineS = Number(p.deadline_s) || 240;
    const a = answers.get(p.inject_id);
    const aTs = a ? tsOf(a) : null;
    const decidedInS = a && firedTs != null && aTs != null ? Math.max(0, Math.round(runMs(firedTs, aTs) / 1000)) : null;
    const ap = (a?.payload ?? {}) as { option?: unknown; confidence?: unknown; rationale?: unknown };
    const option = a ? asStr(ap.option) || null : null;
    const confRaw = asStr(ap.confidence);
    const confidence: Confidence | null = a ? (confRaw === "low" || confRaw === "high" ? confRaw : "medium") : null;
    const rank = option ? key.ranks[option] ?? null : null;
    const state: DecisionRow["state"] = !a ? "expired" : decidedInS != null && decidedInS > deadlineS ? "late" : "answered";
    decided.push({ answer: key, option });
    const ind = indicatorsAfter(decided);
    const decidedAtS = a ? relS(aTs) : firedTs != null ? relS(firedTs + deadlineS * 1000) : null;
    indicatorTrail.push({ t: decidedAtS, card: key.card, ind });
    const labelOf = (id: string) => p.options?.find(o => o.id === id)?.label ?? id;
    decisions.push({
      injectId: p.inject_id, card: key.card, audience: asStr(p.audience), pillar: asStr(p.pillar),
      from: { name: asStr(p.from?.name), role: asStr(p.from?.role) }, channel: asStr(p.channel), text: asStr(p.text), objective: asStr(key.objective),
      firedS: relS(firedTs), deadlineS, decidedInS, state,
      option, optionLabel: option ? labelOf(option) : null, rank, confidence,
      rationale: a ? asStr(ap.rationale) || null : null,
      score: cardScore(rank ?? undefined, confidence ?? undefined),
      best: key.best, bestLabel: labelOf(key.best),
      options: (p.options ?? []).map(o => ({ id: o.id, label: o.label, rank: key.ranks[o.id] ?? null, note: key.notes[o.id] ?? "", delta: key.deltas[o.id] ?? {} })),
      delta: option ? key.deltas[option] ?? {} : key.timeout_delta,
      critical: option ? key.critical?.[option] ?? null : null,
      indicatorsAfter: ind,
    });
  }
  const indicators = indicatorsAfter(decided);
  const avgCards = (rows: DecisionRow[]) => (rows.length ? Math.round(rows.reduce((s, r) => s + r.score, 0) / rows.length) : null);
  const internal = decisions.filter(d => d.audience === "internal"), external = decisions.filter(d => d.audience === "external");

  // ── Stakeholder questions (asked by the server from the live session) ────────
  const repliesBy = new Map(events.filter(e => e.type === "stakeholder.replied" && isMgr(e)).map(e => [String((e.payload as { inject_id?: unknown }).inject_id), e]));
  const questions: QuestionRow[] = [];
  for (const qe of events.filter(e => e.type === "stakeholder.asked")) {
    const p = qe.payload as { inject_id?: string; qid?: string; from?: { name?: string; role?: string }; text?: string; deadline_s?: number; key?: QuestionKey };
    if (!p.inject_id || !p.key) continue;
    const askedTs = tsOf(qe); const deadlineS = Number(p.deadline_s) || 240;
    const r = repliesBy.get(p.inject_id); const rTs = r ? tsOf(r) : null;
    const repliedInS = r && askedTs != null && rTs != null ? Math.max(0, Math.round(runMs(askedTs, rTs) / 1000)) : null;
    const reply = r ? asStr((r.payload as { text?: unknown }).text) : null;
    const graded = reply ? checkReply(reply, p.key) : { checks: [], score: 0 };
    questions.push({
      injectId: p.inject_id, qid: asStr(p.qid), from: { name: asStr(p.from?.name), role: asStr(p.from?.role) }, text: asStr(p.text),
      askedS: relS(askedTs), deadlineS, repliedInS, state: !r ? "expired" : repliedInS != null && repliedInS > deadlineS ? "late" : "answered",
      reply, score: graded.score, checks: graded.checks, model: asStr(p.key.model),
    });
  }

  // ── Incident reports to stakeholders ────────────────────────────────────────
  const reportEvents = mine.filter(e => e.type === "stakeholder.report_sent");
  const updates = [...mine.filter(e => e.type === "sitrep.sent" || e.type === "stakeholder.report_sent").map(tsOf)].filter((x): x is number => x != null).sort((a, b) => a - b);
  const reports: ReportRow[] = reportEvents.map(e => {
    const p = e.payload as Record<string, unknown>;
    const t = tsOf(e);
    const fields = [words(asStr(p.what_happened)) >= 8, words(asStr(p.business_impact)) >= 4, words(asStr(p.actions_taken)) >= 3, !!asStr(p.unknown).trim(), !!asStr(p.known).trim(), Array.isArray(p.affected) && p.affected.length > 0];
    const nextMin = Number(p.next_update_min) || 0;
    const due = t != null && nextMin ? t + nextMin * 60000 : null;
    const kept = due == null ? null : due > ctx.endMs ? null : updates.some(u => t != null && u > t && u <= due + 60000);
    return { atS: relS(t), audience: asStr(p.audience), status: asStr(p.status), dataImpact: asStr(p.data_impact), title: asStr(p.title), completeness: Math.round((100 * fields.filter(Boolean).length) / fields.length), nextUpdateMin: nextMin, promiseKept: kept };
  });

  // ── Pillar A: team & incident ───────────────────────────────────────────────
  const declCell: CommandCell = firstAttackEscTs == null ? { label: "Incident declared on time", score: null, note: "no real attack was escalated, nothing to declare" }
    : declTs == null ? { label: "Incident declared on time", score: 0, note: "the incident was never declared" }
      : (() => { const m = Math.max(0, runMs(firstAttackEscTs, declTs) / 60000); return { label: "Incident declared on time", score: bandLow(m, 3, 6, 10), note: `${Math.round(m * 10) / 10} min after the first real escalation (12 = within 3 min)` }; })();
  const sevCell: CommandCell = (() => {
    const label = "Severity accuracy";
    if (truthSeverity == null || finalSeverity == null) return { label, score: null };
    const diff = finalSeverity - truthSeverity;                                       // >0 = declared less severe than reality
    const score = diff === 0 ? 12 : diff === -1 ? 8 : diff === 1 ? 4 : diff >= 2 ? 0 : 4;
    return { label, score, note: `you set Sev-${finalSeverity}; the incident was ${SEV_TRUTH_LABEL[truthSeverity]}` };
  })();
  // Containment calls, judged against where the attack really was.
  const contDecisions = mine.filter(e => e.type === "containment.approved" || e.type === "containment.denied");
  const contJudged = contDecisions.filter(e => ctx.truthOf(eidOf(e)));
  const contRight = contJudged.filter(e => (e.type === "containment.approved") === isRealEid(eidOf(e))).length;
  const contPct = pct(contRight, contJudged.length);
  const contCell: CommandCell = { label: "Containment calls", score: contPct == null ? null : bandHigh(contPct, 90, 70, 40), note: contPct == null ? undefined : `${contRight} of ${contJudged.length} approvals/denials matched where the attack really was` };
  const reqs = events.filter(e => e.type === "containment.requested");
  const latencies = contDecisions.map(d => {
    const dt = tsOf(d); if (dt == null) return null;
    const req = reqs.filter(r => eidOf(r) === eidOf(d) && (tsOf(r) ?? Infinity) <= dt).pop();
    const rt = req ? tsOf(req) : null;
    return rt != null ? runMs(rt, dt) / 60000 : null;
  }).filter((x): x is number => x != null);
  const latMed = median(latencies);
  const latCell: CommandCell = { label: "Time to decide containment", score: latMed == null ? null : bandLow(latMed, 2, 4, 7), note: latMed == null ? undefined : `median ${Math.round(latMed * 10) / 10} min from request to decision` };
  const assigns = mine.filter(e => e.type === "case.assigned").map(tsOf).filter((x): x is number => x != null);
  const ownedMin = assigns.length ? Math.max(0, runMs(ctx.startedMs, Math.min(...assigns)) / 60000) : null;
  const pillarTeam: CommandCell[] = [
    declCell, sevCell, contCell, latCell,
    { label: "Internal decision cards", score: avgCards(internal), note: internal.length ? `${internal.length} card${internal.length > 1 ? "s" : ""} from your own team, confidence-calibrated` : undefined },
    { label: "Team organised", score: ownedMin == null ? null : bandLow(ownedMin, 3, 8, 15), note: ownedMin == null ? undefined : `first case owner set at ${Math.round(ownedMin)} min` },
    { label: "Load balancing", score: ctx.loadBalanceRate == null ? null : bandHigh(ctx.loadBalanceRate, 100, 50, 1), note: ctx.loadBalanceRate == null ? undefined : `${ctx.loadBalanceRate}% of overloaded analysts got help` },
  ];

  // ── Pillar B: stakeholders ──────────────────────────────────────────────────
  const missed = decisions.filter(d => d.state !== "answered").length;
  const pillarStake: CommandCell[] = [
    { label: "External decision cards", score: avgCards(external), note: external.length ? `${external.length} request${external.length > 1 ? "s" : ""} from CISO / Legal / business, confidence-calibrated` : undefined },
    { label: "Answered before the deadline", score: decisions.length ? (missed === 0 ? 12 : missed === 1 ? 8 : missed === 2 ? 4 : 0) : null, note: decisions.length ? `${decisions.length - missed} of ${decisions.length} decided in time` : undefined },
    (() => {
      const onTime = questions.filter(q => q.state === "answered").length;
      const p = pct(onTime, questions.length);
      return { label: "Stakeholder questions answered in time", score: p == null ? null : bandHigh(p, 100, 75, 50), note: p == null ? undefined : `${onTime} of ${questions.length} answered before the deadline` };
    })(),
    (() => {
      const ans = questions.filter(q => q.reply);
      const avg = ans.length ? Math.round(ans.reduce((s, q) => s + q.score, 0) / ans.length) : null;
      return { label: "Quality of stakeholder answers", score: avg, note: avg == null ? undefined : "status, honest unknowns, a time for the next update, no claims beyond the facts" };
    })(),
  ];

  // ── Pillar C: reporting to management ───────────────────────────────────────
  const sitreps = mine.filter(e => e.type === "sitrep.sent");
  const sitTs = sitreps.map(tsOf).filter((x): x is number => x != null).sort((a, b) => a - b);
  const gaps: string[] = [];
  let maxGapMs: number | null = null;
  if (firstAttackEscTs != null) {
    const points = [firstAttackEscTs, ...sitTs.filter(t => t >= firstAttackEscTs), ctx.endMs];
    for (let i = 1; i < points.length; i++) {
      const g = runMs(points[i - 1], points[i]);
      if (maxGapMs == null || g > maxGapMs) maxGapMs = g;
      if (g > 10 * 60000) gaps.push(i === 1 ? `${mins(g)} min from the first escalation to the first SITREP` : i === points.length - 1 ? `${mins(g)} min without a SITREP at the end of the shift` : `${mins(g)} min between two SITREPs`);
    }
  }
  if (declTs != null && firstAttackEscTs != null && runMs(firstAttackEscTs, declTs) > 6 * 60000) gaps.unshift(`declared ${mins(runMs(firstAttackEscTs, declTs))} min after the first real escalation`);
  const cadenceCell: CommandCell = firstAttackEscTs == null ? { label: "SITREP cadence", score: null }
    : !sitTs.length ? { label: "SITREP cadence", score: 0, note: "no SITREP during a live incident" }
      : { label: "SITREP cadence", score: bandLow((maxGapMs ?? 0) / 60000, 10, 15, 25), note: `longest stretch without an update: ${mins(maxGapMs ?? 0)} min (12 = 10 min or less)` };
  const completeness = sitreps.map(s => {
    const p = s.payload as Record<string, unknown>;
    const f = ["situation", "actions", "status", "next"].filter(k => words(asStr(p[k])) >= 3).length;
    return (f + (words(asStr(p.situation)) >= 8 ? 1 : 0)) / 5;
  });
  const compPct = completeness.length ? Math.round((100 * completeness.reduce((a, b) => a + b, 0)) / completeness.length) : null;
  const statusCards = cardEvents.filter(c => STATUS_CARDS.has(asStr((c.payload as { card?: unknown }).card)));
  const statusAnswered = statusCards.filter(c => { const t = tsOf(c); return t != null && sitTs.some(st => st >= t && runMs(t, st) <= 5 * 60000); }).length;
  const statusPct = pct(statusAnswered, statusCards.length);
  const logged = mine.filter(e => e.type === "decision.logged");
  const reasoned = [...logged.map(e => asStr((e.payload as { rationale?: unknown }).rationale)), ...decisions.filter(d => d.state !== "expired").map(d => d.rationale ?? "")];
  // The log needs some substance to judge: a decision logged, or at least two decided cards.
  const reasonPct = reasoned.length && (logged.length > 0 || reasoned.length >= 2) ? pct(reasoned.filter(r => words(r) >= 3).length, reasoned.length) : null;
  // Accuracy: a SITREP that rules out data loss after exfiltration showed up, or calls it contained while a compromised host is still online.
  const criticalErrors: CriticalError[] = [];
  let falseClaims = 0, softClaims = 0;
  for (const s of sitreps) {
    const st = tsOf(s); if (st == null) continue;
    const text = ["situation", "actions", "status", "next"].map(k => asStr((s.payload as Record<string, unknown>)[k])).join(" ");
    if (exfilTs != null && exfilTs <= st && NO_DATA_CLAIM.test(text)) {
      falseClaims++;
      criticalErrors.push({ label: "False statement to management", detail: `A SITREP at ${fmtMin(relS(st))} ruled out data loss, but data exfiltration was already in the feed at ${fmtMin(relS(exfilTs))}. The right line: "suspected, under investigation".`, atS: relS(st) });
    } else if (CONTAINED_CLAIM.test(text) && !NOT_CONTAINED.test(text)) {
      const openHosts = new Set(attackLogs.filter(x => x.t.ts != null && x.t.ts <= st && x.t.host).map(x => ctx.hostKey(x.t.host)).filter(k => { const iso = ctx.isolatedAt.get(k); return iso == null || iso > st; }));
      if (openHosts.size) softClaims++;
    }
  }
  for (const q of questions) {
    if (!q.reply || exfilTs == null || q.askedS == null) continue;
    const at = ctx.startedMs + q.askedS * 1000;
    if (exfilTs <= at + (q.repliedInS ?? 0) * 1000 && REPLY_NO_DATA.test(q.reply)) {
      falseClaims++;
      criticalErrors.push({ label: "False statement to a stakeholder", detail: `You told ${q.from.name || "a stakeholder"} that data was not affected, but data exfiltration was already in the feed at ${fmtMin(relS(exfilTs))}.`, atS: q.askedS + (q.repliedInS ?? 0) });
    }
  }
  for (const e of reportEvents) {
    const st = tsOf(e); if (st == null) continue;
    const p = e.payload as Record<string, unknown>;
    const text = ["what_happened", "business_impact", "known", "actions_taken"].map(k => asStr(p[k])).join(" ");
    if (exfilTs != null && exfilTs <= st && (NO_DATA_CLAIM.test(text) || REPLY_NO_DATA.test(text))) {
      falseClaims++;
      criticalErrors.push({ label: "False statement in the stakeholder report", detail: `The report at ${fmtMin(relS(st))} ruled out data loss after exfiltration reached the feed at ${fmtMin(relS(exfilTs))}.`, atS: relS(st) });
    } else if (asStr(p.status) === "contained") {
      const openHosts = attackLogs.filter(x => x.t.ts != null && x.t.ts <= st && x.t.host).map(x => ctx.hostKey(x.t.host)).filter(k => { const iso = ctx.isolatedAt.get(k); return iso == null || iso > st; });
      if (openHosts.length) softClaims++;
    }
  }
  const accCell: CommandCell = !sitreps.length && !reportEvents.length && !questions.some(q => q.reply) ? { label: "Accuracy to management", score: null }
    : { label: "Accuracy to management", score: falseClaims ? 0 : softClaims ? 4 : 12, note: falseClaims ? "an update ruled out data loss that had already happened" : softClaims ? "an update called it contained while a compromised host was still online" : "nothing reported contradicted the facts" };
  const pillarReport: CommandCell[] = [
    cadenceCell,
    { label: "SITREP completeness", score: compPct == null ? null : bandHigh(compPct, 90, 70, 40), note: compPct == null ? undefined : `${sitreps.length} SITREP${sitreps.length > 1 ? "s" : ""}, ${compPct}% complete` },
    { label: "Status requests answered", score: statusPct == null ? null : bandHigh(statusPct, 100, 50, 1), note: statusPct == null ? undefined : `${statusAnswered} of ${statusCards.length} status requests got a SITREP within 5 min` },
    { label: "Decision log", score: reasonPct == null ? null : bandHigh(reasonPct, 90, 60, 30), note: reasonPct == null ? undefined : `${reasonPct}% of your decisions carry a reason` },
    accCell,
    (() => {
      if (declTs == null) return { label: "Stakeholder report", score: null };
      const first = reportEvents.map(tsOf).filter((x): x is number => x != null)[0];
      if (first == null) return { label: "Stakeholder report", score: 0, note: "no incident report was sent to stakeholders" };
      const m = Math.max(0, runMs(declTs, first) / 60000);
      const comp = reports[0]?.completeness ?? 0;
      return { label: "Stakeholder report", score: Math.round((bandLow(m, 10, 15, 25) + bandHigh(comp, 90, 70, 40)) / 2), note: `first report ${Math.round(m)} min after the declaration, ${comp}% complete` };
    })(),
    (() => {
      const judged = reports.filter(r => r.promiseKept != null);
      const kept = judged.filter(r => r.promiseKept).length;
      const p = pct(kept, judged.length);
      return { label: "Promised updates kept", score: p == null ? null : bandHigh(p, 100, 66, 33), note: p == null ? undefined : `${kept} of ${judged.length} next-update times kept` };
    })(),
  ];

  // ── Team outcome (15%) ──────────────────────────────────────────────────────
  const endInd = (indicators.continuity + indicators.trust + indicators.capacity + indicators.regulatory) / 4;
  const pillarOutcome: CommandCell[] = [
    { label: "Incidents handled", score: ctx.avgHandlingScore == null ? null : bandHigh(ctx.avgHandlingScore, 85, 65, 40), note: ctx.avgHandlingScore == null ? undefined : `team handling score ${ctx.avgHandlingScore}/100` },
    { label: "Escalation pickup (MTTA)", score: ctx.handoffLatS == null ? null : bandLow(ctx.handoffLatS / 60, 2, 5, 10), note: ctx.handoffLatS == null ? undefined : `median ${Math.round(ctx.handoffLatS)} s from escalation to acknowledgement` },
    { label: "Impact indicators at the end", score: decisions.length ? Math.round((endInd / 5) * 12) : null, note: decisions.length ? `continuity ${indicators.continuity} · trust ${indicators.trust} · capacity ${indicators.capacity} · regulatory ${indicators.regulatory} (of 5)` : undefined },
  ];

  const mkPillar = (key: PillarKey, label: string, weight: number, cells: CommandCell[], minCells: number): CommandPillar => {
    const m = cells.filter(c => c.score != null);
    return { key, label, weight, cells, measured: m.length, score: m.length >= minCells ? Math.round((m.reduce((s, c) => s + (c.score ?? 0), 0) / m.length / 12) * 100) : null };
  };
  const pillars = [
    mkPillar("team", "Team & incident", PILLAR_WEIGHTS.team, pillarTeam, 1),
    mkPillar("stakeholders", "Stakeholders", PILLAR_WEIGHTS.stakeholders, pillarStake, 1),
    mkPillar("reporting", "Reporting to management", PILLAR_WEIGHTS.reporting, pillarReport, 1),
    mkPillar("outcome", "Team outcome", OUTCOME_WEIGHT, pillarOutcome, 1),
  ];
  const proc = pillars.filter(p => p.key !== "outcome" && p.score != null);
  const procW = proc.reduce((s, p) => s + p.weight, 0);
  // A command score needs evidence from at least two of the three process pillars: one answered
  // card alone must not read as "Ready to command".
  const process = proc.length >= 2 && procW ? proc.reduce((s, p) => s + p.weight * (p.score ?? 0), 0) / procW : null;
  const outcome = pillars[3].score;
  const uncappedScore = process == null ? null : Math.round(outcome == null ? process : process * (1 - OUTCOME_WEIGHT) + outcome * OUTCOME_WEIGHT);

  // ── Critical errors (cap at 69) ─────────────────────────────────────────────
  for (const d of decisions) if (d.critical) criticalErrors.push({ label: d.critical, detail: `${d.from.name}: you chose "${d.optionLabel}". Better: "${d.bestLabel}"`, atS: d.firedS != null && d.decidedInS != null ? d.firedS + d.decidedInS : d.firedS });
  if (truthSeverity === 1 && firstAttackEscTs != null && declTs == null) {
    criticalErrors.push({ label: "A Sev-1 incident was never declared", detail: "The attack reached data, a critical asset or destructive impact, and the shift ended without an incident declaration.", atS: null });
  }
  const score = uncappedScore == null ? null : criticalErrors.length ? Math.min(uncappedScore, MANAGER_SCORE_CAP) : uncappedScore;
  const level = score == null ? null : score >= 85 ? "command_ready" : score >= 70 ? "proficient" : score >= 50 ? "developing" : "needs_coaching";
  const levelLabel = level === "command_ready" ? "Ready to command" : level === "proficient" ? "Proficient" : level === "developing" ? "Developing" : level === "needs_coaching" ? "Needs coaching" : "Not enough evidence";

  // ── Confidence calibration ──────────────────────────────────────────────────
  const zero = () => ({ low: 0, medium: 0, high: 0 });
  const grid: Record<Rank, Record<Confidence, number>> = { great: zero(), good: zero(), okay: zero(), weak: zero() };
  for (const d of decisions) if (d.rank && d.confidence) grid[d.rank][d.confidence]++;
  const highTotal = grid.great.high + grid.good.high + grid.okay.high + grid.weak.high;
  const highGreat = grid.great.high;
  const calibrated = highTotal >= 2 ? highGreat / highTotal >= 0.8 : null;

  // ── Command timeline ────────────────────────────────────────────────────────
  const timeline: TimelineMark[] = [];
  const firstAttack = attackLogs.map(x => x.t.ts).filter((x): x is number => x != null).sort((a, b) => a - b)[0];
  if (firstAttack != null) timeline.push({ t: relS(firstAttack) ?? 0, lane: "attacker", label: "first attack log", tone: "neutral" });
  if (firstAttackEscTs != null) timeline.push({ t: relS(firstAttackEscTs) ?? 0, lane: "attacker", label: "first real escalation", tone: "neutral" });
  if (exfilTs != null) timeline.push({ t: relS(exfilTs) ?? 0, lane: "attacker", label: "data exfiltration", tone: "bad" });
  if (impactTs != null) timeline.push({ t: relS(impactTs) ?? 0, lane: "attacker", label: "destructive impact", tone: "bad" });
  for (const e of sevEvents) timeline.push({ t: relS(tsOf(e)) ?? 0, lane: "manager", label: e.type === "incident.declared" ? `declared Sev-${(e.payload as { severity?: unknown }).severity}` : `severity → Sev-${(e.payload as { severity?: unknown }).severity}`, tone: "neutral" });
  for (const e of contDecisions) timeline.push({ t: relS(tsOf(e)) ?? 0, lane: "manager", label: e.type === "containment.approved" ? "approved containment" : "denied containment", tone: (e.type === "containment.approved") === isRealEid(eidOf(e)) ? "good" : "bad" });
  sitreps.forEach((e, i) => timeline.push({ t: relS(tsOf(e)) ?? 0, lane: "manager", label: `SITREP ${i + 1}`, tone: "neutral" }));
  for (const d of decisions) {
    if (d.firedS != null) timeline.push({ t: d.firedS, lane: "pressure", label: `${d.from.name || d.card}${d.state === "expired" ? " (expired)" : ""}`, tone: d.state === "expired" ? "bad" : "neutral" });
    if (d.state !== "expired" && d.firedS != null && d.decidedInS != null) timeline.push({ t: d.firedS + d.decidedInS, lane: "manager", label: `answered ${d.from.name || d.card}`, tone: d.rank === "great" || d.rank === "good" ? "good" : "bad" });
  }
  for (const q of questions) {
    if (q.askedS != null) timeline.push({ t: q.askedS, lane: "pressure", label: `${q.from.name || "stakeholder"} asked${q.state === "expired" ? " (no answer)" : ""}`, tone: q.state === "expired" ? "bad" : "neutral" });
    if (q.askedS != null && q.repliedInS != null) timeline.push({ t: q.askedS + q.repliedInS, lane: "manager", label: `answered ${q.from.name || "a stakeholder"}`, tone: q.score >= 8 ? "good" : "bad" });
  }
  for (const r of reports) if (r.atS != null) timeline.push({ t: r.atS, lane: "manager", label: `stakeholder report (${r.audience})`, tone: "neutral" });
  timeline.sort((a, b) => a.t - b.t);

  // ── Leadership profile (patterns, not a score) ──────────────────────────────
  const answered = decisions.filter(d => d.state !== "expired");
  const goodShare = answered.length ? answered.filter(d => d.rank === "great" || d.rank === "good").length / answered.length : 0;
  const medDecide = median(answered.map(d => d.decidedInS ?? 0));
  const cellScore = (label: string) => [...pillarTeam, ...pillarStake, ...pillarReport].find(c => c.label === label)?.score ?? null;
  const profile: ProfileTrait[] = [];
  if (answered.length >= 2 && medDecide != null && medDecide <= 90 && goodShare >= 0.6) profile.push({ style: "Decisive", evidence: `median ${Math.round(medDecide)} s per decision, ${Math.round(goodShare * 100)}% good or better` });
  if (grid.weak.high >= 2 || (calibrated === false && highTotal >= 2)) profile.push({ style: "Overconfident", evidence: `${highTotal - highGreat} of ${highTotal} high-confidence calls were not the best option` });
  if (decisions.length - answered.length >= 2 || (grid.okay.low + grid.okay.medium >= 2 && grid.great.high === 0)) profile.push({ style: "Over-cautious", evidence: `${decisions.length - answered.length} request${decisions.length - answered.length === 1 ? "" : "s"} ran out of time; several middle-of-the-road calls` });
  if (answered.length >= 2 && medDecide != null && medDecide <= 90 && (cellScore("SITREP cadence") ?? 12) <= 4) profile.push({ style: "Firefighter", evidence: "fast on each request, but management went long without a SITREP" });
  if (indicators.continuity <= 1 && contDecisions.filter(e => e.type === "containment.approved").length >= 2) profile.push({ style: "Over-isolator", evidence: `business continuity ended at ${indicators.continuity}/5 after ${contDecisions.filter(e => e.type === "containment.approved").length} approved containments` });
  if ((cellScore("SITREP cadence") ?? 0) >= 8 && (pillars[1].score ?? 0) >= 70) profile.push({ style: "Communicator", evidence: "steady SITREPs and sound stakeholder calls" });
  if ((cellScore("Load balancing") ?? 0) >= 8 || ((avgCards(internal) ?? 0) >= 8 && internal.length >= 2)) profile.push({ style: "Shields the team", evidence: "handled the team's dilemmas and load before they became problems" });

  // ── Keep 3 / improve 3 ──────────────────────────────────────────────────────
  const measured = [...pillarTeam, ...pillarStake, ...pillarReport].filter(c => c.score != null);
  const keep = [...measured].filter(c => (c.score ?? 0) >= 8).sort((a, b) => (b.score ?? 0) - (a.score ?? 0)).slice(0, 3).map(c => KEEP_LINE[c.label] ?? c.label);
  const improve = [...measured].filter(c => (c.score ?? 0) <= 8 && !keep.includes(KEEP_LINE[c.label] ?? c.label)).sort((a, b) => (a.score ?? 0) - (b.score ?? 0)).slice(0, 3).map(c => IMPROVE_LINE[c.label] ?? c.label);

  // ── Debrief questions, chosen by what happened ──────────────────────────────
  const fired = new Set(decisions.map(d => d.card));
  const debrief: string[] = [];
  if (fired.has("isolate_or_wait")) debrief.push("Tier-2 wanted to isolate and Tier-3 wanted to watch. How did you choose, and what would have happened with the other call?");
  if (fired.has("owner_veto")) debrief.push("How did the team weigh the business owner's objection against the risk on the critical asset?");
  if (declTs == null && firstAttackEscTs != null) debrief.push("When did you first know this was an incident, and what held back the declaration?");
  if (decisions.some(d => d.state === "expired")) debrief.push("Which request ran out of time, and what stopped you answering it?");
  if (gaps.some(g => g.includes("SITREP"))) debrief.push(`There was a long stretch without a SITREP (${gaps.find(g => g.includes("SITREP"))}). What was happening, and who could have sent one?`);
  if (fired.has("legal_reportable") || questions.some(q => q.qid === "q_data")) debrief.push("What did you know about personal data when Legal asked, and how did you say it?");
  if (questions.some(q => q.state === "expired")) debrief.push("A stakeholder question went unanswered. Who else could have answered it, and what did that silence cost?");
  if (fired.has("contested_verdict")) debrief.push("Two analysts made opposite calls on the same log. What evidence settled it, and how do we avoid a split picture next time?");
  debrief.push("Which decision would you make differently with what you know now?", "What did the team need from you that it did not get?");

  return {
    managerId: lead.user_id, managerName: lead.name,
    score, uncappedScore, level, levelLabel, criticalErrors, pillars, decisions, questions, reports,
    calibration: { grid, highTotal, highGreat, calibrated },
    indicators, indicatorTrail, timeline, endS, gaps,
    declared, finalSeverity, truthSeverity,
    profile: profile.slice(0, 3), keep, improve, debrief: debrief.slice(0, 3),
  };
}

/** The team's view of the Command Review: the timeline and the decisions, no grades. */
export function redactManagerReview(r: ManagerReview): ManagerReview {
  return {
    ...r, score: null, uncappedScore: null, level: null, levelLabel: "", criticalErrors: [],
    pillars: [], profile: [], keep: [], improve: [],
    calibration: { grid: { great: { low: 0, medium: 0, high: 0 }, good: { low: 0, medium: 0, high: 0 }, okay: { low: 0, medium: 0, high: 0 }, weak: { low: 0, medium: 0, high: 0 } }, highTotal: 0, highGreat: 0, calibrated: null },
    decisions: r.decisions.map(d => ({ ...d, score: 0, rank: null, confidence: null, critical: null, options: d.options.map(o => ({ ...o, rank: null })) })),
    questions: r.questions.map(q => ({ ...q, score: 0, checks: [] })),
    reports: r.reports.map(x => ({ ...x, completeness: 0, promiseKept: null })),
    timeline: r.timeline.map(m => ({ ...m, tone: "neutral" as const })),
    redacted: true,
  };
}
