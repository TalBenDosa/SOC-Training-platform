import type { RosterMember, Ev } from "@/lib/team/types";
import { CLAIM_TTL_MS } from "@/lib/team/projections";
import { asStr, hostKey } from "@/lib/team/format";
import { pausedSpans, activeMs, addActive } from "@/lib/team/pauses";

// ── After-action report — derived entirely from the event log (isomorphic: no React,
// no server-only imports, so the server computes it once and the client can re-run it).
//
// 2026-09-27 live-playtest fix round (docs/team-review/LIVE-PLAYTEST-2026-09-27-team.md,
// P0-1 + "P1 — הוגנות הניקוד"): detection is scored per INCIDENT (the answer key's
// `incident_id`), `suspicious` is partial credit, precision is a smooth band judged per
// incident, help-desk is scored on the decision, take-overs/overload need real load,
// unopened-log dispositions are down-weighted, T3/TI/T2 cells measure substance, timings
// use the right escalation, and curveballs need supporting telemetry to be "handled".

// Work-division thresholds: an analyst is "overloaded" at ≥3 concurrent open cases
// (matches the existing amber load styling), and NIMS/ICS puts effective span of
// control at 3–7 direct reports — beyond 7 a single coordinator loses oversight.
export const OVERLOAD_CASES = 3;
/** Bumped whenever the report's shape/semantics change (cached reports older than this are stale). */
export const REPORT_VERSION = 4;   // 3: per-event SLA, misses, team triage metrics · 4: EDR host isolation judged
// (QA M3 pause-aware timing — like H2 — applies to reports built from now on; no bump, so a
// cached report keeps matching the XP already awarded from it. Without pauses nothing changes.)

// ── Scoring weights (documented here so the debrief can explain every number) ──────
/** `suspicious` = a LOW-CONFIDENCE LEAD. On a real attack log it earns partial credit —
 *  the analyst flagged it, just without full confidence; it is never a hard miss. */
export const SUSPICIOUS_CREDIT_ON_ATTACK = 0.75;
/** `suspicious` on a benign log is a MILD penalty (half credit): noise was raised as a
 *  lead but not called an attack. A blanket "mark everything suspicious" strategy lands
 *  at ≈50–55% accuracy — below the 75% band — so hedging can't game the score. */
export const SUSPICIOUS_CREDIT_ON_BENIGN = 0.5;
/** Escalating the legitimate "control" log of a REAL incident (right incident, wrong log)
 *  earns half credit in escalation precision, unless the same analyst also escalated one
 *  of that incident's malicious logs (then it is a duplicate, counted once at full). */
export const RELATED_CONTROL_CREDIT = 0.5;
/** A disposition on a log the analyst never opened (no event.opened / click for that id
 *  by that user) is a guess, not triage: it keeps only this share of its credit. Applied
 *  only when the session HAS click telemetry (legacy logs without it aren't penalised). */
export const UNOPENED_DISPOSITION_WEIGHT = 0.5;
/** An average read time under this many seconds is clicking through, not reading:
 *  Time-to-triage is then capped at 4/12 so raw speed isn't rewarded. */
export const MIN_EVIDENCE_DWELL_S = 5;
/** An overload episode (≥ OVERLOAD_CASES open at once) must last at least this long before
 *  it counts for the Manager's "Load balancing" (a 29-second spike is not overload). */
export const OVERLOAD_MIN_MS = 60_000;
/** A card needs at least this many MEASURED criteria to show a percentage; below it the
 *  card reads "insufficient evidence" instead of an inflated 100%. */
export const MIN_MEASURED_CELLS = 2;

const ATTACK_VERDICTS = new Set(["tp", "escalate"]);

// ── Balanced disposition accuracy (Tal, 2026-10-07 — report P0 fairness) ──────────────
// Most of the feed is noise, so a plain "share of logs judged right" let an analyst who
// stamps everything benign score high while walking past the attack. The T1 card now
// averages TWO halves: attack handling (severity-weighted — a missed Critical costs four
// times a missed Low, and an attack log you OPENED and left, with nobody else catching it,
// counts as a miss) and accuracy on benign logs. Full marks need at least one attack log
// handled: with no attack log in your work the cell is capped at 8/12.
const SEV_WEIGHT: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 1, info: 1 };
const sevWeight = (s: string) => SEV_WEIGHT[(s || "").toLowerCase().trim()] ?? 1;
/** An attack log you opened and left, from an incident the team DID detect through another
 *  log, is a missed piece of evidence rather than a missed attack: it weighs half. */
export const DETECTED_INCIDENT_MISS_WEIGHT = 0.5;
// ── Share of the load (Tal, 2026-10-07): passivity used to cost nothing — an analyst who
// barely touched the feed got "insufficient evidence" or a score built on three logs. Each
// Tier-1 is now measured against a fair share of the queue: the logs that reached the feed
// divided by the Tier-1 analysts on the roster. 90% of a fair share or more = full marks,
// 10% or less = 0, linear in between. (Carrying more than your share caps at full marks.)
const LOAD_SHARE_FULL = 90, LOAD_SHARE_ZERO = 10;

// ── "Good catch" model (Tal, 2026-10-03). An incident is built from several logs, so a
// binary "someone flagged one log" over-credits a shallow catch. Catch quality is graded
// per incident: a detection FLOOR, then TIMELINESS (MTTD vs an SLA by severity), SCOPE
// COVERAGE (how much of the incident's logs/hosts/techniques the team actually surfaced),
// and VERDICT quality (a firm TP beats a hedged "suspicious"). Thresholds are defaults and
// live here so they are easy to tune.
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, informational: 0, info: 0 };
/** Time-to-detect SLA per max-severity of the incident, in seconds. */
const SLA_SEC: Record<string, number> = { critical: 300, high: 900, medium: 1800, low: 3600 };
const sevRank = (s: string) => SEV_RANK[s.toLowerCase().trim()] ?? 0;
const slaForSev = (s: string) => SLA_SEC[s.toLowerCase().trim()] ?? 1800;
/** A catch is "caught well" only at or above these; "partial" needs one of them. */
const SCOPE_GOOD = 60, SCOPE_PARTIAL = 40;
export type IncidentGrade = "missed" | "noticed" | "partial" | "caught_well";
/** Triage SLA per severity — the same table the live alert queue uses (minutes). */
const SLA_MIN: Record<string, number> = { critical: 1, high: 3, medium: 10 };
const slaSecFor = (sev: string) => (SLA_MIN[sev] ?? 30) * 60;
const REPORTED_CAP = 20;
const MISS_CAP = 8;
const VALID_VERDICTS = new Set(["true_positive", "false_positive", "benign", "suspicious"]);

export interface RubricCell { label: string; score: number | null; note?: string }
/** One log an analyst acted on — escalated, or triaged when high/critical — against its SLA. */
export interface ReportedItem {
  label: string; severity: string; kind: "escalation" | "triage";
  arrivedS: number | null; actedS: number | null; responseS: number | null;
  /** Triage SLA for the log's severity (seconds) — the same table as the live alert queue. */
  slaS: number; withinSla: boolean | null;
  /** Ground truth: a real attack log, a control step of a real incident, or benign. */
  truth: "attack" | "related" | "benign";
  /** Escalations only: what Tier-2 did with it. */
  outcome?: "resolved" | "acknowledged" | "bounced" | "open";
  verdict?: string;
}
/** A log worth talking about in the debrief (a miss / a false alarm). */
export interface MissItem { label: string; severity: string; arrivedS: number | null; detail?: string }
/** One EDR network isolation (0082), judged against the answer key. */
export interface IsolationItem {
  host: string; by: string | null; atS: number | null;
  /** When the host was released again (by anyone), if it was. */
  releasedS: number | null;
  /** compromised = the host carried at least one real attack log; clean = it never did. */
  verdict: "compromised" | "clean";
  /** Isolating a compromised host is right; isolating a clean one disrupted the business for nothing. */
  correct: boolean;
  /** Compromised hosts: first attack log on the host → the isolation (seconds, ≥ 0). */
  timeToIsolateS: number | null;
}
/** A compromised host nobody isolated. */
export interface MissedHost { host: string; attackLogs: number; firstAttackS: number | null }
export interface UserReport {
  user_id: string; name: string; role: string;
  opened: number; avgDwellS: number | null; dispCount: number; dispCorrect: number;
  /** Balanced disposition accuracy: mean of attackHandling and benignAcc (either alone when only one exists). */
  dispAcc: number | null;
  /** Attack half, severity-weighted: attack logs you flagged (TP / suspicious / escalated) vs those you called benign or opened and left. */
  attackHandling: number | null;
  /** Benign half: benign/control logs you judged correctly (suspicious = half). */
  benignAcc: number | null;
  /** Tier-1 only: distinct logs you triaged (verdict or escalation) as % of a fair share of the feed. */
  loadSharePct: number | null;
  /** Distinct logs judged, and those whose final verdict is wrong (QA H2: XP counts distinct work, wrong calls cost). */
  dispDistinct: number; dispWrong: number;
  /** Distinct dispositions on logs this analyst never opened (0 when the session has no click telemetry). */
  dispUnopened: number;
  escCount: number; escQuality: number | null; acks: number; contReq: number; contDecided: number;
  roleActions: number; firstActionS: number | null; contribution: number;
  rubric: RubricCell[]; rubricPct: number | null;
  /** How many rubric cells were actually measured; < MIN_MEASURED_CELLS ⇒ insufficientEvidence. */
  measuredCells: number; insufficientEvidence: boolean;
  // ── v3: per-event SLA + misses ──
  /** Escalations + high/critical triage, oldest first (capped at REPORTED_CAP). */
  reported: ReportedItem[];
  slaMet: number; slaTotal: number; slaPct: number | null;
  /** Attack logs this analyst called benign / false positive (latest verdict). */
  falseNegatives: MissItem[];
  /** Attack logs this analyst opened, took no action on — and nobody else handled either. */
  walkedPast: MissItem[];
  /** Benign logs (not part of any incident) this analyst escalated or called a true positive. */
  falseAlarms: MissItem[];
  // ── v4: EDR host isolation ──
  /** Hosts this analyst isolated in EDR (first isolation per host), each judged. */
  isolations: IsolationItem[];
  isoCorrect: number; isoPct: number | null;
}
export interface IncidentReport {
  id: string; label: string; attackEvents: number;
  detected: boolean; escalated: boolean; contained: boolean;
  firstSeenS: number | null; detectS: number | null; dwellS: number | null;
  /** How much of the incident the team surfaced (built from several logs). */
  scopeCoverage: number | null; hostCoverage: number | null; techCoverage: number | null;
  /** Timeliness inputs + overall catch grade. */
  maxSeverity: string; slaSec: number; slaMet: boolean | null;
  handlingScore: number; grade: IncidentGrade;
}
export interface InjectResult {
  kind: string; text: string; expected: string; objective: string;
  decoy: boolean; scored: boolean; handled: boolean;
  /** false ⇒ the log holds nothing to judge this inject against (e.g. a twist with no supporting telemetry). */
  evaluable: boolean; note?: string;
}

const ROLE_ACTION_TYPES = new Set(["hunt.logged", "rule.published", "rule.tuned", "intel.published", "handover.noted", "decision.logged", "evidence.pinned", "case.status_set", "case.assigned", "note.added", "containment.executed", "scope.set", "scope.confirmed", "sitrep.sent", "ticket.answered", "escalation.resolved", "elevation.requested", "report.submitted"]);

// ── small helpers ──────────────────────────────────────────────────────────────
const eidOf = (e: Ev) => { const v = (e.payload as { event_id?: unknown } | null)?.event_id; return v == null ? "" : String(v); };
const tsOf = (e: Ev): number | null => (e.occurred_at ? Date.parse(e.occurred_at) : null);
const wordCount = (s: string) => s.trim().split(/\s+/).filter(Boolean).length;
const clamp01 = (x: number) => Math.max(0, Math.min(1, x));
const bandHigh = (v: number, a: number, b: number, c: number) => (v >= a ? 12 : v >= b ? 8 : v >= c ? 4 : 0);
const bandLow = (v: number, a: number, b: number, c: number) => (v <= a ? 12 : v <= b ? 8 : v <= c ? 4 : 0);
/** Continuous 0–12 (integer) between `zero` and `full` — no cliff where one extra miss drops a band to 0. */
const smoothBand = (v: number, zero: number, full: number) => Math.round(12 * clamp01((v - zero) / (full - zero)));
function median(xs: number[]): number | null { if (!xs.length) return null; const s = [...xs].sort((a, b) => a - b); const m = Math.floor(s.length / 2); return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; }
const pct = (num: number, den: number) => (den ? Math.round((num / den) * 100) : null);

/** MITRE ids in free text ("T1078.004, T1098" → ["T1078.004","T1098"]). */
function techIds(v: unknown): string[] { return String(v ?? "").toUpperCase().match(/T\d{4}(?:\.\d{3})?/g) ?? []; }
const techBase = (t: string) => t.slice(0, 5);
// Bounded quantifiers (RFC label ≤63, TLD ≤24, hash ≤128) so a long hyphen-heavy string
// can't trigger catastrophic backtracking — a 16 KB finding was ~110 ms/run, and 500 of them
// blew past the report route's 60 s maxDuration (Phase 9 P9-01). Callers also slice the text.
const IOC_LIKE = /(?:\d{1,3}\.){3}\d{1,3}|\b[a-f0-9]{32,128}\b|\b[a-z0-9-]{1,63}\.[a-z]{2,24}\b|#\d+/i;
/** Guard any free-text before an unbounded-ish regex / scan (Phase 9 P9-01). */
const clip = (v: unknown, n = 2000) => String(v ?? "").slice(0, n);
const TRIVIAL = /^(n\/?a|none|unknown|tbd|test|todo|x+|-+|\?+|\.+|asdf|na|no|yes|idk)$/i;
/** Non-trivial text: long enough, has letters, not a placeholder. */
function substantive(v: unknown, minWords = 1, minLen = 3): boolean {
  const s = String(v ?? "").trim();
  return s.length >= minLen && /[a-z]/i.test(s) && !TRIVIAL.test(s) && wordCount(s) >= minWords;
}

// ── entity tokens (for "does this text cite the case?") ────────────────────────
const ENTITY_RAW_KEY = /(^|[._])(domain|hostname|host|dstip|srcip|dst_ip|src_ip|ip|sha256|md5|query|email|user|username|computer_name|devicename)$/i;
function addTok(out: Set<string>, v: unknown) {
  if (typeof v !== "string" && typeof v !== "number") return;
  const s = String(v).trim().toLowerCase();
  if (s.length < 3) return;
  out.add(s);
  // user@domain → also the local part ("m.torres") and the domain ("mailout-nexacorp.com").
  if (s.includes("@")) { const [local, dom] = s.split("@"); if (local && local.length >= 3) out.add(local); if (dom && dom.length >= 4) out.add(dom); }
  // DOMAIN\user → user
  if (s.includes("\\")) { const u = s.split("\\").pop() ?? ""; if (u.length >= 3) out.add(u); }
  // ws-eng-2093.nexacorp.com → ws-eng-2093 (host FQDN vs short name)
  if (/^[a-z][a-z0-9-]*\.[a-z0-9.-]+$/.test(s)) { const short = s.split(".")[0]; if (short.length >= 5 && /[\d-]/.test(short)) out.add(short); }
}
function entityTokens(p: Record<string, unknown>): Set<string> {
  const out = new Set<string>();
  for (const k of ["hostname", "user_email", "src_ip", "dst_ip", "dest_ip"]) addTok(out, p[k]);
  const obj = (v: unknown) => (v && typeof v === "object" ? v as Record<string, unknown> : null);
  const u = obj(p.user); if (u) { addTok(out, u.email); addTok(out, u.name); }
  const n = obj(p.network); if (n) { addTok(out, n.domain); addTok(out, n.ip); }
  const f = obj(p.file); if (f) addTok(out, f.sha256);
  const d = obj(p.dns); if (d) { addTok(out, d.query); addTok(out, obj(d.question)?.name); }
  const pr = obj(p.process); if (pr) addTok(out, pr.user);
  const raw = obj(p.raw); if (raw) for (const [k, v] of Object.entries(raw)) if (ENTITY_RAW_KEY.test(k)) addTok(out, v);
  return out;
}
const mentions = (text: string, tokens: Iterable<string>) => { const t = text.toLowerCase(); for (const k of tokens) if (t.includes(k)) return true; return false; };
const countMentions = (text: string, tokens: string[]) => { const t = text.toLowerCase(); return tokens.filter(k => t.includes(k)).length; };

// ── quality scorers ─────────────────────────────────────────────────────────────
function escQualityScore(p: Record<string, unknown>): number {
  // T1-4/5: structured report quality — summary + mechanism-bearing observations
  // (word count) + requested_action + severity + at least one IOC. `what`/`why`
  // are back-compat aliases of summary/observations.
  let s = 0;
  if (String(p.summary ?? p.what ?? "").trim()) s += 30;
  const whyWords = wordCount(String(p.observations ?? p.why ?? ""));
  s += whyWords >= 20 ? 25 : whyWords >= 10 ? 15 : whyWords > 0 ? 8 : 0;
  if (String(p.requested_action ?? "").trim()) s += 15;
  if (p.severity || p.impact) s += 15;
  if (Array.isArray(p.iocs) ? p.iocs.length > 0 : false) s += 15;
  return Math.min(100, s);
}
/** T3 hunt quality — substance over count. Hypothesis naming a real case entity (25) ·
 *  a finding citing case entities (35) · a MITRE technique matching the case — a
 *  sub-technique or parent of an observed one counts (T1078.004 ≈ T1078) (25) · a
 *  conclusion BACKED by a finding (15; no free points for the default "confirmed").
 *  A REFUTED / INCONCLUSIVE hunt with evidence gets the full technique credit —
 *  disproving a wrong hypothesis is real hunting even if its technique isn't in the case.
 *  Entities match by full value, email local-part (m.torres) and short host name. */
function huntQualityScore(p: Record<string, unknown>, caseEntities: string[], caseTechBases: Set<string>): number {
  const hyp = clip(p.hypothesis).trim();
  const finding = clip(p.finding).trim();
  const conclusion = clip(p.conclusion, 64).trim().toLowerCase();
  let s = 0;
  const hypWords = wordCount(hyp);
  if (hypWords >= 12 && mentions(hyp, caseEntities)) s += 25; else if (hypWords >= 8) s += 12;
  const findWords = wordCount(finding);
  const findCited = countMentions(finding, caseEntities);
  if (findWords >= 15 && findCited >= 2) s += 35; else if (findWords >= 10 && findCited >= 1) s += 18; else if (finding) s += 5;
  const techs = techIds(p.technique);
  const refutedOrInc = conclusion === "refuted" || conclusion === "inconclusive";
  const hasEvidence = findCited >= 1 || IOC_LIKE.test(finding);
  if (techs.length && techs.some(t => caseTechBases.has(techBase(t)))) s += 25;
  else if (techs.length && refutedOrInc && hasEvidence) s += 25;
  else if (techs.length) s += 12;
  if (["confirmed", "refuted", "inconclusive"].includes(conclusion) && findWords >= 10) s += 15;
  return Math.min(100, s);
}
/** T2 incident-report quality (deterministic, same spirit as escQualityScore). */
function reportQualityScore(p: Record<string, unknown>): number {
  // Spread the score so the 0/4/8/12 bands are all reachable ABOVE the submit floor
  // (summary + ≥12-word findings + recommendation). Depth climbs it (G2); a cited
  // indicator in the findings earns a substance bonus (G5, partial).
  let s = 0;
  if (clip(p.summary, 400).trim()) s += 15;
  const findings = clip(p.findings).trim();
  const findingWords = wordCount(findings);
  s += findingWords >= 60 ? 40 : findingWords >= 35 ? 30 : findingWords >= 20 ? 20 : findingWords >= 12 ? 12 : findingWords > 0 ? 5 : 0;
  if (clip(p.verdict, 64).trim()) s += 10;
  const recWords = wordCount(clip(p.recommendation));
  s += recWords >= 12 ? 20 : recWords > 0 ? 10 : 0;
  // Bounded quantifiers (Phase 9 P9-01) — findings is already clipped to 2 KB.
  const hasIoc = /(?:\d{1,3}\.){3}\d{1,3}|\b[a-f0-9]{16,128}\b|\b[a-z0-9-]{1,63}\.[a-z]{2,24}\b|\b[A-Z]{2,}[-_][A-Z0-9-]{1,64}\b/.test(findings);
  if (hasIoc) s += 15;
  return Math.min(100, s);
}

// ── help-desk tickets: the correct DECISION ─────────────────────────────────────
// A ticket's expected decision comes from the answer key: an explicit
// `expected_decision` if present, else inferred from expected_response/text — a
// social-engineering ticket (read back an MFA code, "never", "refuse", vishing…)
// must be REJECTED; anything else with an expected response is "handled".
// Inference is deliberately narrow (a manual ticket like "user says they don't have VPN
// access" must NOT read as a refusal): refusal verbs in the EXPECTED RESPONSE, or a
// request in the ticket to read back / share a one-time code.
const RE_REJECT_RESPONSE = /\b(never|refuse[sd]?|reject(ed)?|decline|(do not|don't) (read|share|give|disclose|provide|send)|social[- ]engineering attempt)\b/i;
const RE_REJECT_TICKET = /\b(read(ing)? (it |them )?back|share|give|tell)\b[^.]{0,40}\b(mfa|otp|one[- ]time|verification) code/i;
function expectedTicketDecision(p: Record<string, unknown>): "handled" | "rejected" | null {
  const ex = asStr(p.expected_decision).toLowerCase();
  if (ex === "handled" || ex === "rejected") return ex;
  if (RE_REJECT_RESPONSE.test(asStr(p.expected_response)) || RE_REJECT_TICKET.test(asStr(p.text))) return "rejected";
  return asStr(p.expected_response) ? "handled" : null;
}
const normDecision = (d: unknown): "handled" | "rejected" => (/reject|refus|deny|denied|escalat/i.test(asStr(d)) ? "rejected" : "handled");

// ── per-role success rubric (0/4/8/12) ──────────────────────────────────────────
// Criteria still awaiting instrumentation score `null` ("not yet measured") and are
// EXCLUDED from the % — and a card with fewer than MIN_MEASURED_CELLS measured cells
// shows "insufficient evidence" rather than a % built on one or zero criteria.
const TODO: RubricCell = { label: "", score: null, note: "not yet measured" };
function rubricPercent(cells: RubricCell[]): number | null {
  const scored = cells.filter(c => c.score != null);
  if (scored.length < MIN_MEASURED_CELLS) return null;
  return Math.round((scored.reduce((s, c) => s + (c.score ?? 0), 0) / (scored.length * 12)) * 100);
}

interface RubricCtx {
  role: string; dispAcc: number | null; dispNoAttack: boolean; loadSharePct: number | null; loadHandled: number; loadFair: number; escAckRate: number | null; escPrecision: number | null; escQuality: number | null;
  triageMin: number | null; dwellTooShort: boolean; ackLatencyMin: number | null; approvalLatencyMin: number | null;
  huntCount: number; huntTech: number; huntQuality: number | null; noteCount: number; elevAnsweredPct: number | null;
  rulePublished: number; ruleMatched: number; ruleTechniques: number; ruleDocRate: number | null;
  intelAttrib: number | null; intelNext: number | null; iocPrecision: number | null;
  contReason: number | null; contQuality: number | null; reportAcc: number | null; isoPct: number | null;
  scopeSetDims: number; scopeConfirmDims: number; scopeConfirmed: boolean;
  decisionCount: number; decisionRationaleRate: number | null;
  helpdeskPct: number | null; helpdeskDupOnly: boolean; sitrepCount: number; reportQuality: number | null;
  huntToConfirmMin: number | null; caseOwnedMin: number | null; mgmtRespondedRate: number | null;
  backupCount: number; loadBalanceRate: number | null; correctionsCount: number;
}
function roleRubric(c: RubricCtx): RubricCell[] {
  switch (c.role) {
    case "t1": {
      const triage = c.triageMin == null ? null : bandLow(c.triageMin, 5, 10, 15);
      return [
        { label: "Disposition accuracy (balanced)", score: c.dispAcc == null ? null : c.dispNoAttack ? Math.min(8, bandHigh(c.dispAcc, 90, 75, 50)) : bandHigh(c.dispAcc, 90, 75, 50), note: c.dispNoAttack ? "capped at 8: no attack log in your work — full marks need a correct call on an attack log" : "average of attack handling (severity-weighted; an attack log you opened and left counts as a miss) and benign accuracy; suspicious = partial credit; unopened logs count at reduced weight" },
        { label: "Share of the load", score: c.loadSharePct == null ? null : smoothBand(c.loadSharePct, LOAD_SHARE_ZERO, LOAD_SHARE_FULL), note: c.loadSharePct == null ? undefined : `you triaged ${c.loadHandled} log${c.loadHandled === 1 ? "" : "s"}; a fair share of this feed was ~${Math.round(c.loadFair)} (${c.loadSharePct}%) — logs a teammate handled never count against you` },
        { label: "Escalation precision", score: c.escPrecision == null ? null : smoothBand(c.escPrecision, 10, 80), note: "per incident: of what you escalated, how much was a real incident (duplicates of one incident count once)" },
        { label: "Card completeness", score: c.escQuality == null ? null : bandHigh(c.escQuality, 90, 70, 40) },
        { label: "Handoff coordination", score: c.escAckRate == null ? null : bandHigh(c.escAckRate, 80, 60, 40), note: "share of your escalations Tier-2 closed the loop on (acknowledged or bounced)" },
        { label: "Time-to-triage", score: triage == null ? null : c.dwellTooShort ? Math.min(triage, 4) : triage, ...(c.dwellTooShort ? { note: `capped: average read time under ${MIN_EVIDENCE_DWELL_S}s — speed without reading isn't triage` } : {}) },
        { label: "Backup & load-balancing", score: c.backupCount ? bandHigh(c.backupCount, 2, 1, 1) : null, note: "took over an alert from an overloaded teammate, or rescued a stale (abandoned) claim — a plain collision earns nothing" },
        { label: "Self-correction", score: c.correctionsCount ? bandHigh(c.correctionsCount, 2, 1, 1) : null, note: "caught and fixed your own verdict — no-fault, scores for you" },
        { label: "Help-desk tickets", score: c.helpdeskPct == null ? null : bandHigh(c.helpdeskPct, 100, 66, 33), note: c.helpdeskDupOnly ? "a second answer to an already-answered ticket earns nothing" : "the right call (verify / refuse) on the tickets injected — not how many you clicked" },
      ];
    }
    case "t2": return [
      { label: "Ack latency", score: c.ackLatencyMin == null ? null : bandLow(c.ackLatencyMin, 2, 5, 10) },
      { ...TODO, label: "Timeline accuracy" },
      { label: "Scoping completeness", score: c.scopeSetDims >= 3 ? 12 : c.scopeSetDims >= 2 ? 8 : c.scopeSetDims >= 1 ? 4 : null },
      { label: "Containment recommendation", score: c.contReason == null ? null : bandHigh(c.contReason, 90, 60, 30) },
      { label: "Containment quality", score: c.contQuality == null ? null : bandHigh(c.contQuality, 85, 60, 35), note: "a denied or later re-targeted request lowers it; executed after approval raises it" },
      { label: "Host isolation", score: c.isoPct == null ? null : bandHigh(c.isoPct, 100, 75, 50), note: "each host you isolated in EDR, judged: a host with real attack activity was right to isolate; a clean host is a needless business outage" },
      { label: "Backup & load-balancing", score: c.backupCount ? bandHigh(c.backupCount, 2, 1, 1) : null, note: "picked up a case while a teammate was overloaded" },
      { label: "Incident report", score: c.reportQuality == null ? null : bandHigh(c.reportQuality, 85, 60, 35) },
      { label: "Report accuracy", score: c.reportAcc == null ? null : bandHigh(c.reportAcc, 90, 65, 40), note: "your report's verdict vs the incident's ground truth" },
    ];
    case "t3": return [
      { label: "Final scope (confirmed)", score: c.scopeConfirmed ? (c.scopeConfirmDims >= 3 ? 12 : c.scopeConfirmDims >= 2 ? 8 : c.scopeConfirmDims >= 1 ? 4 : 0) : null, note: c.scopeConfirmed ? "hosts · users · techniques confirmed" : "not confirmed" },
      { label: "Hunt quality", score: c.huntQuality == null ? null : bandHigh(c.huntQuality, 75, 55, 30), note: "substance + cited evidence + matching technique (sub-technique/parent ok) + backed conclusion" },
      { label: "Hypothesis→conclusion time", score: c.huntToConfirmMin == null ? null : bandLow(c.huntToConfirmMin, 5, 12, 20), note: "the hunt that led to each scope confirmation → the confirmation (early proactive hunts don't count against you)" },
      { label: "Technique attribution", score: c.huntCount ? bandHigh(Math.round((c.huntTech / c.huntCount) * 100), 90, 60, 30) : null, note: "hunts tagged with a valid MITRE technique id" },
      { label: "Elevations answered", score: c.elevAnsweredPct == null ? null : bandHigh(c.elevAnsweredPct, 100, 66, 33), note: "a hunt linked to the elevation (event_id) answers it" },
      { label: "Guidance to T2", score: c.noteCount ? bandHigh(c.noteCount, 3, 2, 1) : null },
      { label: "Host isolation", score: c.isoPct == null ? null : bandHigh(c.isoPct, 100, 75, 50), note: "each host you isolated in EDR, judged: a host with real attack activity was right to isolate; a clean host is a needless business outage" },
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
      { label: "Attribution accuracy", score: c.intelAttrib == null ? null : bandHigh(c.intelAttrib, 90, 60, 30), note: "a real actor/campaign AND a technique or IOC that matches what the attack actually did — not just non-empty fields" },
      { label: "Next-step prediction", score: c.intelNext == null ? null : bandHigh(c.intelNext, 90, 60, 30), note: "your prediction matched a technique / tactic / entity that showed up AFTER you published" },
      { label: "IOC precision", score: c.iocPrecision == null ? null : bandHigh(c.iocPrecision, 90, 60, 30), note: "published IOCs that appear in the attack telemetry (an unverified decoy costs)" },
    ];
    // In the 4-role model the SOC Manager IS the incident coordinator.
    case "mgr": return [
      { label: "Team organised", score: c.caseOwnedMin == null ? null : bandLow(c.caseOwnedMin, 3, 8, 15) },
      { label: "Time-to-approval", score: c.approvalLatencyMin == null ? null : bandLow(c.approvalLatencyMin, 3, 7, 12) },
      { label: "Decision log", score: c.decisionCount === 0 ? null : c.decisionRationaleRate == null ? 4 : bandHigh(c.decisionRationaleRate, 90, 60, 30) },
      { label: "Cadence + SITREP", score: c.sitrepCount === 0 ? null : bandHigh(c.sitrepCount, 3, 2, 1) },
      { label: "Load balancing", score: c.loadBalanceRate == null ? null : bandHigh(c.loadBalanceRate, 100, 50, 1), note: `nudged analysts who stayed overloaded for ≥${OVERLOAD_MIN_MS / 1000}s so the team rebalanced` },
      { label: "Management pressure", score: c.mgmtRespondedRate == null ? null : bandHigh(c.mgmtRespondedRate, 100, 50, 1) },
    ];
    default: return [];
  }
}

export function computeReport(rawEvents: Ev[], roster: RosterMember[]) {
  // A JSON-null payload on any single event must not crash the whole report — one bad row
  // would otherwise make GET /report a permanent 500 and block XP (Phase 9 P9-04).
  const events: Ev[] = rawEvents.map(e => (e.payload == null ? { ...e, payload: {} } : e));
  const started = events.find(e => e.type === "session.started");
  const startedMs = started?.occurred_at ? Date.parse(started.occurred_at)
    : events.length ? Math.min(...events.filter(e => e.occurred_at).map(e => Date.parse(e.occurred_at!))) : Date.now();
  // QA M3: every timing below is RUNNING time — paused spans (session.paused →
  // resumed / ended) are cut out, so a pause never breaches an SLA, ages a claim or
  // inflates MTTD / ack / triage latency (nobody can act while paused).
  const spans = pausedSpans(events);
  const runMs = (a: number, b: number) => activeMs(a, b, spans);
  const relS = (t: number | null) => (t == null || !Number.isFinite(t) ? null : Math.max(0, Math.round(runMs(startedMs, t) / 1000)));
  const feed = events.filter(e => e.type === "feed.event");
  const fid = (e: Ev) => String((e.payload as { id?: string }).id ?? e.seq);

  // ── Ground truth (contract 1). A missing verdict ⇒ benign; a malicious event without
  // an incident_id ⇒ its own incident ("solo:<id>", legacy = one incident per attack event).
  interface Truth { isAttack: boolean; incident: string | null; supports: string | null; ts: number | null; label: string; tokens: Set<string>; technique: string; tactic: string; severity: string; host: string }
  const truth = new Map<string, Truth>();
  for (const fe of feed) {
    const p = fe.payload as Record<string, unknown>;
    const id = fid(fe);
    const isAttack = ATTACK_VERDICTS.has(asStr(p.expected_verdict));
    truth.set(id, {
      isAttack, incident: asStr(p.incident_id) || (isAttack ? `solo:${id}` : null), supports: asStr(p.supports_inject) || null,
      ts: tsOf(fe), label: asStr(p.description) || asStr(p.event_type) || "event", tokens: entityTokens(p),
      technique: String(p.mitre_technique ?? ""), tactic: String(p.mitre_tactic ?? ""),
      severity: asStr(p.severity), host: asStr(p.hostname),
    });
  }
  const attackIds = new Set([...truth].filter(([, t]) => t.isAttack).map(([k]) => k));
  const incidents = new Map<string, { id: string; label: string; attackEids: string[]; firstSeen: number | null }>();
  for (const [eid, t] of truth) {
    if (!t.isAttack || !t.incident) continue;
    let inc = incidents.get(t.incident);
    if (!inc) { inc = { id: t.incident, label: t.label, attackEids: [], firstSeen: t.ts }; incidents.set(t.incident, inc); }
    inc.attackEids.push(eid);
    if (t.ts != null && (inc.firstSeen == null || t.ts < inc.firstSeen)) { inc.firstSeen = t.ts; inc.label = t.label; }
  }
  /** The REAL incident (one with ≥1 malicious log) this log belongs to — control steps included. */
  const incidentOfEid = (eid: string) => { const inc = truth.get(eid)?.incident; return inc && incidents.has(inc) ? inc : null; };

  // Tokens that show up in >30% of a realistic feed (the company domain, a shared DC IP)
  // don't identify anything — drop them so "cites the case" means something.
  const tokenFreq = new Map<string, number>();
  for (const t of truth.values()) for (const k of t.tokens) tokenFreq.set(k, (tokenFreq.get(k) ?? 0) + 1);
  const isCommon = (k: string) => feed.length >= 20 && (tokenFreq.get(k) ?? 0) > feed.length * 0.3;
  const caseEntities = [...new Set([...attackIds].flatMap(id => [...truth.get(id)!.tokens]))].filter(k => !isCommon(k));
  const caseTechBases = new Set<string>();
  for (const id of attackIds) for (const x of techIds(truth.get(id)!.technique)) caseTechBases.add(techBase(x));

  // ── Valid dispositions only: a real verdict value on a real feed log (a stray
  // `probably_fine` or an unknown id must neither score nor fake a self-correction).
  const telemetry = events.some(e => e.type === "event.opened");
  const isValidDisp = (e: Ev) => e.type === "disposition.set" && VALID_VERDICTS.has(asStr((e.payload as { verdict?: unknown }).verdict)) && (truth.size === 0 || truth.has(eidOf(e)));
  const dispEvents = events.filter(isValidDisp);
  const verdictOf = (e: Ev) => asStr((e.payload as { verdict?: unknown }).verdict);
  const verdictCredit = (eid: string, v: string): number => {
    const atk = attackIds.has(eid);
    if (v === "suspicious") return atk ? SUSPICIOUS_CREDIT_ON_ATTACK : SUSPICIOUS_CREDIT_ON_BENIGN;
    if (atk) return v === "true_positive" ? 1 : 0;
    return v === "false_positive" || v === "benign" ? 1 : 0;
  };

  // ── Escalation timing maps. MTTR is measured from the FIRST escalation of a log; an
  // ack/approval is paired with the latest request AT OR BEFORE it (so a re-escalation
  // raised after a resolve can't make the delta negative, and a bounce→re-escalate
  // is timed from the request that was actually acknowledged).
  const escReq = events.filter(e => e.type === "escalation.requested");
  const validEid = (eid: string) => !!eid && eid !== "undefined" && eid !== "null";
  const timesByEid = (type: string) => {
    const m = new Map<string, number[]>();
    for (const e of events) { if (e.type !== type) continue; const eid = eidOf(e); const t = tsOf(e); if (!validEid(eid) || t == null) continue; if (!m.has(eid)) m.set(eid, []); m.get(eid)!.push(t); }
    for (const v of m.values()) v.sort((a, b) => a - b);
    return m;
  };
  const escTimes = timesByEid("escalation.requested");
  // A case a Tier-2 / Tier-3 opened themselves (0092): they acknowledge it the same moment, so
  // it is no hand-off, and it must not count toward acknowledge latency / team MTTA.
  const selfOpened = new Set(escReq.filter(e => e.role === "t2" || e.role === "t3").map(eidOf));
  const contTimes = timesByEid("containment.requested");
  const reqBefore = (m: Map<string, number[]>, eid: string, t: number): number | null => {
    const ts = m.get(eid); if (!ts?.length) return null;
    let best: number | null = null; for (const x of ts) if (x <= t) best = x;
    return best ?? ts[0];
  };
  const feedTs = new Map<string, number | null>([...truth].map(([k, t]) => [k, t.ts]));
  const feedSev = new Map<string, string>(feed.map(e => [fid(e), String((e.payload as { severity?: string }).severity ?? "")]));

  // ── Per-incident detection (P0-1). An incident is DETECTED when any of its malicious
  // logs was escalated, or marked true_positive / suspicious (standing verdict).
  const escalatedAttack = new Map<string, number>();
  for (const e of escReq) { const eid = eidOf(e); if (!attackIds.has(eid)) continue; const t = tsOf(e) ?? Infinity; if (!escalatedAttack.has(eid) || t < escalatedAttack.get(eid)!) escalatedAttack.set(eid, t); }
  const standing = new Map<string, { eid: string; v: string; t: number | null }>();
  for (const d of dispEvents) standing.set(`${d.actor_id ?? ""}\u0000${eidOf(d)}`, { eid: eidOf(d), v: verdictOf(d), t: tsOf(d) });
  const markedAttack = new Map<string, number>();
  for (const s of standing.values()) {
    if (!attackIds.has(s.eid) || (s.v !== "true_positive" && s.v !== "suspicious")) continue;
    const t = s.t ?? Infinity; if (!markedAttack.has(s.eid) || t < markedAttack.get(s.eid)!) markedAttack.set(s.eid, t);
  }
  // Best standing verdict per attack log: a firm true_positive beats a hedged suspicious
  // (feeds each incident's verdict quality in the "good catch" grade).
  const attackVerdictKind = new Map<string, "tp" | "susp">();
  for (const s of standing.values()) {
    if (!attackIds.has(s.eid)) continue;
    if (s.v === "true_positive") attackVerdictKind.set(s.eid, "tp");
    else if (s.v === "suspicious" && !attackVerdictKind.has(s.eid)) attackVerdictKind.set(s.eid, "susp");
  }
  /** A malicious log is "surfaced" when the team escalated it or gave it a TP/suspicious verdict. */
  const flaggedAttack = (eid: string) => escalatedAttack.has(eid) || markedAttack.has(eid);
  const executedEids = new Set(events.filter(e => e.type === "containment.executed").map(eidOf));

  // ── v4: EDR host isolation (0082). A host is COMPROMISED when it carried at least one
  // real attack log; isolating it is right, isolating a clean host is a needless outage.
  const attackHosts = new Map<string, { host: string; logs: number; first: number | null; incidents: Set<string> }>();
  for (const fe of feed) {
    const t = truth.get(fid(fe)); const h = asStr((fe.payload as { hostname?: unknown }).hostname).trim();
    if (!t?.isAttack || !h) continue;
    const k = hostKey(h);
    const cur = attackHosts.get(k) ?? { host: h, logs: 0, first: null, incidents: new Set<string>() };
    cur.logs++;
    if (t.ts != null && (cur.first == null || t.ts < cur.first)) cur.first = t.ts;
    if (t.incident) cur.incidents.add(t.incident);
    attackHosts.set(k, cur);
  }
  const isoHost = (e: Ev) => asStr((e.payload as { host?: unknown }).host).trim();
  const isoEvents = events.filter(e => (e.type === "edr.host_isolated" || e.type === "edr.host_released") && isoHost(e))
    .sort((a, b) => a.seq - b.seq);
  const isoItems: IsolationItem[] = [];
  isoEvents.forEach((e, i) => {
    if (e.type !== "edr.host_isolated") return;
    const host = isoHost(e); const k = hostKey(host);
    const release = isoEvents.slice(i + 1).find(x => x.type === "edr.host_released" && hostKey(isoHost(x)) === k);
    const atk = attackHosts.get(k); const at = tsOf(e);
    isoItems.push({
      host, by: e.actor_id, atS: relS(at), releasedS: release ? relS(tsOf(release)) : null,
      verdict: atk ? "compromised" : "clean", correct: !!atk,
      timeToIsolateS: atk && atk.first != null && at != null ? Math.max(0, Math.round(runMs(atk.first, at) / 1000)) : null,
    });
  });
  /** First isolation per host (by anyone) — the team view; a re-isolation after a release isn't a new decision. */
  const isoFirstByHost = new Map<string, IsolationItem>();
  for (const it of isoItems) if (!isoFirstByHost.has(hostKey(it.host))) isoFirstByHost.set(hostKey(it.host), it);
  const isolatedIncidents = new Set([...isoFirstByHost.keys()].flatMap(k => [...(attackHosts.get(k)?.incidents ?? [])]));
  const incidentList: IncidentReport[] = [...incidents.values()].map(inc => {
    const minOf = (m: Map<string, number>) => { let best: number | null = null; for (const id of inc.attackEids) { const v = m.get(id); if (v != null && (best == null || v < best)) best = v; } return best; };
    const escTs = minOf(escalatedAttack); const markTs = minOf(markedAttack);
    const escalated = escTs != null; const detected = escalated || markTs != null;
    // Detection time = the EARLIEST detecting action, whether a TP/suspicious mark or an
    // escalation. The T1 flow requires a verdict BEFORE escalating, so using the escalation
    // time alone would charge the analyst's report-writing time against the SLA (Phase 9 P9-02).
    const detTs = [escTs, markTs].filter((t): t is number => t != null && Number.isFinite(t))
      .reduce<number | null>((a, b) => (a == null || b < a ? b : a), null);
    const contained = [...executedEids].some(eid => incidentOfEid(eid) === inc.id) || isolatedIncidents.has(inc.id);
    const detS = detTs != null ? relS(detTs) : null;
    const dwellS = detTs != null && inc.firstSeen != null ? Math.max(0, Math.round(runMs(inc.firstSeen, detTs) / 1000)) : null;

    // ── "Good catch" grade — the incident is built from several logs, so measure how much
    // of it the team surfaced (across logs, hosts AND techniques), not just whether one log
    // was flagged.
    const totalLogs = inc.attackEids.length;
    const flaggedEids = inc.attackEids.filter(flaggedAttack);
    const scopeCoverage = totalLogs ? Math.round((100 * flaggedEids.length) / totalLogs) : null;
    const hostsOf = (eids: string[]) => new Set(eids.map(e => hostKey(truth.get(e)?.host ?? "")).filter(Boolean));
    const techsOf = (eids: string[]) => new Set(eids.flatMap(e => [...techIds(truth.get(e)?.technique ?? "")].map(techBase)).filter(Boolean));
    const allHosts = hostsOf(inc.attackEids), flagHosts = hostsOf(flaggedEids);
    const allTechs = techsOf(inc.attackEids), flagTechs = techsOf(flaggedEids);
    const hostCoverage = allHosts.size ? Math.round((100 * flagHosts.size) / allHosts.size) : null;
    const techCoverage = allTechs.size ? Math.round((100 * flagTechs.size) / allTechs.size) : null;
    // Blend the coverage axes the incident actually has (log coverage is always present;
    // host/technique coverage only when the incident spans >0 of them).
    const covAxes = [scopeCoverage, hostCoverage, techCoverage].filter((x): x is number => x != null);
    const coverage = covAxes.length ? Math.round(covAxes.reduce((a, b) => a + b, 0) / covAxes.length) : (scopeCoverage ?? 0);
    const maxSeverity = inc.attackEids.reduce((best, e) => { const s = truth.get(e)?.severity ?? ""; return sevRank(s) > sevRank(best) ? s : best; }, "");
    const slaSec = slaForSev(maxSeverity);
    // Judge the SLA from when the incident's MAX-severity activity first appeared, not from an
    // earlier low-severity recon log — otherwise a kill chain whose first log looks benign is
    // always "past SLA" (Phase 9 P9-05). dwellS (MTTD) is still measured from the first log.
    const slaAnchor = inc.attackEids.reduce<number | null>((a, e) => {
      const t = truth.get(e); if (!t || t.ts == null || !Number.isFinite(t.ts) || sevRank(t.severity) !== sevRank(maxSeverity)) return a;
      return a == null || t.ts < a ? t.ts : a;
    }, null) ?? inc.firstSeen;
    const slaDwellS = detTs != null && slaAnchor != null ? Math.max(0, Math.round(runMs(slaAnchor, detTs) / 1000)) : null;
    const slaMet = slaDwellS == null ? null : slaDwellS <= slaSec;
    const verdictQ = inc.attackEids.some(e => attackVerdictKind.get(e) === "tp") ? 1
      : inc.attackEids.some(e => attackVerdictKind.get(e) === "susp") ? 0.5
        : escalated ? 0.25 : 0;
    const timeliness = slaDwellS == null ? 0 : slaDwellS <= slaSec ? 1 : slaDwellS <= 2 * slaSec ? 0.6 : 0.3;
    const handlingScore = !detected ? 0
      : Math.round(40 + 20 * timeliness + 25 * (coverage / 100) + 15 * verdictQ);
    const grade: IncidentGrade = !detected ? "missed"
      : (slaMet === true && coverage >= SCOPE_GOOD && verdictQ >= 1) ? "caught_well"
        : (coverage >= SCOPE_PARTIAL || slaMet === true || verdictQ >= 0.5) ? "partial"
          : "noticed";

    return {
      id: inc.id, label: inc.label.slice(0, 140), attackEvents: inc.attackEids.length, detected, escalated, contained,
      firstSeenS: relS(inc.firstSeen), detectS: detS, dwellS,
      scopeCoverage, hostCoverage, techCoverage, maxSeverity, slaSec, slaMet, handlingScore, grade,
    };
  }).sort((a, b) => (a.firstSeenS ?? 0) - (b.firstSeenS ?? 0));
  const incidentsDetected = incidentList.filter(i => i.detected).length;
  const incidentRecall = pct(incidentsDetected, incidentList.length);
  // Graded "good catch" tallies for the team headline.
  const incidentsCaughtWell = incidentList.filter(i => i.grade === "caught_well").length;
  const incidentsPartial = incidentList.filter(i => i.grade === "partial").length;
  const incidentsNoticed = incidentList.filter(i => i.grade === "noticed").length;
  const incidentsMissed = incidentList.filter(i => i.grade === "missed").length;
  const avgScopeCoverage = incidentList.length ? Math.round(incidentList.reduce((s, i) => s + (i.scopeCoverage ?? 0), 0) / incidentList.length) : null;
  const avgHandlingScore = incidentList.length ? Math.round(incidentList.reduce((s, i) => s + i.handlingScore, 0) / incidentList.length) : null;

  /** Escalation precision judged per INCIDENT: every distinct target is one row — a real
   *  incident (1, however many of its logs you escalated), the control log of a real
   *  incident (RELATED_CONTROL_CREDIT unless the incident is already credited), or a
   *  benign log (0). */
  const precisionOf = (escs: Ev[]): number | null => {
    const credit = new Map<string, number>();
    for (const e of escs) {
      const eid = eidOf(e);
      if (attackIds.has(eid)) { credit.set(`inc:${truth.get(eid)!.incident}`, 1); continue; }
      const inc = incidentOfEid(eid);
      if (inc) { const k = `inc:${inc}`; credit.set(k, Math.max(credit.get(k) ?? 0, RELATED_CONTROL_CREDIT)); continue; }
      credit.set(`evt:${eid}`, 0);
    }
    const vals = [...credit.values()];
    return vals.length ? Math.round((vals.reduce((s, n) => s + n, 0) / vals.length) * 100) : null;
  };

  const players = roster.filter(r => r.role !== "instructor" && r.role !== "observer");

  // ── Work-division / backup metrics (one ordered pass over the log) ────────────
  // Reconstructs each analyst's live load to detect: (a) T1 take-overs — credited ONLY
  // when the previous holder was overloaded (≥ OVERLOAD_CASES) or their claim had gone
  // stale (> CLAIM_TTL_MS, an abandoned alert); a plain collision earns nothing — the
  // same spirit as (b) T2/T3 backup (acking while a same-role peer is overloaded); and
  // (c) overload EPISODES lasting ≥ OVERLOAD_MIN_MS, for the Manager's load balancing.
  const roleByUser = new Map(players.map(p => [p.user_id, p.role]));
  const takeoverByUser = new Map<string, number>();
  const backupAckByUser = new Map<string, number>();
  const liveLoad = new Map<string, number>();
  const overloadSince = new Map<string, number>();
  const episodes = new Map<string, { start: number; end: number }[]>();
  const claimHolder = new Map<string, { by: string; at: number }>(); // live claims
  const staleClaim = new Map<string, { by: string; at: number }>();  // expired, never released
  const caseOwner = new Map<string, string>();
  const bump = (u: string, d: number, ts: number) => {
    if (!u) return;
    const before = liveLoad.get(u) ?? 0; const v = Math.max(0, before + d); liveLoad.set(u, v);
    if (before < OVERLOAD_CASES && v >= OVERLOAD_CASES) overloadSince.set(u, ts);
    if (before >= OVERLOAD_CASES && v < OVERLOAD_CASES) { const s = overloadSince.get(u); if (s != null) { if (!episodes.has(u)) episodes.set(u, []); episodes.get(u)!.push({ start: s, end: ts }); } overloadSince.delete(u); }
  };
  let lastTs = startedMs;
  for (const e of events) {
    const ts = e.occurred_at ? Date.parse(e.occurred_at) : lastTs; lastTs = Math.max(lastTs, ts);
    for (const [eid, c] of claimHolder) if (runMs(c.at, ts) > CLAIM_TTL_MS) { bump(c.by, -1, addActive(c.at, CLAIM_TTL_MS, spans)); claimHolder.delete(eid); staleClaim.set(eid, c); }
    if (e.type === "alert.claimed") {
      const eid = eidOf(e); if (!eid) continue; const who = e.actor_id ?? "";
      const live = claimHolder.get(eid); const stale = staleClaim.get(eid);
      const prev = live ?? stale;
      if (prev && prev.by !== who) {
        const prevOverloaded = !!live && (liveLoad.get(live.by) ?? 0) >= OVERLOAD_CASES;
        const wasStale = !live && !!stale;
        if (prevOverloaded || wasStale) takeoverByUser.set(who, (takeoverByUser.get(who) ?? 0) + 1);
        if (live) bump(live.by, -1, ts);
      }
      staleClaim.delete(eid);
      if (!live || live.by !== who) bump(who, 1, ts);
      claimHolder.set(eid, { by: who, at: ts }); // re-claim refreshes the TTL
    } else if (e.type === "alert.released" || e.type === "disposition.set" || e.type === "escalation.requested") {   // same claim-ending rule as the server + activeClaims
      const eid = eidOf(e); if (!eid) continue;
      const prev = claimHolder.get(eid)?.by;
      if (prev) { bump(prev, -1, ts); claimHolder.delete(eid); }
      staleClaim.delete(eid);
    } else if (e.type === "escalation.acknowledged") {
      const eid = eidOf(e); const who = e.actor_id ?? ""; if (!eid) continue;
      // Explicit backup take-over (0073 `takeover: true`) moves the case — same rule
      // as the live board's openLoadByUser; a plain second ack no longer happens.
      const prevOwner = caseOwner.get(eid);
      if (prevOwner) {
        if (!(e.payload as { takeover?: unknown }).takeover || prevOwner === who) continue;
        if (liveLoad.get(prevOwner) != null && (liveLoad.get(prevOwner) ?? 0) >= OVERLOAD_CASES) backupAckByUser.set(who, (backupAckByUser.get(who) ?? 0) + 1);
        bump(prevOwner, -1, ts); caseOwner.set(eid, who); bump(who, 1, ts);
        continue;
      }
      let teammateOverloaded = false; // a SAME-ROLE peer already drowning
      for (const [u, l] of liveLoad) if (u !== who && l >= OVERLOAD_CASES && roleByUser.get(u) === roleByUser.get(who)) { teammateOverloaded = true; break; }
      if (teammateOverloaded) backupAckByUser.set(who, (backupAckByUser.get(who) ?? 0) + 1);
      caseOwner.set(eid, who); bump(who, 1, ts);
    } else if (e.type === "escalation.resolved" || e.type === "escalation.bounced") {
      const eid = eidOf(e); const owner = eid ? caseOwner.get(eid) : undefined;
      if (owner) { bump(owner, -1, ts); caseOwner.delete(eid); }
    }
  }
  const ended = events.find(e => e.type === "session.ended");
  const endTs = Math.max(lastTs, ended?.occurred_at ? Date.parse(ended.occurred_at) : 0);
  for (const [u, s] of overloadSince) { if (!episodes.has(u)) episodes.set(u, []); episodes.get(u)!.push({ start: s, end: endTs }); }
  const realEpisodes = new Map([...episodes].map(([u, eps]) => [u, eps.filter(ep => runMs(ep.start, ep.end) >= OVERLOAD_MIN_MS)] as const).filter(([, eps]) => eps.length > 0));
  const backupByUser = new Map<string, number>();
  for (const p of players) backupByUser.set(p.user_id, (takeoverByUser.get(p.user_id) ?? 0) + (backupAckByUser.get(p.user_id) ?? 0));
  // Manager load balancing: of the analysts with a REAL overload episode, how many were
  // nudged during it (or within 5 min after)? Scores RESPONDING to overload, not volume.
  const NUDGE_GRACE = 5 * 60000;
  const nudges = events.filter(e => e.type === "coordination.nudge").map(e => ({ target: String((e.payload as { target?: string }).target), at: tsOf(e) }));
  const overloadedUsers = [...realEpisodes.keys()];
  const respondedTo = overloadedUsers.filter(u => nudges.some(n => n.target === u && (n.at == null || realEpisodes.get(u)!.some(ep => n.at! >= ep.start && n.at! <= addActive(ep.end, NUDGE_GRACE, spans)))));
  const loadBalanceRate = pct(respondedTo.length, overloadedUsers.length);

  // ── Help-desk tickets: the FIRST answer per ticket is judged on its decision; a later
  // answer to the same ticket earns nothing. Tickets = staff.inject kind "ticket".
  const tickets = events.filter(e => e.type === "staff.inject" && asStr((e.payload as { kind?: unknown }).kind) === "ticket")
    .map(e => ({ seq: e.seq, ts: tsOf(e), expected: expectedTicketDecision(e.payload) }));
  const ticketFirst = new Map<number, { actor: string; correct: boolean; ts: number | null; decision: string }>();
  const dupAnswersBy = new Map<string, number>();
  for (const a of events.filter(e => e.type === "ticket.answered")) {
    const p = a.payload as { ticket_seq?: unknown; decision?: unknown };
    let tk = p.ticket_seq != null ? tickets.find(t => t.seq === Number(p.ticket_seq)) : undefined;
    if (!tk && p.ticket_seq == null) { const at = tsOf(a); tk = tickets.find(t => !ticketFirst.has(t.seq) && (at == null || t.ts == null || t.ts <= at)) ?? tickets.find(t => t.ts == null || at == null || t.ts <= at); }
    if (!tk) continue;
    const who = a.actor_id ?? "";
    if (ticketFirst.has(tk.seq)) { dupAnswersBy.set(who, (dupAnswersBy.get(who) ?? 0) + 1); continue; }
    const decision = normDecision(p.decision);
    ticketFirst.set(tk.seq, { actor: who, correct: tk.expected == null || tk.expected === decision, ts: tsOf(a), decision });
  }
  const unansweredTickets = tickets.filter(t => !ticketFirst.has(t.seq)).length;

  // ── Elevations → hunts (T3). A hunt carrying the elevation's `event_id` answers it;
  // a legacy hunt with no event_id answers the latest elevation its author acked.
  const elevFirst = new Map<string, number | null>();
  for (const e of events) if (e.type === "elevation.requested") { const eid = eidOf(e); if (validEid(eid) && !elevFirst.has(eid)) elevFirst.set(eid, tsOf(e)); }
  const elevAckers = new Map<string, Set<string>>();
  const ackedInOrder = new Map<string, string[]>();
  const answeredBy = new Map<string, Set<string>>();
  for (const e of events) {
    const u = e.actor_id ?? "";
    if (e.type === "elevation.acknowledged") {
      const eid = eidOf(e); if (!elevFirst.has(eid)) continue;
      if (!elevAckers.has(eid)) elevAckers.set(eid, new Set()); elevAckers.get(eid)!.add(u);
      if (!ackedInOrder.has(u)) ackedInOrder.set(u, []); ackedInOrder.get(u)!.push(eid);
    } else if (e.type === "hunt.logged") {
      const set = answeredBy.get(u) ?? new Set<string>();
      const linked = eidOf(e);
      if (validEid(linked)) { if (elevFirst.has(linked)) set.add(linked); }
      else { const cand = [...(ackedInOrder.get(u) ?? [])].reverse().find(x => !set.has(x)); if (cand) set.add(cand); }
      answeredBy.set(u, set);
    }
  }
  const answeredAny = new Set([...answeredBy.values()].flatMap(s => [...s]));

  // ── Containment requests (T2 quality) — team-wide, ordered.
  const contEvents = events.filter(e => e.type === "containment.requested" || e.type === "containment.approved" || e.type === "containment.denied" || e.type === "containment.executed");
  const normTarget = (v: unknown) => asStr(v).trim().toLowerCase();
  /** 0.5 pending · 0.75 approved · 1.0 executed after approval · 0 denied; a request later
   *  re-targeted on the same case (a different target) is capped at 0.25. */
  const containmentCredit = (req: Ev): number => {
    const eid = eidOf(req); const idx = contEvents.indexOf(req); const target = normTarget((req.payload as { target?: unknown }).target);
    let credit = 0.5; let approved = false; let retargeted = false;
    for (let i = idx + 1; i < contEvents.length; i++) {
      const x = contEvents[i]; if (eidOf(x) !== eid) continue;
      if (x.type === "containment.requested") { if (normTarget((x.payload as { target?: unknown }).target) !== target) retargeted = true; break; }
      if (x.type === "containment.denied" && !approved) { credit = 0; break; }
      if (x.type === "containment.approved") { approved = true; credit = 0.75; }
      if (x.type === "containment.executed" && approved) { credit = 1; }
    }
    return retargeted ? Math.min(credit, 0.25) : credit;
  };
  const reportVerdictClass = (v: unknown) => { const s = asStr(v).toLowerCase(); return ["true_positive", "escalate", "suspicious", "tp"].includes(s) ? "attack" : ["false_positive", "benign", "fp"].includes(s) ? "benign" : null; };
  const caseTruth = (eid: string) => (!truth.has(eid) ? null : attackIds.has(eid) || incidentOfEid(eid) ? "attack" : "benign");

  // Bounced + acknowledged ⇒ the handoff loop was CLOSED (a bounce is an explicit answer).
  const escAckedIds = new Set(events.filter(e => e.type === "escalation.acknowledged").map(eidOf));
  const escBouncedIds = new Set(events.filter(e => e.type === "escalation.bounced").map(eidOf));
  const escResolvedIds = new Set(events.filter(e => e.type === "escalation.resolved").map(eidOf));

  // Team-wide action counts (for firstAction / contribution only).
  const mgmtInjects = events.filter(e => e.type === "staff.inject" && String((e.payload as { kind?: string }).kind) === "mgmt_pressure");
  const tms = (es: Ev[]) => es.map(e => (e.occurred_at ? Date.parse(e.occurred_at) : NaN)).filter(n => Number.isFinite(n));

  // ── v3: first triage action per log (any analyst) + per-log SLA ───────────────
  // "Triaged" = the first disposition OR escalation anyone made on the log.
  const firstTriage = new Map<string, number>();
  for (const e of events) {
    if (e.type !== "disposition.set" && e.type !== "escalation.requested") continue;
    if (e.type === "disposition.set" && !isValidDisp(e)) continue;
    const eid = eidOf(e); const t = tsOf(e); if (!truth.has(eid) || t == null) continue;
    if (!firstTriage.has(eid) || t < firstTriage.get(eid)!) firstTriage.set(eid, t);
  }
  const sevOf = (eid: string) => (feedSev.get(eid) || "informational").toLowerCase();
  const labelOf = (eid: string) => (truth.get(eid)?.label ?? "event").slice(0, 140);
  const truthClass = (eid: string): "attack" | "related" | "benign" => attackIds.has(eid) ? "attack" : incidentOfEid(eid) ? "related" : "benign";
  const missItem = (eid: string, detail?: string): MissItem => ({ label: labelOf(eid), severity: sevOf(eid), arrivedS: relS(feedTs.get(eid) ?? null), ...(detail ? { detail } : {}) });
  const escalatedBy = new Map<string, Set<string>>();   // eid → who escalated it
  for (const e of escReq) { const eid = eidOf(e); if (!escalatedBy.has(eid)) escalatedBy.set(eid, new Set()); escalatedBy.get(eid)!.add(e.actor_id ?? ""); }
  const caughtByAnyone = (eid: string) => escalatedBy.has(eid) || markedAttack.has(eid);
  const escOutcome = (eid: string): ReportedItem["outcome"] =>
    escResolvedIds.has(eid) ? "resolved" : escBouncedIds.has(eid) ? "bounced" : escAckedIds.has(eid) ? "acknowledged" : "open";

  const detectedIncidents = new Set(incidentList.filter(i => i.detected).map(i => i.id));
  const t1Count = players.filter(p => p.role === "t1" && p.status !== "left").length || players.filter(p => p.role === "t1").length;
  const perUser: UserReport[] = players.map(m => {
    const mine = events.filter(e => e.actor_id === m.user_id);
    // event.opened carries { event_id, dwell_ms }; count DISTINCT ids opened, max dwell per id.
    const openedEvents = mine.filter(e => e.type === "event.opened");
    const dwellByEid = new Map<string, number>();
    for (const e of openedEvents) {
      const eid = eidOf(e); if (!eid) continue;
      const d = Number((e.payload as { dwell_ms?: number }).dwell_ms ?? 0);
      dwellByEid.set(eid, Math.max(dwellByEid.get(eid) ?? 0, Number.isFinite(d) ? d : 0));
    }
    const opened = dwellByEid.size || openedEvents.length;
    const dwellVals = [...dwellByEid.values()].filter(d => d > 0);
    const avgDwellS = dwellVals.length ? Math.round(dwellVals.reduce((s, d) => s + d, 0) / dwellVals.length / 1000) : null;

    // Accuracy over DISTINCT logs keeping the LATEST verdict (a wrong→right correction
    // never costs score). corrections = logs first called at zero credit and later
    // fixed to ≥ half credit (e.g. benign→suspicious on an attack is a real correction).
    const disp = mine.filter(isValidDisp);
    const latestVerdict = new Map<string, string>();
    const everZero = new Set<string>(); const corrected = new Set<string>();
    for (const d of disp) {
      const eid = eidOf(d); const v = verdictOf(d); const c = verdictCredit(eid, v);
      if (c === 0) everZero.add(eid); else if (everZero.has(eid) && c >= 0.5) corrected.add(eid);
      latestVerdict.set(eid, v);
    }
    const distinctDisp = latestVerdict.size;
    let credit = 0; let dispCorrect = 0; let dispUnopened = 0; let dispWrong = 0;
    for (const [eid, v] of latestVerdict) {
      const c = verdictCredit(eid, v); if (c === 1) dispCorrect++; else if (c === 0) dispWrong++;
      const wasOpened = !telemetry || dwellByEid.has(eid);
      if (!wasOpened) dispUnopened++;
      credit += c * (wasOpened ? 1 : UNOPENED_DISPOSITION_WEIGHT);
    }
    const correctionsCount = corrected.size;

    // Balanced accuracy (see SEV_WEIGHT). Escalating an attack log is an attack call (full
    // credit) even without a separate verdict; a benign/control log keeps its verdict credit.
    const myAttackEsc = new Set(mine.filter(e => e.type === "escalation.requested").map(eidOf).filter(eid => attackIds.has(eid)));
    const openFactor = (eid: string) => (!telemetry || dwellByEid.has(eid) ? 1 : UNOPENED_DISPOSITION_WEIGHT);
    let atkNum = 0, atkDen = 0, benNum = 0, benDen = 0;
    const atkHandled = new Set<string>([...myAttackEsc, ...[...latestVerdict.keys()].filter(eid => attackIds.has(eid))]);
    for (const eid of atkHandled) {
      const w = sevWeight(truth.get(eid)?.severity ?? "");
      const c = myAttackEsc.has(eid) ? 1 : verdictCredit(eid, latestVerdict.get(eid)!);
      atkNum += w * c * openFactor(eid); atkDen += w;
    }
    // Opened an attack log, took no action, and nobody else caught it: a weighted miss.
    for (const eid of dwellByEid.keys()) {
      if (!attackIds.has(eid) || atkHandled.has(eid) || caughtByAnyone(eid)) continue;
      const inc = incidentOfEid(eid);
      atkDen += sevWeight(truth.get(eid)?.severity ?? "") * (inc && detectedIncidents.has(inc) ? DETECTED_INCIDENT_MISS_WEIGHT : 1);
    }
    for (const [eid, v] of latestVerdict) {
      if (attackIds.has(eid)) continue;
      benNum += verdictCredit(eid, v) * openFactor(eid); benDen += 1;
    }
    const attackHandling = atkDen ? Math.round((atkNum / atkDen) * 100) : null;
    const benignAcc = benDen ? Math.round((benNum / benDen) * 100) : null;
    const dispAcc = attackHandling != null && benignAcc != null ? Math.round((attackHandling + benignAcc) / 2)
      : attackHandling ?? benignAcc;
    const dispNoAttack = attackHandling == null && benignAcc != null;
    // Share of the load (Tier-1): distinct logs you triaged vs a fair share of the feed.
    const loadHandled = new Set<string>([...latestVerdict.keys(), ...mine.filter(e => e.type === "escalation.requested").map(eidOf).filter(eid => truth.has(eid))]).size;
    const loadFair = m.role === "t1" && t1Count > 0 ? feed.length / t1Count : 0;
    const loadSharePct = loadFair > 0 ? Math.round((loadHandled / loadFair) * 100) : null;
    const dwellTooShort = telemetry && avgDwellS != null && avgDwellS < MIN_EVIDENCE_DWELL_S && distinctDisp > 0;

    const esc = mine.filter(e => e.type === "escalation.requested");
    const escQuality = esc.length ? Math.round(esc.reduce((s, e) => s + escQualityScore(e.payload), 0) / esc.length) : null;
    // QA H2/M6: activity counts DISTINCT work — the same log re-judged, the same escalation
    // re-acknowledged, the same action repeated, a free-text note: none of them farm XP.
    const acks = new Set(mine.filter(e => e.type === "escalation.acknowledged").map(eidOf)).size;
    const myContReq = mine.filter(e => e.type === "containment.requested");
    const contDecided = new Set(mine.filter(e => e.type === "containment.approved" || e.type === "containment.denied").map(eidOf)).size;
    const roleActions = new Set(mine.filter(e => ROLE_ACTION_TYPES.has(e.type) && e.type !== "note.added").map(e => `${e.type}:${eidOf(e)}`)).size;
    const actionTimes = mine.filter(e => e.occurred_at && e.type !== "member.ready").map(e => Date.parse(e.occurred_at!));
    const firstActionS = actionTimes.length ? relS(Math.min(...actionTimes)) : null;
    const contribution = Math.min(100, opened * 3 + distinctDisp * 6 + esc.length * 15 + acks * 10 + myContReq.length * 15 + contDecided * 20 + roleActions * 15);

    const escPrecision = esc.length ? precisionOf(esc) : null;
    const escAckRate = esc.length ? pct(esc.filter(e => { const id = eidOf(e); return escAckedIds.has(id) || escBouncedIds.has(id); }).length, esc.length) : null;
    const triageMin = median(disp.map(d => {
      const eid = eidOf(d); const sev = feedSev.get(eid); if (sev !== "high" && sev !== "critical") return null;
      const ft = feedTs.get(eid); const dt = tsOf(d);
      return ft != null && dt != null ? runMs(ft, dt) / 60000 : null;
    }).filter((x): x is number => x != null && x >= 0));
    const ackLatencyMin = median(mine.filter(e => e.type === "escalation.acknowledged" && !selfOpened.has(eidOf(e))).map(e => {
      const at = tsOf(e); if (at == null) return null; const rt = reqBefore(escTimes, eidOf(e), at);
      return rt != null ? runMs(rt, at) / 60000 : null;
    }).filter((x): x is number => x != null && x >= 0));
    const approvalLatencyMin = median(mine.filter(e => e.type === "containment.approved").map(e => {
      const at = tsOf(e); if (at == null) return null; const rt = reqBefore(contTimes, eidOf(e), at);
      return rt != null ? runMs(rt, at) / 60000 : null;
    }).filter((x): x is number => x != null && x >= 0));

    // T3 hunts.
    const hunts = mine.filter(e => e.type === "hunt.logged");
    const huntTech = hunts.filter(e => techIds((e.payload as { technique?: unknown }).technique).length > 0).length;
    const huntQuality = hunts.length ? Math.round(hunts.reduce((s, e) => s + huntQualityScore(e.payload, caseEntities, caseTechBases), 0) / hunts.length) : null;
    const noteCount = mine.filter(e => e.type === "note.added").length;
    const myAnswered = answeredBy.get(m.user_id) ?? new Set<string>();
    const myAckedElev = [...elevAckers].filter(([, us]) => us.has(m.user_id)).map(([k]) => k);
    const orphanElev = [...elevFirst.keys()].filter(k => !elevAckers.has(k) && !answeredAny.has(k));
    const elevDenom = new Set([...myAckedElev, ...myAnswered, ...orphanElev]);
    const elevAnsweredPct = pct([...elevDenom].filter(k => myAnswered.has(k)).length, elevDenom.size);

    // DE rules.
    const rules = mine.filter(e => e.type === "rule.published");
    const ruleMatched = rules.reduce((s, e) => s + Number((e.payload as { matched?: number }).matched ?? 0), 0);
    const ruleTechniques = new Set(rules.map(e => String((e.payload as { technique?: string }).technique ?? "")).filter(Boolean)).size;
    const ruleDocRate = rules.length ? pct(rules.filter(e => String((e.payload as { keyword?: string }).keyword ?? "").trim()).length, rules.length) : null;

    // TI — substance, not non-empty fields.
    const intel = mine.filter(e => e.type === "intel.published");
    const intelAttrib = intel.length ? pct(intel.filter(e => {
      const p = e.payload as Record<string, unknown>;
      if (!substantive(p.actor)) return false;
      const related = techIds(p.technique).some(t => caseTechBases.has(techBase(t)))
        || mentions(`${asStr(p.technique)} ${asStr(p.ioc)}`, caseEntities);
      return related;
    }).length, intel.length) : null;
    const nextEvaluable = intel.map(e => {
      const at = tsOf(e);
      const later = [...attackIds].map(id => truth.get(id)!).filter(t => at == null || t.ts == null || t.ts > at);
      if (!later.length) return null; // nothing arrived afterwards — can't judge this prediction
      const p = e.payload as Record<string, unknown>;
      const nx = asStr(p.next_expected);
      if (!substantive(nx, 3)) return false;
      const laterBases = new Set(later.flatMap(t => techIds(t.technique).map(techBase)));
      const laterTactics = [...new Set(later.map(t => t.tactic.trim().toLowerCase()).filter(s => s.length >= 5))];
      const laterTokens = [...new Set(later.flatMap(t => [...t.tokens]))].filter(k => !isCommon(k));
      return techIds(nx).some(t => laterBases.has(techBase(t))) || mentions(nx, laterTactics) || mentions(nx, laterTokens);
    }).filter((x): x is boolean => x != null);
    const intelNext = nextEvaluable.length ? pct(nextEvaluable.filter(Boolean).length, nextEvaluable.length) : null;
    const withIoc = intel.filter(e => asStr((e.payload as { ioc?: unknown }).ioc).trim().length >= 3);
    const attackTokenSet = new Set(caseEntities);
    const iocPrecision = withIoc.length ? pct(withIoc.filter(e => {
      const ioc = asStr((e.payload as { ioc?: unknown }).ioc).trim().toLowerCase();
      return attackTokenSet.has(ioc) || caseEntities.some(k => k.length >= 6 && (k.includes(ioc) || ioc.includes(k)));
    }).length, withIoc.length) : null;

    // T2 containment + report.
    const contReason = myContReq.length ? pct(myContReq.filter(e => String((e.payload as { reason?: string }).reason ?? "").trim().length >= 10).length, myContReq.length) : null;
    const contQuality = myContReq.length ? Math.round((myContReq.reduce((s, e) => s + containmentCredit(e), 0) / myContReq.length) * 100) : null;
    const reports = mine.filter(e => e.type === "report.submitted");
    const reportQuality = reports.length ? Math.round(reports.reduce((s, e) => s + reportQualityScore(e.payload), 0) / reports.length) : null;
    const judged = reports.map(e => { const t = caseTruth(eidOf(e)); const v = reportVerdictClass((e.payload as { verdict?: unknown }).verdict); return t && v ? t === v : null; }).filter((x): x is boolean => x != null);
    const reportAcc = judged.length ? pct(judged.filter(Boolean).length, judged.length) : null;

    // Scope (dims = hosts/users/techniques filled in this user's best scope event).
    const dimsOf = (e: Ev) => { const p = e.payload as { hosts?: string[]; users?: string[]; techniques?: string[] }; return (p.hosts?.length ? 1 : 0) + (p.users?.length ? 1 : 0) + (p.techniques?.length ? 1 : 0); };
    const scopeSets = mine.filter(e => e.type === "scope.set");
    const scopeConfirms = mine.filter(e => e.type === "scope.confirmed");
    const scopeSetDims = scopeSets.length ? Math.max(...scopeSets.map(dimsOf)) : 0;
    const scopeConfirmDims = scopeConfirms.length ? Math.max(...scopeConfirms.map(dimsOf)) : 0;
    const decisions = mine.filter(e => e.type === "decision.logged");
    const decisionRationaleRate = decisions.length ? pct(decisions.filter(e => String((e.payload as { rationale?: string }).rationale ?? "").trim().length >= 5).length, decisions.length) : null;

    // Help-desk: correct first answers ÷ (my first answers + tickets nobody answered).
    const myFirst = [...ticketFirst.values()].filter(a => a.actor === m.user_id);
    const helpDenom = myFirst.length + (m.role === "t1" ? unansweredTickets : 0);
    const helpdeskPct = helpDenom ? pct(myFirst.filter(a => a.correct).length, helpDenom) : null;
    const helpdeskDupOnly = !myFirst.length && (dupAnswersBy.get(m.user_id) ?? 0) > 0;

    const sitrepCount = mine.filter(e => e.type === "sitrep.sent").length;
    // T3 hypothesis→conclusion: per scope confirmation, the LATEST hunt before it → it.
    const huntTs = tms(hunts).sort((a, b) => a - b);
    const huntToConfirmMin = median(tms(scopeConfirms).map(ct => { let best: number | null = null; for (const h of huntTs) if (h <= ct) best = h; return best != null ? runMs(best, ct) / 60000 : null; }).filter((x): x is number => x != null));
    const caseAssigns = mine.filter(e => e.type === "case.assigned");
    const caseOwnedMin = tms(caseAssigns).length ? Math.max(0, runMs(startedMs, Math.min(...tms(caseAssigns))) / 60000) : null;
    // Mgmt pressure: each inject paired one-to-one with a DISTINCT following SITREP (≤15 min).
    const injTs = tms(mgmtInjects).sort((a, b) => a - b);
    const sitrepPool = tms(mine.filter(e => e.type === "sitrep.sent")).sort((a, b) => a - b);
    const MGMT_WINDOW = 15 * 60000;
    let mgmtAnswered = 0;
    for (const it of injTs) { const idx = sitrepPool.findIndex(st => st >= it && runMs(it, st) <= MGMT_WINDOW); if (idx !== -1) { mgmtAnswered++; sitrepPool.splice(idx, 1); } }
    const mgmtRespondedRate = pct(mgmtAnswered, mgmtInjects.length);

    // ── v3: SLA per reported event ──
    const firstEsc = new Map<string, number>();
    for (const e of esc) { const eid = eidOf(e); const t = tsOf(e); if (!truth.has(eid) || t == null) continue; if (!firstEsc.has(eid) || t < firstEsc.get(eid)!) firstEsc.set(eid, t); }
    const firstDispHigh = new Map<string, { t: number; v: string }>();
    for (const d of disp) {
      const eid = eidOf(d); const t = tsOf(d); const sev = sevOf(eid);
      if (t == null || firstEsc.has(eid) || (sev !== "high" && sev !== "critical")) continue;
      if (!firstDispHigh.has(eid) || t < firstDispHigh.get(eid)!.t) firstDispHigh.set(eid, { t, v: verdictOf(d) });
    }
    const asItem = (eid: string, t: number, kind: ReportedItem["kind"], verdict?: string): ReportedItem => {
      const arr = feedTs.get(eid) ?? null; const sev = sevOf(eid); const slaS = slaSecFor(sev);
      const responseS = arr != null ? Math.max(0, Math.round(runMs(arr, t) / 1000)) : null;
      return {
        label: labelOf(eid), severity: sev, kind, arrivedS: relS(arr), actedS: relS(t), responseS, slaS,
        withinSla: responseS == null ? null : responseS <= slaS, truth: truthClass(eid),
        ...(kind === "escalation" ? { outcome: escOutcome(eid) } : {}), ...(verdict ? { verdict } : {}),
      };
    };
    const reportedAll = [
      ...[...firstEsc].map(([eid, t]) => asItem(eid, t, "escalation")),
      ...[...firstDispHigh].map(([eid, x]) => asItem(eid, x.t, "triage", x.v)),
    ].sort((a, b) => (a.actedS ?? 0) - (b.actedS ?? 0));
    const slaJudged = reportedAll.filter(r => r.withinSla != null);
    const slaMet = slaJudged.filter(r => r.withinSla).length;

    // ── v3: misses ──
    const falseNegatives = [...latestVerdict].filter(([eid, v]) => attackIds.has(eid) && (v === "benign" || v === "false_positive"))
      .map(([eid, v]) => missItem(eid, `called it ${v.replace("_", " ")}`));
    const walkedPast = [...dwellByEid.keys()].filter(eid => attackIds.has(eid) && !latestVerdict.has(eid) && !firstEsc.has(eid) && !caughtByAnyone(eid))
      .map(eid => { const inc = incidentOfEid(eid); return missItem(eid, inc && detectedIncidents.has(inc)
        ? "opened, no action — the incident was caught through another log, but this evidence was never marked"
        : "opened, no action — and nobody else caught it"); });
    const alarmEids = new Set<string>([
      ...[...firstEsc.keys()].filter(eid => truthClass(eid) === "benign"),
      ...[...latestVerdict].filter(([eid, v]) => v === "true_positive" && truthClass(eid) === "benign").map(([eid]) => eid),
    ]);
    const falseAlarms = [...alarmEids].map(eid => missItem(eid, firstEsc.has(eid) ? "escalated a benign log" : "called a benign log a true positive"));

    // ── v4: hosts this analyst isolated (first isolation per host), judged.
    const myIso: IsolationItem[] = [];
    for (const it of isoItems) if (it.by === m.user_id && !myIso.some(x => hostKey(x.host) === hostKey(it.host))) myIso.push(it);
    const isoCorrect = myIso.filter(x => x.correct).length;
    const isoPct = pct(isoCorrect, myIso.length);

    const rubric = roleRubric({
      role: m.role, dispAcc, dispNoAttack, loadSharePct, loadHandled, loadFair, escAckRate, escPrecision, escQuality, triageMin, dwellTooShort, ackLatencyMin, approvalLatencyMin,
      huntCount: hunts.length, huntTech, huntQuality, noteCount, elevAnsweredPct,
      rulePublished: rules.length, ruleMatched, ruleTechniques, ruleDocRate,
      intelAttrib, intelNext, iocPrecision, contReason, contQuality, reportAcc, isoPct,
      scopeSetDims, scopeConfirmDims, scopeConfirmed: scopeConfirms.length > 0,
      decisionCount: decisions.length, decisionRationaleRate,
      helpdeskPct, helpdeskDupOnly, sitrepCount, reportQuality,
      huntToConfirmMin, caseOwnedMin, mgmtRespondedRate,
      backupCount: backupByUser.get(m.user_id) ?? 0, loadBalanceRate, correctionsCount,
    });
    const measuredCells = rubric.filter(c => c.score != null).length;
    return {
      user_id: m.user_id, name: m.name, role: m.role, opened, avgDwellS,
      dispCount: disp.length, dispCorrect, dispAcc, attackHandling, benignAcc, loadSharePct, dispUnopened, dispDistinct: distinctDisp, dispWrong,
      escCount: esc.length, escQuality, acks, contReq: myContReq.length, contDecided, roleActions, firstActionS, contribution,
      rubric, rubricPct: rubricPercent(rubric),
      measuredCells, insufficientEvidence: rubric.length > 0 && measuredCells < MIN_MEASURED_CELLS,
      reported: reportedAll.slice(0, REPORTED_CAP),
      slaMet, slaTotal: slaJudged.length, slaPct: pct(slaMet, slaJudged.length),
      falseNegatives: falseNegatives.slice(0, MISS_CAP),
      walkedPast: walkedPast.slice(0, MISS_CAP),
      falseAlarms: falseAlarms.slice(0, MISS_CAP),
      isolations: myIso.slice(0, MISS_CAP), isoCorrect, isoPct,
    };
  });


  // ── Team detection. MTTD = the FIRST correct escalation of any malicious log.
  // MTTD matches per-incident detection: the earliest escalation OR TP/suspicious mark of any
  // attack log (was escalation-only, which showed "detected 1/1" next to "MTTD —" — Phase 9 P9-F).
  const firstDetect = Math.min(...[...escalatedAttack.values(), ...markedAttack.values()].filter(Number.isFinite), Infinity);
  const detected = incidentList.length ? incidentsDetected > 0 : escalatedAttack.size > 0;
  // MTTD is measured from the first attack log reaching the feed, not from shift start — a warm-up
  // of benign traffic before the attack must not be charged to the team (diagnostic P1).
  const firstAttackFeedMs = Math.min(...[...attackIds].map(id => feedTs.get(id)).filter((t): t is number => t != null), Infinity);
  const timeToDetectS = Number.isFinite(firstDetect)
    ? (Number.isFinite(firstAttackFeedMs) ? Math.max(0, Math.round(runMs(firstAttackFeedMs, firstDetect) / 1000)) : relS(firstDetect))
    : null;
  // Team disposition accuracy over DISTINCT logs (latest verdict, suspicious = partial).
  const teamLatestVerdict = new Map<string, string>();
  for (const d of dispEvents) teamLatestVerdict.set(eidOf(d), verdictOf(d));
  const dispDistinct = teamLatestVerdict.size;
  const teamCredit = [...teamLatestVerdict].reduce((s, [eid, v]) => s + verdictCredit(eid, v), 0);

  // Handoff loop closure: an escalated log is CLOSED once a Tier-2 acknowledged, bounced
  // (an explicit answer back to T1) or resolved it. Set-based, junk ids excluded.
  const escEidSet = new Set(escReq.map(eidOf).filter(validEid));
  const loopClosurePct = pct([...escEidSet].filter(id => escAckedIds.has(id) || escBouncedIds.has(id) || escResolvedIds.has(id)).length, escEidSet.size);

  // MTTR: median Δ(FIRST escalation → escalation.resolved) per resolved log.
  const mttrS = median(events.filter(e => e.type === "escalation.resolved").map(e => {
    const rt = escTimes.get(eidOf(e))?.[0]; const at = tsOf(e);
    return rt != null && at != null ? runMs(rt, at) / 1000 : null;
  }).filter((x): x is number => x != null && x >= 0));
  // Handoff latency (team MTTA): per log, first ack − the request it acknowledged.
  const ackFirstTs = new Map<string, number>();
  for (const e of events.filter(x => x.type === "escalation.acknowledged" && !selfOpened.has(eidOf(x)))) { const eid = eidOf(e); const at = tsOf(e); if (at != null && !ackFirstTs.has(eid)) ackFirstTs.set(eid, at); }
  const handoffLatS = median([...ackFirstTs].map(([eid, at]) => { const rt = reqBefore(escTimes, eid, at); return rt != null ? runMs(rt, at) / 1000 : null; }).filter((x): x is number => x != null && x >= 0));

  // ── Evaluable MSEL injects ─────────────────────────────────────────────────────
  // mgmt pressure → a SITREP within 15 min (one-to-one). ticket → the first answer's
  // DECISION must be right. twist → handled only if a response references the inject's
  // supporting telemetry (feed events with supports_inject = its MSEL id) or the team
  // re-scopes after that telemetry lands; no supporting telemetry ⇒ "not evaluable".
  // false_lead (decoy) → handled when nobody escalated its supporting benign events.
  const INJECT_WINDOW = 15 * 60000;
  const sitrepAts = tms(events.filter(e => e.type === "sitrep.sent")).sort((a, b) => a - b);
  const usedS = new Set<number>();
  const supportsByKey = new Map<string, string[]>();
  for (const [eid, t] of truth) if (t.supports) { if (!supportsByKey.has(t.supports)) supportsByKey.set(t.supports, []); supportsByKey.get(t.supports)!.push(eid); }
  const scopeChanges: number[] = [];
  let prevSig = "";
  for (const e of events) {
    if (e.type !== "scope.set" && e.type !== "scope.confirmed") continue;
    const p = e.payload as { hosts?: unknown[]; users?: unknown[]; techniques?: unknown[] };
    const sig = JSON.stringify([p.hosts ?? [], p.users ?? [], p.techniques ?? []]);
    const at = tsOf(e); if (sig !== prevSig && at != null) scopeChanges.push(at);
    prevSig = sig;
  }
  const RESPONSE_TYPES = new Set(["escalation.requested", "elevation.requested", "hunt.logged", "report.submitted", "containment.requested", "note.added", "scope.set", "scope.confirmed", "case.status_set", "intel.published", "decision.logged", "sitrep.sent", "evidence.pinned"]);
  const NOT_EVALUABLE = "not evaluable — no supporting telemetry for it in the feed";
  // A role must exist to own a management inject — with no SOC Manager / Lead / Tier-3 in the room,
  // a CISO/Legal/Exec SITREP request is skipped, not counted missed (diagnostic P1).
  const hasSenior = players.some(p => ["mgr", "lead", "ti", "t3"].includes(p.role));
  const injectResults: InjectResult[] = events.filter(e => e.type === "staff.inject").map(e => {
    const p = e.payload as { id?: string; original_id?: string; kind?: string; text?: string; expected_response?: string; linked_objective?: string };
    const kind = String(p.kind ?? ""); const at = tsOf(e);
    const base = { kind, text: asStr(p.text), expected: asStr(p.expected_response), objective: asStr(p.linked_objective), decoy: false, evaluable: true };
    if (kind === "announcement") return { ...base, scored: false, handled: true };
    const key = asStr(p.original_id) || asStr(p.id);
    // Only a scripted MSEL row (it carries an id) may fall back to msel_<kind> telemetry —
    // an instructor-typed curveball must not borrow the script's logs from another time.
    const sup = supportsByKey.get(key) ?? (key ? supportsByKey.get(`msel_${kind}`) : undefined) ?? [];
    const supSet = new Set(sup);
    if (kind === "false_lead") {
      if (!sup.length) return { ...base, decoy: true, scored: false, handled: false, evaluable: false, note: NOT_EVALUABLE };
      const chased = escReq.some(x => supSet.has(eidOf(x)));
      // Handling a decoy is an EXPLICIT call, not silence: the team must disposition its telemetry
      // benign / FP (or answer the inject) AND not escalate it. Doing nothing is not "handled".
      const dispositionedBenign = dispEvents.some(x => supSet.has(eidOf(x)) && ["benign", "false_positive"].includes(verdictOf(x)));
      const answered = at != null && sitrepAts.some(t => t >= at && runMs(at, t) <= INJECT_WINDOW);
      const acted = dispositionedBenign || answered;
      return { ...base, decoy: true, scored: true, handled: acted && !chased,
        note: chased ? "the team escalated the decoy's benign telemetry (over-escalation)" : acted ? "the team identified it as benign" : "no explicit call — the decoy was neither dispositioned benign nor answered" };
    }
    if (kind === "twist") {
      if (!sup.length) return { ...base, scored: false, handled: false, evaluable: false, note: NOT_EVALUABLE };
      const tokens = [...new Set(sup.flatMap(id => [...truth.get(id)!.tokens]))].filter(k => !isCommon(k));
      const supTimes = sup.map(id => truth.get(id)!.ts).filter((x): x is number => x != null);
      const firstSup = supTimes.length ? Math.min(...supTimes) : null;
      const from = at ?? -Infinity;
      const until = addActive(Math.max(at ?? 0, firstSup ?? 0), INJECT_WINDOW, spans);
      const inWin = (t: number | null) => t != null && t >= from && t <= until;
      const referenced = events.some(x => {
        if (!x.actor_id || !inWin(tsOf(x))) return false;
        if (x.type === "disposition.set") return supSet.has(eidOf(x)) && ["true_positive", "suspicious"].includes(verdictOf(x));
        if (!RESPONSE_TYPES.has(x.type)) return false;
        return supSet.has(eidOf(x)) || mentions(JSON.stringify(x.payload ?? {}), tokens);
      });
      const rescoped = !referenced && firstSup != null && scopeChanges.some(t => inWin(t) && t >= firstSup);
      return { ...base, scored: true, handled: referenced || rescoped, note: referenced ? "a response referenced the new telemetry" : rescoped ? "the team re-scoped after the new telemetry landed" : "no response referenced the new telemetry" };
    }
    if (kind === "ticket") {
      const tk = ticketFirst.get(e.seq);
      if (!tk) return { ...base, scored: true, handled: false, note: "the ticket was never answered" };
      const onTime = at == null || tk.ts == null || runMs(at, tk.ts) <= INJECT_WINDOW;
      return { ...base, scored: true, handled: tk.correct && onTime, note: !tk.correct ? `answered "${tk.decision}" — the wrong call` : onTime ? `answered "${tk.decision}" — the right call` : "answered after the 15-min window" };
    }
    if (kind === "mgmt_pressure" && !hasSenior) return { ...base, scored: false, handled: false, evaluable: false, note: "no SOC Manager / senior in the team to own this — skipped" };
    let handled = false;
    if (at != null) { const idx = sitrepAts.findIndex((t, i) => !usedS.has(i) && t >= at && runMs(at, t) <= INJECT_WINDOW); if (idx !== -1) { usedS.add(idx); handled = true; } }
    return { ...base, scored: true, handled };
  });
  const scoredInjects = injectResults.filter(i => i.scored);
  const injectsHandled = scoredInjects.filter(i => i.handled).length;

  // ── Shared-picture coherence: CONTESTED when two analysts gave contradictory
  // verdict classes (attack vs benign) on the same log. `suspicious` is neither.
  const vClass = (v: string) => v === "true_positive" ? "attack" : (v === "false_positive" || v === "benign") ? "benign" : "other";
  const verdictsByEid = new Map<string, Map<string, string>>();
  for (const d of dispEvents) {
    const eid = eidOf(d); const who = d.actor_id ?? "";
    if (!verdictsByEid.has(eid)) verdictsByEid.set(eid, new Map());
    verdictsByEid.get(eid)!.set(who, vClass(verdictOf(d)));
  }
  const contestedList: { eid: string; label: string; calls: { actor: string; cls: string }[] }[] = [];
  for (const [eid, mm] of verdictsByEid) {
    const classes = new Set([...mm.values()]);
    if (mm.size >= 2 && classes.has("attack") && classes.has("benign")) contestedList.push({ eid, label: truth.get(eid)?.label ?? "event", calls: [...mm.entries()].map(([actor, cls]) => ({ actor, cls })) });
  }

  // ── v3: team triage metrics ────────────────────────────────────────────────────
  const attackList = [...attackIds];
  const attackSlaJudged = attackList.filter(eid => feedTs.get(eid) != null);
  const attackInSla = attackSlaJudged.filter(eid => { const ft = firstTriage.get(eid); const at = feedTs.get(eid)!; return ft != null && runMs(at, ft) / 1000 <= slaSecFor(sevOf(eid)); }).length;
  const highCrit = [...truth.keys()].filter(eid => { const s = sevOf(eid); return s === "high" || s === "critical"; });
  const highTriaged = highCrit.filter(eid => firstTriage.has(eid));
  const mtttS = median(highTriaged.map(eid => { const at = feedTs.get(eid); return at != null ? runMs(at, firstTriage.get(eid)!) / 1000 : null; }).filter((x): x is number => x != null && x >= 0));
  // Attack logs nobody touched — the team's blind spots. An incident may still have been
  // caught through another of its logs; the note says so.
  const incidentDetected = new Map(incidentList.map(i => [i.id, i.detected] as const));
  const missedAttackLogs = attackList.filter(eid => !firstTriage.has(eid))
    .sort((a, b) => (feedTs.get(a) ?? 0) - (feedTs.get(b) ?? 0))
    .map(eid => { const inc = truth.get(eid)?.incident; const caught = inc ? incidentDetected.get(inc) : false; return missItem(eid, caught ? "its incident was caught through another log" : "its incident was not caught"); });
  // Team false negatives: attack logs whose standing call (latest verdict by anyone) is
  // benign / false positive and that nobody escalated.
  const teamFalseNegatives = [...teamLatestVerdict].filter(([eid, v]) => attackIds.has(eid) && (v === "benign" || v === "false_positive") && !escalatedBy.has(eid))
    .map(([eid, v]) => missItem(eid, `standing call: ${v.replace("_", " ")}`));
  const falseAlarmEscalations = [...escalatedBy.keys()].filter(eid => truth.has(eid) && truthClass(eid) === "benign").map(eid => missItem(eid, "escalated, but benign"));
  // Workload split: share of all triage actions (dispositions + escalations) done by the busiest analyst.
  const triageActionsBy = new Map<string, number>();
  for (const e of events) {
    if ((e.type === "disposition.set" && isValidDisp(e)) || e.type === "escalation.requested") {
      const u = e.actor_id ?? ""; if (!roleByUser.has(u)) continue;
      triageActionsBy.set(u, (triageActionsBy.get(u) ?? 0) + 1);
    }
  }
  const triageTotal = [...triageActionsBy.values()].reduce((a, b) => a + b, 0);
  const busiest = [...triageActionsBy].sort((a, b) => b[1] - a[1])[0];
  const triagers = triageActionsBy.size;

  const caseStatusEvt = [...events].reverse().find(e => e.type === "case.status_set");
  // MTTC: Δ(the containment request it executed → containment.executed), median seconds.
  const execEvents = events.filter(e => e.type === "containment.executed");
  const mttcS = median(execEvents.map(e => { const xt = tsOf(e); if (xt == null) return null; const rt = reqBefore(contTimes, eidOf(e), xt); return rt != null ? runMs(rt, xt) / 1000 : null; })
    .filter((x): x is number => x != null && x >= 0));
  // MTTI: first attack log on a compromised host → its isolation, median seconds.
  const mttiS = median([...isoFirstByHost.values()].map(x => x.timeToIsolateS).filter((x): x is number => x != null));
  const team = {
    version: REPORT_VERSION,
    logs: feed.length, attacks: attackIds.size, detected, timeToDetectS,
    incidentsTotal: incidentList.length, incidentsDetected, incidentRecall, incidents: incidentList.slice(0, 12),
    // ── "Good catch" grading (per incident, built from several logs) ──
    incidentsCaughtWell, incidentsPartial, incidentsNoticed, incidentsMissed,
    avgScopeCoverage, avgHandlingScore,
    escalations: escReq.length, acknowledged: events.filter(e => e.type === "escalation.acknowledged").length,
    containmentReq: events.filter(e => e.type === "containment.requested").length,
    contained: events.filter(e => e.type === "containment.approved").length,
    executed: execEvents.length, mttcS: mttcS != null ? Math.round(mttcS) : null,
    dispTotal: dispDistinct, dispAcc: dispDistinct ? Math.round((teamCredit / dispDistinct) * 100) : null,
    loopClosure: loopClosurePct,
    mttrS: mttrS != null ? Math.round(mttrS) : null,
    handoffLatS: handoffLatS != null ? Math.round(handoffLatS) : null,
    injects: injectResults, injectsScored: scoredInjects.length, injectsHandled,
    contested: contestedList.length, contestedList: contestedList.slice(0, 6),
    caseStatus: (caseStatusEvt?.payload as { status?: string })?.status ?? "—",
    evidencePinned: events.filter(e => e.type === "evidence.pinned").length,
    // ── v3 ──
    attackSlaPct: pct(attackInSla, attackSlaJudged.length), attackSlaMet: attackInSla, attackSlaTotal: attackSlaJudged.length,
    highCritTotal: highCrit.length, highCritTriaged: highTriaged.length, highCritCoverage: pct(highTriaged.length, highCrit.length),
    mtttS: mtttS != null ? Math.round(mtttS) : null,
    missedAttackCount: missedAttackLogs.length, missedAttackLogs: missedAttackLogs.slice(0, 10),
    falseNegativeCount: teamFalseNegatives.length, falseNegatives: teamFalseNegatives.slice(0, MISS_CAP),
    falseAlarmCount: falseAlarmEscalations.length, falseAlarms: falseAlarmEscalations.slice(0, MISS_CAP),
    triageActions: triageTotal, triagers,
    busiestShare: busiest && triageTotal ? pct(busiest[1], triageTotal) : null,
    busiestName: busiest ? (players.find(pl => pl.user_id === busiest[0])?.name ?? null) : null,
    // ── v4: EDR host isolation ──
    isolations: [...isoFirstByHost.values()].slice(0, 12),
    isoTotal: isoFirstByHost.size,
    isoCorrect: [...isoFirstByHost.values()].filter(x => x.correct).length,
    isoPct: pct([...isoFirstByHost.values()].filter(x => x.correct).length, isoFirstByHost.size),
    compromisedHosts: attackHosts.size,
    mttiS: mttiS != null ? Math.round(mttiS) : null,
    hostsLeftOnline: [...attackHosts].filter(([k]) => !isoFirstByHost.has(k))
      .sort((a, b) => (a[1].first ?? 0) - (b[1].first ?? 0))
      .map(([, h]): MissedHost => ({ host: h.host, attackLogs: h.logs, firstAttackS: relS(h.first) })).slice(0, 10),
  };
  return { team, perUser };
}
