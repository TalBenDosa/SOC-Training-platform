/**
 * Timeline incident report (Tal, 2026-10-28): the solo dashboard's report is built like
 * a ticket that goes to Tier-2. The analyst reconstructs the attack end to end (when,
 * where, who ran it, what ran, and the log that proves each step), lists the indicators
 * with the role each one played, sums up the impact and hands the case over (what was
 * done, what is still open, the next step).
 *
 * Pure (no React, no server-only deps): the modal builds the report with these types and
 * the grading route scores it with gradeTimelineReport. The grade is deterministic: every
 * timeline row is matched to a real log of the attack, so it reads what the analyst
 * reconstructed instead of counting keywords.
 */
import { scoreAttackIdentification } from "./attackIdentification";

export type Difficulty = "easy" | "medium" | "hard";

export interface TimelineRow {
  id: string;
  /** The feed log this row was added from ("Add to timeline"); empty for a typed row. */
  eventId?: string;
  time: string;
  host: string;
  /** Who ran it: the account, or the process that started it. */
  actor: string;
  /** What ran / what happened, in the analyst's words (a command line counts). */
  action: string;
}

export const IOC_ROLES = [
  ["attacker_ip", "Attacker IP"],
  ["c2", "C2 / exfil destination"],
  ["phishing", "Phishing sender / domain"],
  ["payload", "Payload URL / domain"],
  ["malicious_file", "Malicious file / hash / process"],
  ["compromised_account", "Compromised account"],
  ["compromised_host", "Compromised host"],
  ["other", "Other"],
] as const;
export type IocRole = (typeof IOC_ROLES)[number][0];

export interface IocRow { id: string; value: string; role: IocRole | "" }

export interface TimelineReport {
  rows: TimelineRow[];
  iocs: IocRow[];
  summary: string;
  done: string;
  open: string;
  next: string;
}

export const EMPTY_TIMELINE_REPORT: TimelineReport = { rows: [], iocs: [], summary: "", done: "", open: "", next: "" };

/** One attack log as the grader sees it: what the analyst could read in the feed. */
export interface TruthEvent {
  id: string;
  ts: string;
  source: string;
  /** Attack stage key (ATT&CK technique, else the event type): rows are counted per stage. */
  stage: string;
  host?: string;
  users: string[];
  /** Process, parent process and any other "who ran it" names on the log. */
  actors: string[];
  ips: string[];
  domains: string[];
  files: string[];
  cmd?: string;
}

// ── Limits (the body is untrusted) ──────────────────────────────────────────
const MAX_ROWS = 40, MAX_IOCS = 30, MAX_TRUTH = 300, MAX_TEXT = 1200, MAX_FIELD = 300;
const str = (v: unknown, max: number) => (typeof v === "string" ? v.slice(0, max) : "");
const strList = (v: unknown, max = 40) => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string").slice(0, max).map(x => x.slice(0, MAX_FIELD)) : []);
const ROLE_SET = new Set<string>(IOC_ROLES.map(r => r[0]));

/** A report from storage or a request body, with every field typed and capped. */
export function sanitizeTimelineReport(v: unknown): TimelineReport {
  const o = (v && typeof v === "object" ? v : {}) as Record<string, unknown>;
  const rows = (Array.isArray(o.rows) ? o.rows : []).slice(0, MAX_ROWS).map((r, i) => {
    const x = (r && typeof r === "object" ? r : {}) as Record<string, unknown>;
    return { id: str(x.id, 64) || `r${i}`, eventId: str(x.eventId, 200) || undefined, time: str(x.time, 40), host: str(x.host, MAX_FIELD), actor: str(x.actor, MAX_FIELD), action: str(x.action, MAX_TEXT) };
  });
  const iocs = (Array.isArray(o.iocs) ? o.iocs : []).slice(0, MAX_IOCS).map((r, i) => {
    const x = (r && typeof r === "object" ? r : {}) as Record<string, unknown>;
    const role = str(x.role, 40);
    return { id: str(x.id, 64) || `i${i}`, value: str(x.value, MAX_FIELD).trim(), role: (ROLE_SET.has(role) ? role : "") as IocRole | "" };
  });
  return { rows, iocs, summary: str(o.summary, MAX_TEXT), done: str(o.done, MAX_TEXT), open: str(o.open, MAX_TEXT), next: str(o.next, MAX_TEXT) };
}

export function sanitizeTruth(v: unknown): TruthEvent[] {
  return (Array.isArray(v) ? v : []).slice(0, MAX_TRUTH).map(r => {
    const x = (r && typeof r === "object" ? r : {}) as Record<string, unknown>;
    return {
      id: str(x.id, 200), ts: str(x.ts, 40), source: str(x.source, 60), stage: str(x.stage, 120) || "event",
      host: str(x.host, MAX_FIELD) || undefined, users: strList(x.users), actors: strList(x.actors), ips: strList(x.ips),
      domains: strList(x.domains), files: strList(x.files), cmd: str(x.cmd, 2000) || undefined,
    };
  }).filter(t => t.id);
}

// ── Grading ─────────────────────────────────────────────────────────────────

export type CheckStatus = "ok" | "warn" | "bad";
export interface ReportCheck { status: CheckStatus; title: string; detail?: string }

export interface TimelineGrade {
  score: number;
  passed: boolean;
  feedback: string;
  checks: ReportCheck[];
  /** What is still missing to pass at this difficulty (empty once passed). */
  requirements: string[];
  /** The pass mark at this difficulty. */
  threshold: number;
}

/** What each difficulty asks of the report on top of the score. */
export const PASS_RULES: Record<Difficulty, { score: number; coverage: number; iocs: number; handoff: "none" | "filled" | "fit"; order: number }> = {
  easy:   { score: 60, coverage: 0.5, iocs: 1, handoff: "none",   order: 0 },
  medium: { score: 65, coverage: 0.6, iocs: 2, handoff: "filled", order: 0 },
  hard:   { score: 70, coverage: 0.8, iocs: 3, handoff: "fit",    order: 0.8 },
};

const norm = (s: string) => s.trim().toLowerCase();
/** "NEXA\\d.levi", "d.levi@nexacorp.com" and "d.levi" are the same account. */
function accountKeys(v: string): string[] {
  const n = norm(v);
  if (!n) return [];
  const out = new Set([n]);
  const afterSlash = n.split(/[\\/]/).pop();
  if (afterSlash) out.add(afterSlash);
  const at = (afterSlash ?? n).indexOf("@");
  if (at > 0) out.add((afterSlash ?? n).slice(0, at));
  return [...out].filter(x => x.length >= 3);
}
function tokens(text: string): Set<string> {
  const out = new Set<string>();
  for (const raw of norm(text).split(/[\s"'`,;()[\]{}<>|=]+/)) {
    const t = raw.replace(/^[.:!?]+|[.:!?]+$/g, "");
    if (!t) continue;
    out.add(t);
    for (const k of accountKeys(t)) out.add(k);
    const last = t.split(/[\\/]/).pop();
    if (last) out.add(last);
  }
  return out;
}
const fmtTime = (ts: string) => { const d = new Date(ts); return Number.isNaN(d.getTime()) ? "" : d.toLocaleTimeString("en-GB", { hour12: false }); };

const IPV4 = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const HEX = /^[0-9a-f]{32,64}$/;
const DOMAIN = /^(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$/;

interface Classes { ips: Set<string>; domains: Set<string>; files: Set<string>; users: Set<string>; hosts: Set<string>; actors: Set<string> }
function truthClasses(truth: TruthEvent[], realIndicators: string[]): Classes {
  const c: Classes = { ips: new Set(), domains: new Set(), files: new Set(), users: new Set(), hosts: new Set(), actors: new Set() };
  for (const t of truth) {
    t.ips.forEach(v => c.ips.add(norm(v)));
    t.domains.forEach(v => c.domains.add(norm(v)));
    t.files.forEach(v => c.files.add(norm(v)));
    t.users.forEach(v => accountKeys(v).forEach(k => c.users.add(k)));
    t.actors.forEach(v => c.actors.add(norm(v)));
    if (t.host) c.hosts.add(norm(t.host));
  }
  // Values that live only in a vendor-native raw block (the discrete indicator list).
  for (const r of realIndicators) {
    const v = norm(r);
    if (IPV4.test(v)) c.ips.add(v);
    else if (HEX.test(v)) c.files.add(v);
    else if (v.includes("@")) accountKeys(v).forEach(k => c.users.add(k));
    else if (DOMAIN.test(v) && !c.hosts.has(v)) c.domains.add(v);
  }
  return c;
}

/** Does a value fit the role the analyst gave it, judged by where it appears in the attack? */
function roleFits(role: IocRole | "", v: string, c: Classes): boolean {
  const n = norm(v);
  const acct = accountKeys(v).some(k => c.users.has(k));
  const host = n.replace(/^https?:\/\//, "").split(/[/:]/)[0];
  switch (role) {
    case "attacker_ip": return c.ips.has(n);
    case "c2": return c.ips.has(n) || c.domains.has(host);
    case "phishing": return c.domains.has(host) || (n.includes("@") && (acct || c.domains.has(n.split("@")[1] ?? "")));
    case "payload": return c.domains.has(host) || c.files.has(n) || c.files.has(n.split(/[\\/]/).pop() ?? "");
    case "malicious_file": return c.files.has(n) || c.files.has(n.split(/[\\/]/).pop() ?? "") || c.actors.has(n);
    case "compromised_account": return acct;
    case "compromised_host": return c.hosts.has(n);
    default: return false;
  }
}
function inAttack(v: string, c: Classes, real: Set<string>): boolean {
  const n = norm(v);
  if (real.has(n)) return true;
  const host = n.replace(/^https?:\/\//, "").split(/[/:]/)[0];
  return c.ips.has(n) || c.domains.has(host) || c.files.has(n) || c.files.has(n.split(/[\\/]/).pop() ?? "")
    || c.hosts.has(n) || c.actors.has(n) || accountKeys(v).some(k => c.users.has(k));
}

const NEXT_STEP: Record<"endpoint" | "identity" | "network" | "cloud", RegExp> = {
  endpoint: /isolat|contain|quarantin|kill|terminat|re-?image|block (the )?hash/i,
  identity: /reset|revok|disabl|suspend|lock|mfa|sign.?out|session/i,
  network:  /block|sinkhole|firewall|deny|blocklist|blacklist/i,
  cloud:    /revok|rotat|disabl|delete|remove|deactivat/i,
};
const ENDPOINT_SOURCES = /edr|sysmon|endpoint|defender|crowdstrike|sentinel|windows|linux|auditd|av/i;
const IDENTITY_SOURCES = /azure_ad|entra|okta|o365|office|ad$|^ad|iam|idp|vpn|duo|ping/i;
const CLOUD_SOURCES = /cloud|aws|gcp|azure_activity|k8s|kubernetes/i;
function attackKinds(truth: TruthEvent[]): ("endpoint" | "identity" | "network" | "cloud")[] {
  const k = new Set<"endpoint" | "identity" | "network" | "cloud">();
  for (const t of truth) {
    if (t.cmd || ENDPOINT_SOURCES.test(t.source)) k.add("endpoint");
    if (IDENTITY_SOURCES.test(t.source)) k.add("identity");
    if (CLOUD_SOURCES.test(t.source)) k.add("cloud");
    if (/firewall|proxy|dns|waf|network|ids|ips/i.test(t.source)) k.add("network");
  }
  return [...k];
}
const KIND_LABEL = { endpoint: "an endpoint", identity: "an account", network: "the network", cloud: "a cloud tenant" };

export interface GradeInput {
  report: TimelineReport;
  truth: TruthEvent[];
  realIndicators: string[];
  /** Every log the analyst saw, serialized: a value in here is real, never invented. */
  evidenceText: string;
  attackTitle?: string;
  mitre: string[];
  difficulty: Difficulty;
}

export function gradeTimelineReport(input: GradeInput): TimelineGrade {
  const { report, truth, realIndicators, evidenceText, attackTitle, mitre, difficulty } = input;
  const rule = PASS_RULES[difficulty];
  const checks: ReportCheck[] = [];
  const req: string[] = [];
  const rows = report.rows.filter(r => r.eventId || r.host.trim() || r.actor.trim() || r.action.trim());
  const byId = new Map(truth.map(t => [t.id, t]));
  const c = truthClasses(truth, realIndicators);
  const real = new Set(realIndicators.map(norm));
  const feedTokens = tokens(evidenceText);

  if (truth.length === 0) {
    return {
      score: 0, passed: false, threshold: rule.score, checks: [], requirements: [],
      feedback: "There is no open incident to report yet. Keep watching the feed: build the timeline once the attack shows up.",
    };
  }

  // ── Timeline: tie every row to a log of the attack ─────────────────────────
  const matched: { row: TimelineRow; idx: number; ev: TruthEvent }[] = [];
  const offAttack: number[] = [];
  const inaccurate: number[] = [];
  const unexplained: number[] = [];
  rows.forEach((row, idx) => {
    let ev = row.eventId ? byId.get(row.eventId) : undefined;
    if (!ev && !row.eventId) {
      // A typed row: tie it to the log on the same host that shares the most distinctive
      // values with it (a tie goes to a stage no other row covers yet).
      const said = tokens(`${row.host} ${row.actor} ${row.action}`);
      const coveredNow = new Set(matched.map(m => m.ev.stage));
      let best = 0;
      for (const t of truth) {
        if (t.host && row.host.trim() && norm(row.host) !== norm(t.host)) continue;
        const hits = [...t.ips, ...t.domains, ...t.files, ...t.actors.filter(a => !/^(explorer|svchost|winword|excel|outlook|chrome|msedge)\.exe$/i.test(a))]
          .filter(v => said.has(norm(v))).length;
        const rank = hits * 2 + (hits && !coveredNow.has(t.stage) ? 1 : 0);
        if (rank > best) { best = rank; ev = t; }
      }
    }
    if (!ev) { offAttack.push(idx + 1); return; }
    matched.push({ row, idx, ev });
    const hostOk = !ev.host || !row.host.trim() || norm(row.host).includes(norm(ev.host)) || norm(ev.host).includes(norm(row.host));
    const who = tokens(row.actor);
    const actorOk = (ev.users.length === 0 && ev.actors.length === 0)
      || ev.users.some(u => accountKeys(u).some(k => who.has(k))) || ev.actors.some(a => who.has(norm(a)));
    if (!hostOk || !actorOk) inaccurate.push(idx + 1);
    if (row.action.trim().length < 8) unexplained.push(idx + 1);
  });

  // Stages, in the order the attack ran.
  const stageFirst = new Map<string, number>();
  for (const t of truth) { const ms = Date.parse(t.ts) || 0; const cur = stageFirst.get(t.stage); if (cur === undefined || ms < cur) stageFirst.set(t.stage, ms); }
  const stages = [...stageFirst.entries()].sort((a, b) => a[1] - b[1]).map(([s]) => s);
  const covered = new Set(matched.map(m => m.ev.stage));
  const coverage = stages.length ? covered.size / stages.length : 0;

  // Order: the rows as listed against the time of the logs they stand on.
  let inversions = 0; const swapped: string[] = [];
  for (let i = 1; i < matched.length; i++) {
    if ((Date.parse(matched[i].ev.ts) || 0) < (Date.parse(matched[i - 1].ev.ts) || 0)) { inversions++; swapped.push(`${matched[i - 1].idx + 1} and ${matched[i].idx + 1}`); }
  }
  const orderRatio = matched.length >= 2 ? 1 - inversions / (matched.length - 1) : matched.length === 1 ? 1 : 0;
  const goodRows = matched.filter(m => !inaccurate.includes(m.idx + 1) && !unexplained.includes(m.idx + 1)).length;
  const accuracy = rows.length ? goodRows / rows.length : 0;
  const timelinePts = 25 * coverage + 10 * accuracy + (matched.length >= 2 ? 10 * orderRatio : matched.length === 1 ? 4 : 0);

  if (rows.length === 0) {
    checks.push({ status: "bad", title: "The timeline is empty.", detail: "Open each log of the attack in the feed and press \"Add to timeline\", then say what happened in it." });
  } else {
    checks.push(offAttack.length === 0
      ? { status: "ok", title: `Every row stands on a log of this attack (${matched.length} of ${rows.length}).` }
      : { status: matched.length ? "warn" : "bad", title: `${matched.length} of ${rows.length} rows are tied to this attack's logs.`,
          detail: `Row${offAttack.length > 1 ? "s" : ""} ${offAttack.join(", ")} ${offAttack.length > 1 ? "aren't" : "isn't"} part of this attack: routine activity, a false positive, or a typed row that quotes no value from the attack's logs.` });
    if (inaccurate.length) checks.push({ status: "warn", title: `Who and where: row${inaccurate.length > 1 ? "s" : ""} ${inaccurate.join(", ")} ${inaccurate.length > 1 ? "don't" : "doesn't"} match ${inaccurate.length > 1 ? "their logs" : "its log"}.`, detail: "Check the host and the account or process that ran it, exactly as the log shows them." });
    else if (matched.length) checks.push({ status: "ok", title: "Who ran it and where match the logs." });
    if (unexplained.length) checks.push({ status: "warn", title: `Say what happened in row${unexplained.length > 1 ? "s" : ""} ${unexplained.join(", ")}.`, detail: "What ran, what it did, or what changed. A row without it is a log reference, not an investigation." });
    if (matched.length >= 2) checks.push(inversions === 0
      ? { status: "ok", title: "The timeline is in the order the attack happened." }
      : { status: "warn", title: `Order: rows ${swapped.slice(0, 3).join("; ")} are swapped.`, detail: "Tier-2 reads the timeline top to bottom: put each step after the one that caused it." });
    // Coverage and the first gap, without naming what is missing.
    let gap = "";
    const firstUncovered = stages.findIndex(s => !covered.has(s));
    if (firstUncovered === 0 && covered.size > 0) gap = "The attack started before your first row. Look for what came before it.";
    else if (firstUncovered > 0) {
      const prev = matched.filter(m => m.ev.stage === stages[firstUncovered - 1]).map(m => m.row.time || fmtTime(m.ev.ts)).sort().pop();
      gap = `There's a gap after ${prev || "your last covered step"}: the attack kept going. Check what happened next on the same host or account.`;
    }
    checks.push(coverage >= 1
      ? { status: "ok", title: `Coverage: all ${stages.length} attack stage${stages.length > 1 ? "s" : ""} seen so far are in your timeline.` }
      : { status: coverage >= rule.coverage ? "warn" : "bad", title: `Coverage: ${covered.size} of ${stages.length} attack stages.`, detail: gap || undefined });
  }

  // ── Indicators ─────────────────────────────────────────────────────────────
  const iocs = report.iocs.filter(i => i.value.trim());
  const fabricated: string[] = [], offIncident: string[] = [], wrongRole: string[] = [], noRole: string[] = [];
  let realCount = 0, rolesRight = 0;
  for (const i of iocs) {
    if (inAttack(i.value, c, real)) {
      realCount++;
      if (!i.role) noRole.push(i.value);
      else if (i.role === "other" || roleFits(i.role, i.value, c)) rolesRight++;
      else wrongRole.push(i.value);
    } else if (feedTokens.has(norm(i.value))) offIncident.push(i.value);
    else if (i.value.trim().length >= 3) fabricated.push(i.value);
  }
  const available = new Set([...c.ips, ...c.domains, ...c.files, ...c.hosts, ...realIndicators.map(norm)]).size;
  const iocTarget = Math.max(1, Math.min(rule.iocs + 1, available || 1));
  const iocPts = fabricated.length ? 0 : 12 * Math.min(1, realCount / iocTarget) + (realCount ? 8 * (rolesRight / realCount) : 0);
  if (iocs.length === 0) checks.push({ status: "bad", title: "No indicators listed.", detail: "List the IPs, domains, hashes, accounts and hosts that prove the attack, and the role each one played." });
  else {
    if (fabricated.length) checks.push({ status: "bad", title: `Couldn't verify: ${fabricated.slice(0, 3).map(v => `"${v}"`).join(", ")}.`, detail: "These values don't appear in any log you saw. Copy indicators from the logs, character for character." });
    if (offIncident.length) checks.push({ status: "warn", title: `${offIncident.slice(0, 3).join(", ")} ${offIncident.length > 1 ? "are" : "is"} in the feed but not part of this attack.` });
    if (wrongRole.length) checks.push({ status: "warn", title: `Role doesn't fit: ${wrongRole.slice(0, 3).join(", ")}.`, detail: "The value is in the attack, but not in the role you gave it. Look at the field it appears in." });
    if (noRole.length) checks.push({ status: "warn", title: `Pick a role for ${noRole.slice(0, 3).join(", ")}.` });
    if (!fabricated.length && realCount) checks.push({ status: realCount >= iocTarget && !wrongRole.length && !noRole.length ? "ok" : "warn", title: `Indicators: ${realCount} real, ${rolesRight} with the right role.` });
  }

  // ── Summary: did the analyst name what this attack is? ─────────────────────
  const narrative = [report.summary, ...rows.map(r => r.action)].join("\n");
  const ident = scoreAttackIdentification(narrative, attackTitle, mitre);
  const summaryPts = report.summary.trim().length >= 20 ? (15 * ident.attackScore) / 40 : 0;
  if (report.summary.trim().length < 20) checks.push({ status: "bad", title: "Write the summary.", detail: "Two or three sentences: what the attack is, how far it got, and what it puts at risk." });
  else if (ident.wrongType) checks.push({ status: "warn", title: "The attack type you named doesn't match the evidence.", detail: "Re-read the timeline you built: what do the steps add up to?" });
  else if (ident.attackScore >= 30) checks.push({ status: "ok", title: "The summary names the specific technique." });
  else checks.push({ status: "warn", title: "Name the specific technique in the summary.", detail: "\"Suspicious activity\" or a broad category isn't enough for Tier-2 to act on." });

  // ── Handoff to Tier-2 ──────────────────────────────────────────────────────
  const filled = [report.done, report.open, report.next].filter(s => s.trim().length >= 8).length;
  const kinds = attackKinds(truth);
  const nextFits = report.next.trim().length >= 8 && (kinds.length ? kinds.some(k => NEXT_STEP[k].test(report.next)) : /isolat|block|reset|revok|disabl|contain/i.test(report.next));
  const handoffPts = 4 * filled + (nextFits ? 8 : 0);
  if (filled < 3) checks.push({ status: filled ? "warn" : "bad", title: `Handoff: ${3 - filled} of 3 fields empty.`, detail: "Tier-2 needs what you already did, what's still open, and the next step you recommend." });
  if (report.next.trim().length >= 8) checks.push(nextFits
    ? { status: "ok", title: "The recommended next step fits the attack." }
    : { status: "warn", title: "The next step doesn't stop this attack.", detail: `The attack ran on ${kinds.map(k => KIND_LABEL[k]).join(" and ") || "this environment"}: recommend an action that cuts that access.` });

  const score = Math.max(0, Math.min(100, Math.round(timelinePts + iocPts + summaryPts + handoffPts)));

  // ── Pass rules at this difficulty ──────────────────────────────────────────
  const minRows = Math.min(2, stages.length);
  if (score < rule.score) req.push(`Reach ${rule.score}/100 (now ${score}).`);
  if (matched.length < minRows) req.push(`Tie at least ${minRows} timeline rows to the attack's logs.`);
  if (coverage < rule.coverage) req.push(`Cover at least ${Math.ceil(rule.coverage * stages.length)} of the ${stages.length} attack stages.`);
  const iocNeed = Math.min(rule.iocs, Math.max(1, available));
  if (realCount < iocNeed) req.push(`List at least ${iocNeed} real indicator${iocNeed > 1 ? "s" : ""} from the attack.`);
  if (fabricated.length) req.push("Remove the values that aren't in any log.");
  if (rule.handoff !== "none" && filled < 3) req.push("Fill in all three handoff fields.");
  if (rule.handoff === "fit" && !nextFits) req.push("Recommend a next step that stops this attack.");
  if (rule.order > 0 && matched.length >= 2 && orderRatio < rule.order) req.push("Put the timeline in the order the attack happened.");
  const passed = req.length === 0;

  const label = difficulty[0].toUpperCase() + difficulty.slice(1);
  const feedback = passed
    ? `Escalation accepted: ${score}/100. Tier-2 can pick this case up from your timeline.`
    : `Not ready for Tier-2 yet: ${score}/100. At ${label}, ${req.length === 1 ? "one thing is" : `${req.length} things are`} still missing.`;
  return { score, passed, feedback, checks, requirements: req, threshold: rule.score };
}
