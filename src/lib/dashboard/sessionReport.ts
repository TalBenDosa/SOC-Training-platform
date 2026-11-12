/**
 * The end-of-training report of a SOC Dashboard session (Tal, 2026-11-12: a training is at most 30 minutes, it has
 * success metrics, and it ends with a report that says where the analyst can improve).
 *
 * Pure: the page collects what happened in the shift (the hook's counters, every graded incident report, every
 * missed attack) and this module turns it into metrics with targets, an overall score and the three areas to
 * work on first. No I/O, no clock: the caller passes the times.
 */

/** The longest a single Dashboard training runs. */
export const SESSION_LIMIT_MS = 30 * 60_000;
/** When the countdown turns to a warning. */
export const SESSION_WARN_MS = 5 * 60_000;

export type SessionEnd = "time" | "secured" | "manual";

/** One graded incident report (the grader's rubric: identification /40, evidence /30, action and impact /30). */
export interface GradedReport {
  incidentId: string;
  title: string;
  score: number;
  passed: boolean;
  subScores?: { attack: number; ioc: number; action: number };
  /** The incident's attack reached the feed (epoch ms). */
  injectedAt?: number | null;
  /** The analyst first opened one of its rows (epoch ms). */
  firstOpenedAt?: number | null;
  /** When the report was graded (epoch ms). */
  at: number;
}

export interface MissedAttack { title: string; techniques: string[]; tell: string }

export interface SessionFacts {
  company: string;
  difficulty: string | null;
  startedAt: number;
  endedAt: number;
  endedBy: SessionEnd;
  /** Attacks that reached the feed (not false-positive look-alikes). */
  presented: number;
  caught: number;
  missed: MissedAttack[];
  reports: GradedReport[];
  eventsOpened: number;
  /** Response target of one incident, seconds (the feed's SLA). */
  responseTargetSec: number;
  /** Incidents investigated in the EDR console this shift. */
  edrInvestigations: number;
  xp: number;
}

export type MetricStatus = "met" | "close" | "below" | "na";

export interface Metric {
  id: "detection" | "report_quality" | "identification" | "evidence" | "action" | "first_pass" | "time_to_detect" | "time_to_report";
  label: string;
  /** Display value ("2/3", "78/100", "6m 10s"). */
  value: string;
  target: string;
  status: MetricStatus;
  /** 0..1 how far the metric is toward its target (1 = met); null when not measured. */
  progress: number | null;
  /** What the number means, one line. */
  explain: string;
}

export interface Improvement { metric: Metric["id"]; title: string; why: string; how: string[] }

export interface SessionReport {
  facts: SessionFacts;
  durationMs: number;
  /** 0..100, from the measured metrics only. */
  overall: number | null;
  band: "excellent" | "good" | "developing" | "needs_work" | "not_enough_data";
  metrics: Metric[];
  strengths: string[];
  improvements: Improvement[];
}

const pct = (n: number) => `${Math.round(n * 100)}%`;
export const formatDuration = (ms: number) => {
  const s = Math.max(0, Math.round(ms / 1000));
  return s >= 60 ? `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s` : `${s}s`;
};
const avg = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
function status(progress: number | null): MetricStatus {
  if (progress === null) return "na";
  return progress >= 1 ? "met" : progress >= 0.8 ? "close" : "below";
}

/** Targets: what a competent Tier-1 analyst reaches in one 30-minute shift. */
export const TARGETS = {
  detection: 0.8,
  reportScore: 75,
  identification: 0.75,
  evidence: 0.75,
  action: 0.7,
  firstPass: 0.7,
  /** Seconds from the attack's first row to the analyst opening one of its rows. */
  detectSec: 5 * 60,
} as const;

/** The best report of each incident (a retried report replaces a failed one) and the first attempt of each. */
function perIncident(reports: GradedReport[]) {
  const best = new Map<string, GradedReport>(), first = new Map<string, GradedReport>();
  for (const r of [...reports].sort((a, b) => a.at - b.at)) {
    if (!first.has(r.incidentId)) first.set(r.incidentId, r);
    const b = best.get(r.incidentId);
    if (!b || r.score > b.score) best.set(r.incidentId, r);
  }
  return { best: [...best.values()], first: [...first.values()] };
}

export function buildSessionReport(f: SessionFacts): SessionReport {
  const { best, first } = perIncident(f.reports);
  const metrics: Metric[] = [];

  // 1. Detection: attacks the analyst closed with a passing report, of the attacks that reached the feed.
  const detP = f.presented > 0 ? Math.min(1, f.caught / f.presented / TARGETS.detection) : null;
  metrics.push({ id: "detection", label: "Detection rate", value: f.presented > 0 ? `${f.caught}/${f.presented} (${pct(f.caught / f.presented)})` : "No attack reached the feed",
    target: `${pct(TARGETS.detection)} of attacks`, status: status(detP), progress: detP, explain: "Attacks you closed with a passing incident report, out of the attacks that reached your feed." });

  // 2. Report quality and its three rubric parts (best report per incident).
  const score = avg(best.map(r => r.score));
  const qP = score === null ? null : Math.min(1, score / TARGETS.reportScore);
  metrics.push({ id: "report_quality", label: "Report quality", value: score === null ? "No report filed" : `${Math.round(score)}/100`,
    target: `${TARGETS.reportScore}/100 (pass is 60)`, status: status(qP), progress: qP, explain: "The average grade of your incident reports (best attempt per incident)." });
  const parts = best.filter(r => r.subScores);
  const part = (id: "identification" | "evidence" | "action", label: string, key: "attack" | "ioc" | "action", max: number, target: number, explain: string) => {
    const v = avg(parts.map(r => r.subScores![key] / max));
    const p = v === null ? null : Math.min(1, v / target);
    metrics.push({ id, label, value: v === null ? "Not measured" : pct(v), target: pct(target), status: status(p), progress: p, explain });
  };
  part("identification", "Attack identification", "attack", 40, TARGETS.identification, "Naming the right attack and its technique.");
  part("evidence", "Evidence", "ioc", 30, TARGETS.evidence, "Quoting the real indicators from the logs (users, hosts, addresses, hashes), and nothing invented.");
  part("action", "Response and impact", "action", 30, TARGETS.action, "Saying what to contain or do next, and what the attack put at risk.");

  // 3. First-attempt pass rate.
  const fp = first.length ? first.filter(r => r.passed).length / first.length : null;
  const fpP = fp === null ? null : Math.min(1, fp / TARGETS.firstPass);
  metrics.push({ id: "first_pass", label: "Passed on the first report", value: fp === null ? "No report filed" : `${first.filter(r => r.passed).length}/${first.length}`,
    target: pct(TARGETS.firstPass), status: status(fpP), progress: fpP, explain: "Incidents whose first report already passed: you investigated before writing." });

  // 4. Time to detect: the attack's first row to the analyst opening one of its rows.
  const detect = avg(best.map(r => (r.injectedAt && r.firstOpenedAt && r.firstOpenedAt >= r.injectedAt ? (r.firstOpenedAt - r.injectedAt) / 1000 : NaN)).filter(Number.isFinite));
  const tdP = detect === null ? null : Math.min(1, TARGETS.detectSec / Math.max(1, detect));
  metrics.push({ id: "time_to_detect", label: "Time to detect", value: detect === null ? "Not measured" : formatDuration(detect * 1000),
    target: `within ${formatDuration(TARGETS.detectSec * 1000)}`, status: status(tdP), progress: tdP, explain: "From the attack's first log in the feed to you opening one of its rows." });

  // 5. Time to report: the attack's first row to a passing report (the feed's response target).
  const respond = avg(best.filter(r => r.passed && r.injectedAt).map(r => (r.at - r.injectedAt!) / 1000).filter(s => s >= 0));
  const trP = respond === null ? null : Math.min(1, f.responseTargetSec / Math.max(1, respond));
  metrics.push({ id: "time_to_report", label: "Time to a passing report", value: respond === null ? "Not measured" : formatDuration(respond * 1000),
    target: `within ${formatDuration(f.responseTargetSec * 1000)}`, status: status(trP), progress: trP, explain: "From the attack's first log to your passing incident report." });

  // Overall: detection and report quality carry most of it; the rest are skills behind them.
  const weights: Partial<Record<Metric["id"], number>> = { detection: 30, report_quality: 25, evidence: 10, identification: 10, action: 5, first_pass: 10, time_to_detect: 5, time_to_report: 5 };
  let num = 0, den = 0;
  for (const m of metrics) if (m.progress !== null) { num += m.progress * (weights[m.id] ?? 0); den += weights[m.id] ?? 0; }
  // A shift with no report and no attack has nothing to grade; a shift with an attack and no report scores what it measured.
  const overall = den >= 25 ? Math.round((num / den) * 100) : null;
  const band = overall === null ? "not_enough_data" : overall >= 85 ? "excellent" : overall >= 70 ? "good" : overall >= 50 ? "developing" : "needs_work";

  const strengths = metrics.filter(m => m.status === "met").map(m => `${m.label}: ${m.value} (target ${m.target})`);
  const improvements = improvementsFor(f, metrics, best);
  return { facts: f, durationMs: f.endedAt - f.startedAt, overall, band, metrics, strengths, improvements };
}

/** The areas to work on, worst gap first, three at most; each says what to do next time. */
function improvementsFor(f: SessionFacts, metrics: Metric[], best: GradedReport[]): Improvement[] {
  const out: (Improvement & { gap: number })[] = [];
  const m = (id: Metric["id"]) => metrics.find(x => x.id === id)!;
  const gap = (id: Metric["id"]) => { const p = m(id).progress; return p === null ? 0 : 1 - p; };
  const missedNames = f.missed.map(x => x.title).filter(Boolean);
  const techniques = [...new Set(f.missed.flatMap(x => x.techniques))].slice(0, 4);

  if (m("detection").status !== "met" && m("detection").status !== "na") out.push({ metric: "detection", gap: gap("detection") + (f.missed.length ? 0.6 : 0.2),
    title: "Catch more of the attacks in the feed",
    why: missedNames.length ? `Missed: ${missedNames.join("; ")}.` : "Some attacks ran to the end without a passing report.",
    how: [
      "Sort or filter the feed by severity every few minutes, and open every high and critical row before it scrolls away.",
      "When a row looks odd, pivot on its user, host or address: an attack is several rows that share one of them.",
      ...(techniques.length ? [`Review the techniques you missed: ${techniques.join(", ")} (MITRE drawer on any row).`] : []),
    ] });
  if (f.presented > 0 && best.length === 0) out.push({ metric: "report_quality", gap: 1,
    title: "File an incident report for every attack you find",
    why: "No incident report was graded this shift, and the report is how a catch is counted.",
    how: ["As soon as you are sure a chain of rows is an attack, press Report Incident.", "Write what happened, the evidence you saw and what to do next. The report is graded on those three."] });
  if (m("evidence").status === "below" || m("evidence").status === "close") out.push({ metric: "evidence", gap: gap("evidence"),
    title: "Back your report with the real indicators",
    why: `Evidence scored ${m("evidence").value} against ${m("evidence").target}.`,
    how: ["Copy the exact values from the log rows: the user, the host, the source and destination addresses, the file hash, the domain.", "Never write a value you did not see in the feed: an invented indicator fails the report."] });
  if (m("identification").status === "below" || m("identification").status === "close") out.push({ metric: "identification", gap: gap("identification"),
    title: "Name the attack precisely",
    why: `Identification scored ${m("identification").value} against ${m("identification").target}.`,
    how: ["Say what the attacker did in the analyst's words (for example password spraying, phishing with a credential page, a web shell) and give its MITRE technique.", "Read the attack's rows in time order before you name it: the first row is rarely the whole story."] });
  if (m("action").status === "below" || m("action").status === "close") out.push({ metric: "action", gap: gap("action"),
    title: "Finish with containment and impact",
    why: `Response and impact scored ${m("action").value} against ${m("action").target}.`,
    how: ["End every report with what to do now: isolate the host, disable or reset the account, block the address or domain.", "Say what was at risk: which data, which system, how many users."] });
  if (m("first_pass").status === "below") out.push({ metric: "first_pass", gap: gap("first_pass") * 0.8,
    title: "Investigate before you write",
    why: `${m("first_pass").value} incidents passed on the first report.`,
    how: ["Open the related rows (same user, host or address) and, for an endpoint, the EDR console, before you start the report.", "Read the grader's gaps on a failed report: they name exactly what was missing."] });
  if (m("time_to_detect").status === "below") out.push({ metric: "time_to_detect", gap: gap("time_to_detect") * 0.7,
    title: "Spot attacks sooner",
    why: `It took ${m("time_to_detect").value} on average to open the first row of an attack.`,
    how: ["Keep the feed in view and check new high-severity rows as they land.", "Use a saved search for the signals of your company (failed sign-ins, new admin rights, rare processes)."] });
  if (m("time_to_report").status === "below") out.push({ metric: "time_to_report", gap: gap("time_to_report") * 0.6,
    title: "Close incidents faster",
    why: `A passing report took ${m("time_to_report").value} against a target of ${m("time_to_report").target}.`,
    how: ["Write the report as you investigate: note each indicator as you find it.", "Use the report's structure (what, evidence, action) as your investigation checklist."] });
  if (f.edrInvestigations === 0 && f.presented > 0 && out.length < 3) out.push({ metric: "detection", gap: 0.05,
    title: "Use the EDR console on endpoint alerts",
    why: "No incident was opened in the EDR console this shift.",
    how: ["On an endpoint row, press Investigate in EDR to see the process tree, the parent and the network connections behind the alert."] });
  return out.sort((a, b) => b.gap - a.gap).slice(0, 3).map(({ gap: _g, ...rest }) => { void _g; return rest; });
}
