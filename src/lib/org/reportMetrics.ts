/**
 * The figures and the written summary of a student progress report (PDF, per student or for
 * the whole class). Pure and client-safe: built from the student page's data, compared with
 * the previous report's figures (migration 0110, POST /api/org/students/[id]/report-snapshot).
 *
 * The summary is written by rules, not by a model (production has no AI key), so it says only
 * what the figures show: activity and sign-in, progress since the last report, strengths, the
 * topics to strengthen with the rooms to take next, the learning plan, and what needs action.
 * No pronouns: the learner is named, never "he" or "she".
 */
import type { StudentDetail } from "@/app/api/org/students/[id]/route";
import type { PersonalPlanResponse } from "@/app/api/org/students/[id]/plan/route";

export const MIN_ITEMS = 5;

export interface ReportMetrics {
  v: 1;
  xp: number;
  level: number;
  rooms_completed: number;
  rooms_started: number;
  scenarios_completed: number;
  scenario_avg: number | null;
  sessions: number;
  detect_avg: number | null;
  answered: number;
  first_try_pct: number | null;
  first_try_items: number;
  open_mistakes: number;
  active_days_30: number | null;
  plan_done: number;
  plan_total: number;
  /** Right-first-try % per skill area with enough answers (MIN_ITEMS). */
  areas: Record<string, number>;
}

const num = (v: unknown, max = 1e9): number | null => {
  const n = Number(v);
  return Number.isFinite(n) ? Math.max(0, Math.min(max, Math.round(n * 10) / 10)) : null;
};

/** Re-shapes untrusted JSON (a request body, a stored row) into metrics, or null. */
export function sanitizeReportMetrics(raw: unknown): ReportMetrics | null {
  if (!raw || typeof raw !== "object") return null;
  const o = raw as Record<string, unknown>;
  const areas: Record<string, number> = {};
  if (o.areas && typeof o.areas === "object") {
    for (const [k, v] of Object.entries(o.areas as Record<string, unknown>).slice(0, 40)) {
      const n = num(v, 100);
      if (n !== null && /^[a-z0-9_-]{1,40}$/i.test(k)) areas[k] = n;
    }
  }
  return {
    v: 1,
    xp: num(o.xp) ?? 0, level: num(o.level, 1000) ?? 1,
    rooms_completed: num(o.rooms_completed, 10000) ?? 0, rooms_started: num(o.rooms_started, 10000) ?? 0,
    scenarios_completed: num(o.scenarios_completed, 10000) ?? 0, scenario_avg: num(o.scenario_avg, 100),
    sessions: num(o.sessions, 100000) ?? 0, detect_avg: num(o.detect_avg, 100),
    answered: num(o.answered) ?? 0, first_try_pct: num(o.first_try_pct, 100), first_try_items: num(o.first_try_items) ?? 0,
    open_mistakes: num(o.open_mistakes) ?? 0, active_days_30: num(o.active_days_30, 31),
    plan_done: num(o.plan_done, 10000) ?? 0, plan_total: num(o.plan_total, 10000) ?? 0,
    areas,
  };
}

function planItems(plan?: PersonalPlanResponse | null) {
  if (!plan) return [];
  return [...(plan.personal?.items ?? []), ...plan.assigned.flatMap(p => p.items)];
}

export function metricsOf(s: StudentDetail, plan?: PersonalPlanResponse | null): ReportMetrics {
  const items = planItems(plan).filter(i => i.status !== "untracked");
  const areas: Record<string, number> = {};
  for (const a of s.skills) if (a.items >= MIN_ITEMS && a.accuracy !== null) areas[a.area] = a.accuracy;
  return {
    v: 1,
    xp: s.xp, level: s.level,
    rooms_completed: s.summary.rooms_completed, rooms_started: s.summary.rooms_started,
    scenarios_completed: s.summary.scenarios_completed, scenario_avg: s.summary.scenario_avg_score,
    sessions: s.summary.sessions, detect_avg: s.summary.avg_detect_rate,
    answered: s.summary.first_try.items, first_try_pct: s.summary.first_try.accuracy, first_try_items: s.summary.first_try.items,
    open_mistakes: s.mistake_groups.reduce((n, g) => n + g.mistakes.filter(m => !m.solved).length, 0),
    active_days_30: s.activity?.active_days_30 ?? null,
    plan_done: items.filter(i => i.status === "done").length, plan_total: items.length,
    areas,
  };
}

const DAY = 86_400_000;
const fmtDate = (iso: string) => new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric" });
const ago = (iso: string, now: number) => {
  const d = Math.floor((now - Date.parse(iso)) / DAY);
  return d <= 0 ? "today" : d === 1 ? "yesterday" : `${d} days ago`;
};
const signed = (n: number, unit = "") => `${n > 0 ? "+" : ""}${n}${unit}`;
const list = (xs: string[]) => (xs.length <= 1 ? xs.join("") : `${xs.slice(0, -1).join(", ")} and ${xs[xs.length - 1]}`);

export interface Narrative {
  /** One word for the class table and the colour of the summary: how the learner stands. */
  status: "on track" | "needs attention" | "inactive" | "not started";
  paragraphs: { title: string; text: string }[];
  /** Short changes since the previous report, for the class table ("+320 XP, +2 rooms"). */
  change: string;
}

/** The written summary of one learner's report. */
export function reportNarrative(
  s: StudentDetail,
  plan: PersonalPlanResponse | null | undefined,
  previous: { created_at: string; metrics: ReportMetrics } | null,
  now = Date.now(),
): Narrative {
  const name = s.display_name || s.handle || "This learner";
  const m = metricsOf(s, plan);
  const act = s.activity;
  const paragraphs: Narrative["paragraphs"] = [];

  // ── Activity and sign-in ──
  const sign = act?.last_sign_in_at;
  const signDays = sign ? Math.floor((now - Date.parse(sign)) / DAY) : null;
  let activity = sign
    ? `${name} last signed in ${ago(sign, now)} (${fmtDate(sign)}).`
    : act ? `${name} has not signed in to the platform yet.` : `The last sign-in is not known.`;
  if (act) {
    activity += ` Active on ${act.active_days_30} of the last 30 days (${act.active_days_7} in the last week), with ${act.answered_30} graded answers in the last 30 days.`;
    const w = act.weeks;
    if (w.length === 4 && w.some(x => x > 0)) {
      const trend = w[3] === 0 && w[2] === 0 ? "no activity in the last two weeks"
        : w[3] > w[2] ? "more active this week than the week before" : w[3] < w[2] ? "less active this week than the week before" : "as active this week as the week before";
      activity += ` Active days per week over the last four weeks: ${w.join(", ")} (${trend}).`;
    }
  }
  if (!s.last_active_at) activity += ` No learning activity has been recorded in this organisation yet.`;
  paragraphs.push({ title: "Activity", text: activity });

  // ── Progress, and what changed since the previous report ──
  let progress = `${s.summary.rooms_completed} rooms completed (${s.summary.rooms_started} started), ${s.summary.scenarios_completed} scenarios, ${s.summary.sessions} live SOC shifts`
    + (m.first_try_pct !== null ? `; ${m.first_try_pct}% of ${m.first_try_items} graded questions answered right on the first try.` : `; no graded answers yet.`);
  let change = "first report";
  if (previous) {
    const p = previous.metrics;
    const parts: string[] = [];
    const d = (a: number, b: number, label: string) => { if (a !== b) parts.push(`${signed(Math.round(a - b))} ${label}`); };
    d(m.xp, p.xp, "XP");
    d(m.rooms_completed, p.rooms_completed, m.rooms_completed - p.rooms_completed === 1 ? "room completed" : "rooms completed");
    d(m.scenarios_completed, p.scenarios_completed, "scenarios");
    d(m.sessions, p.sessions, "live shifts");
    d(m.answered, p.answered, "graded answers");
    const acc = m.first_try_pct !== null && p.first_try_pct !== null && m.first_try_pct !== p.first_try_pct
      ? `right first try went from ${p.first_try_pct}% to ${m.first_try_pct}% (${signed(Math.round((m.first_try_pct - p.first_try_pct) * 10) / 10, " points")})` : null;
    const improved = Object.keys(m.areas).filter(k => p.areas[k] !== undefined && m.areas[k] - p.areas[k] >= 5);
    const slipped = Object.keys(m.areas).filter(k => p.areas[k] !== undefined && p.areas[k] - m.areas[k] >= 5);
    const label = (k: string) => s.skills.find(a => a.area === k)?.label ?? k;
    progress += ` Since the previous report (${fmtDate(previous.created_at)}): `
      + (parts.length ? parts.join(", ") : "no new activity")
      + (acc ? `; ${acc}` : "")
      + "."
      + (improved.length ? ` Improved in ${list(improved.map(label))}.` : "")
      + (slipped.length ? ` Slipped in ${list(slipped.map(label))}.` : "");
    change = parts.length || acc ? [parts.slice(0, 3).join(", "), acc ? `first try ${p.first_try_pct}% -> ${m.first_try_pct}%` : ""].filter(Boolean).join("; ") : "no change";
  } else {
    progress += " This is the first report on this learner, so there is nothing to compare with yet.";
  }
  paragraphs.push({ title: "Progress", text: progress });

  // ── Strengths and topics to strengthen ──
  const judged = s.skills.filter(a => a.items >= MIN_ITEMS && a.accuracy !== null);
  const strong = judged.filter(a => (a.accuracy ?? 0) >= 80).sort((a, b) => (b.accuracy ?? 0) - (a.accuracy ?? 0));
  const weak = judged.filter(a => (a.accuracy ?? 100) < 60).sort((a, b) => (a.accuracy ?? 0) - (b.accuracy ?? 0));
  const developing = judged.filter(a => (a.accuracy ?? 0) >= 60 && (a.accuracy ?? 0) < 80);
  let skills = judged.length === 0
    ? `Not enough graded answers yet to judge any topic (at least ${MIN_ITEMS} per topic are needed).`
    : (strong.length ? `Strong in ${list(strong.map(a => `${a.label} (${a.accuracy}%)`))}. ` : "No topic is strong yet. ");
  if (judged.length) {
    const toStrengthen = [...weak, ...developing.sort((a, b) => (a.accuracy ?? 0) - (b.accuracy ?? 0))].slice(0, 3);
    skills += toStrengthen.length
      ? `Needs strengthening in ${list(toStrengthen.map(a => `${a.label} (${a.accuracy}% right first try)`))}.`
      : "No topic needs strengthening right now.";
    if (s.recommendations.length) skills += ` Recommended next: ${list(s.recommendations.map(r => `the room "${r.title}"`))}.`;
    const untouched = s.skills.filter(a => a.items === 0).map(a => a.label);
    if (untouched.length) skills += ` Not practised yet: ${list(untouched.slice(0, 4))}${untouched.length > 4 ? " and more" : ""}.`;
  }
  paragraphs.push({ title: "Strengths and topics to strengthen", text: skills });

  // ── Learning plan ──
  const items = planItems(plan);
  if (items.length) {
    const tracked = items.filter(i => i.status !== "untracked");
    const done = tracked.filter(i => i.status === "done").length;
    const behind = items.filter(i => i.target_minutes && typeof i.minutes_spent === "number" && i.minutes_spent < i.target_minutes * 0.5 && i.status !== "done");
    const overdue = [...(plan?.personal ? [plan.personal] : []), ...(plan?.assigned ?? [])]
      .filter(p => p.due_at && Date.parse(p.due_at) < now && p.items.some(i => i.status !== "done" && i.status !== "untracked")).map(p => p.title);
    let t = `${done} of ${tracked.length} plan items done.`;
    if (overdue.length) t += ` Overdue: ${list(overdue)}.`;
    if (behind.length) t += ` Well under the target time on ${list(behind.slice(0, 3).map(i => i.title))}.`;
    paragraphs.push({ title: "Learning plan", text: t });
  }

  // ── What needs action ──
  const actions: string[] = [];
  if (!sign) actions.push("make sure the learner can sign in");
  else if (signDays !== null && signDays > 14) actions.push(`follow up: no sign-in for ${signDays} days`);
  if (m.open_mistakes > 0) actions.push(`${m.open_mistakes === 1 ? "1 mistake is" : `${m.open_mistakes} mistakes are`} still not corrected; reviewing ${m.open_mistakes === 1 ? "it" : "them"} is the fastest gain`);
  if (weak.length) actions.push(`assign practice in ${list(weak.slice(0, 2).map(a => a.label))}`);
  if (s.affiliation_expires_at && Date.parse(s.affiliation_expires_at) < now + 14 * DAY) actions.push("the enrolment ends within two weeks");
  if (actions.length) paragraphs.push({ title: "Needs action", text: actions.map(a => a.charAt(0).toUpperCase() + a.slice(1)).join(". ") + "." });

  const status: Narrative["status"] = !s.last_active_at && !sign ? "not started"
    : (signDays !== null && signDays > 14) || (act && act.active_days_30 === 0) ? "inactive"
    : weak.length || m.open_mistakes > 10 ? "needs attention" : "on track";
  return { status, paragraphs, change };
}
