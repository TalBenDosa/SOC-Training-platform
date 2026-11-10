/**
 * The learner's own Progress page, computed from their raw records (Progress v2).
 * Spec: claude-work/research/progress-redesign/SPEC-progress-self-tracking.md
 *
 * Pure and answer-free: the route (/api/me/progress) loads the rows, scoped to the
 * learner AND their current organisation (iron rule), and this module turns them into
 * the six tabs. Mastery uses the same engine as the org-admin student page (firstTry,
 * skillStats), so a learner and their instructor always see the same numbers.
 *
 * Rules carried from the spec:
 *  - mastery = right on the first try; retries are persistence, shown apart;
 *  - speed is never shown alone, always next to accuracy;
 *  - medians and p90, never means (one task left open must not move the picture);
 *  - an area with fewer than MIN_ITEMS answers is "not enough data", never "weak";
 *  - a "blind" scenario attempt (submitted in seconds) is listed but kept out of
 *    averages and trends.
 */
import { ROOMS_META } from "@/data/roomsMeta";
import { QUIZZES_META } from "@/data/catalogMeta";
import { groupItems, summarize, type AttemptLike, type ItemResult } from "@/lib/org/firstTry";
import { skillStats, judged, MIN_ITEMS, type AreaStat, type FirstAnswerRow } from "@/lib/org/skillStats";
import { areaOf, roomsInArea, ROOM_TITLE, QUIZ_TITLE, SCENARIO_TITLE } from "@/lib/skills/contentArea";
import { SKILL_LABEL, type SkillArea } from "@/lib/skills/taxonomy";
import { findLesson } from "@/lib/lessons/paths";
import { practiceFor } from "@/lib/team/practice";

// ─── Raw rows (what the route reads) ─────────────────────────────────────────

export interface AttemptRow extends AttemptLike { latency_ms: number | null }
export interface FirstRow extends FirstAnswerRow { created_at: string | null }
export interface RoomRow {
  room_id: string; completed_task_ids: string[] | null; xp_earned: number | null;
  telemetry: { taskId?: string; decisionLatencyMs?: number; submittedAt?: number }[] | null;
  completed_at: string | null; updated_at: string | null;
}
export interface ScenarioReportJson {
  verdict?: string | null; verdictReason?: string; notes?: string; reportScore?: number;
  rubric?: { verdict: number; depth: number; evidence: number; reasoning: number }; passed?: boolean;
}
export interface ScenarioDetailJson {
  items?: { key: string; label: string; points: number; max: number; detail: string }[];
  cappedByVerdict?: boolean; improvements?: string[]; summary?: string;
  citedIndicators?: string[]; missedIndicators?: string[] | null; fabricatedValues?: string[]; misattributedValues?: string[];
  aiFeedback?: string | null; quizScore?: number; words?: number; questions?: { id: string; correct: boolean }[];
}
export interface ScenarioRow {
  slug: string; title: string | null; score: number | null; xp_earned: number | null; time_taken: number | null;
  completed_at: string | null; report: ScenarioReportJson | null; report_detail?: ScenarioDetailJson | null;
}
export interface SessionRow {
  played_at: string | null; xp_earned: number | null; detect_rate: number | null; fn_count: number | null;
  avg_catch_ms: number | null; attacks_caught_count: number | null; attacks_presented_count: number | null;
  events_opened_count: number | null; duration_ms: number | null;
}
export interface IncidentRow {
  id: number; shift_key: string | null; incident_key: string | null; story_id: string | null; title: string;
  company: string | null; severity: string | null; mitre: string[] | null; outcome: "passed" | "failed" | "missed";
  injected_at: string | null; first_opened_at: string | null; report_opened_at: string | null; submitted_at: string;
  report_score: number | null; attack_score: number | null; ioc_score: number | null; action_score: number | null;
  graded_by: string | null; feedback: string | null; strengths: string[] | null; gaps: string[] | null;
  summary: string | null; missed_tell: string | null;
}
export interface QuizProgressRow { quiz_slug: string; best_score_pct: number | null; passed: boolean | null; attempts: number | null; first_completed_at: string | null; last_completed_at: string | null }
export interface LearningAttemptRow { kind: "quiz" | "lesson"; content_id: string; score_pct: number; correct: number; total: number; passed: boolean; created_at: string }
export interface LessonRow { lesson_key: string; best_quiz_pct: number | null; completed_at: string | null; quiz_passed_at: string | null }
export interface EdrRow { case_id: string; title: string | null; chosen: string | null; correct: boolean; duration_ms: number | null; created_at: string }

/** The learner's own card from a cached team after-action report (UserReport subset). */
export interface TeamCardRaw {
  session_id: string; status: string; started_at: string | null; ended_at: string | null; company_id: string | null; role: string | null;
  card: {
    role?: string; rubricPct?: number | null; insufficientEvidence?: boolean;
    rubric?: { label: string; score: number; note?: string }[];
    slaMet?: number; slaTotal?: number; slaPct?: number | null; firstActionS?: number | null;
    dispAcc?: number | null; dispCount?: number; blindCalls?: number; isoPct?: number | null; isolations?: unknown[];
    reported?: { label: string; severity: string; responseS: number | null; slaS: number; withinSla: boolean | null }[];
    falseNegatives?: TeamMissRaw[]; walkedPast?: TeamMissRaw[]; falseAlarms?: TeamMissRaw[];
    forensic?: { accPct?: number | null } | null;
  } | null;
}
export interface TeamMissRaw { label: string; severity: string; technique?: string; practice?: { id: string; title: string } }

export interface RawRows {
  now: number;
  attempts: AttemptRow[];
  firsts: FirstRow[];
  rooms: RoomRow[];
  scenarios: ScenarioRow[];
  sessions: SessionRow[];
  incidents: IncidentRow[];
  quizzes: QuizProgressRow[];
  learning: LearningAttemptRow[];
  lessons: LessonRow[];
  edr: EdrRow[];
  team: TeamCardRaw[];
  /** MITRE technique id → its tactic name (the route resolves it; this module stays small). */
  tacticOf: (technique: string) => string | null;
}

// ─── Output ──────────────────────────────────────────────────────────────────

export type ActivityKind = "room" | "quiz" | "lesson" | "scenario" | "shift" | "team" | "edr";

export interface StatBlock { count: number; median: number | null; p90: number | null }
export interface TrendArea extends AreaStat {
  level: "strong" | "developing" | "weak" | "insufficient";
  /** Accuracy in the last 30 days vs the 30 before; null when either side has too few answers. */
  trend: { now: number; prev: number } | null;
  practice: { kind: "room" | "quiz"; id: string; title: string; href: string }[];
}
export interface NextStep { label: string; detail: string; href: string }
export interface TimelineItem {
  kind: ActivityKind; id: string; title: string; at: string; result: string;
  /** Minutes spent, when known. */
  minutes: number | null;
  href: string | null;
  /** Scenario rows: one per scenario, every attempt listed. */
  attempts?: { at: string; score: number; timeS: number; blind: boolean }[];
  blind?: boolean;
}
export interface ScenarioAttemptView {
  at: string; score: number; xp: number; timeS: number; blind: boolean;
  verdict: string | null; verdictReason: string; notes: string; reportScore: number | null; passed: boolean | null;
  items: { key: string; label: string; points: number; max: number; detail: string }[];
  improvements: string[]; summary: string | null; aiFeedback: string | null;
  citedIndicators: string[]; missedIndicators: string[] | null; fabricatedValues: string[]; misattributedValues: string[];
  quizScore: number | null; questions: { id: string; correct: boolean }[] | null;
  /** False for an attempt recorded before the full breakdown was kept (rubric only). */
  hasDetail: boolean;
}
export interface QualityPoint { at: string; source: "scenario" | "incident"; title: string; identification: number; evidence: number; depth: number }

export interface ProgressPayload {
  generatedAt: string;
  periodDays: number;
  overview: {
    tiles: {
      done: { now: number; prev: number };
      firstTry: { now: number | null; prev: number | null; items: number };
      missed: { now: number; prev: number };
      response: { label: string; nowMs: number | null; prevMs: number | null; targetMs: number | null };
    };
    sentences: string[];
    next: NextStep[];
  };
  activity: {
    weeks: { start: string; counts: Record<ActivityKind, number>; minutes: number }[];
    days: { date: string; count: number }[];
    timeline: TimelineItem[];
    totals: { minutes: number; items: number };
  };
  skills: {
    areas: TrendArea[];
    tactics: { tactic: string; items: number; firstTryCorrect: number; accuracy: number }[];
    firstTry: { items: number; firstTryCorrect: number; accuracy: number | null; unsolved: number };
    persistence: { avgTriesToSolve: number | null; solvedAfterRetry: number };
  };
  response: {
    rooms: StatBlock & { accuracy: number | null; byType: { type: string; label: string; count: number; median: number | null; accuracy: number | null; fastRight: number; fastWrong: number; slowRight: number; slowWrong: number }[]; source: "attempts" | "telemetry" | "none" };
    blindCalls: { count: number; wrong: number };
    live: { notice: StatBlock; investigate: StatBlock; write: StatBlock; total: StatBlock & { withinTarget: number | null }; targetMs: number; source: "incidents" | "sessions" | "none"; bySeverity: { severity: string; median: number | null; count: number }[] };
    scenarios: StatBlock;
    edr: StatBlock & { accuracy: number | null };
    team: { firstAction: StatBlock; slaMet: number; slaTotal: number; bySeverity: { severity: string; median: number | null; count: number; target: number }[] };
    weekly: { start: string; roomMedianMs: number | null; roomAccuracy: number | null; liveMedianMs: number | null }[];
  };
  reports: {
    scenarios: { slug: string; title: string; best: number; last: number; count: number; attempts: ScenarioAttemptView[] }[];
    incidents: IncidentRow[];
    team: { sessionId: string; at: string | null; role: string | null; company: string | null; ready: boolean; rubricPct: number | null; insufficientEvidence: boolean; rubric: { label: string; score: number; note?: string }[]; slaPct: number | null; slaMet: number; slaTotal: number; firstActionS: number | null; dispAcc: number | null; isoPct: number | null; isolations: number; blindCalls: number; forensicAccPct: number | null; misses: (TeamMissRaw & { kind: "called benign" | "walked past" | "false alarm" })[] }[];
    quizzes: { slug: string; title: string; best: number | null; passed: boolean; attempts: { at: string; score: number; passed: boolean }[] }[];
    lessons: { key: string; title: string; best: number | null; passed: boolean; attempts: { at: string; score: number; passed: boolean }[] }[];
    edr: EdrRow[];
    quality: { points: QualityPoint[]; weakest: { key: "identification" | "evidence" | "depth"; count: number; of: number; advice: string } | null };
  };
  /** Missed attacks from the live feed and team exercises (room analyst-verdict misses come from /api/me/mistakes). */
  criticalMisses: { source: "live" | "team"; title: string; at: string | null; detail: string | null; technique: string | null; practice: { id: string; title: string } | null }[];
}

// ─── Small helpers ───────────────────────────────────────────────────────────

const DAY = 86_400_000;
const WEEK = 7 * DAY;
/** Live-feed response target (useLiveEvents SLA_SECONDS). */
export const LIVE_TARGET_MS = 900_000;
/** A scenario attempt under this, or under 10% of the scenario's median, is "blind". */
export const BLIND_SCENARIO_S = 30;
/** A decision this soon after the task opened (same rule as the team report's BLIND_CALL_MS). */
export const BLIND_DECISION_MS = 3_000;
const MAX_DECISION_MS = 5 * 60_000;
/** A team shift runs 20, 30 or 45 minutes; a session ended hours later by the reaper is not active time. */
const MAX_TEAM_SHIFT_MS = 60 * 60_000;
const TEAM_SLA_S: Record<string, number> = { critical: 60, high: 180, medium: 600 };

const ts = (s: string | null | undefined): number | null => { if (!s) return null; const t = Date.parse(s); return Number.isNaN(t) ? null : t; };
export function median(xs: number[]): number | null {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b); const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2);
}
export function p90(xs: number[]): number | null {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil(0.9 * s.length) - 1)];
}
const stat = (xs: number[]): StatBlock => ({ count: xs.length, median: median(xs), p90: p90(xs) });
const pct = (a: number, b: number) => (b > 0 ? Math.round((a / b) * 100) : null);
/** Monday 00:00 UTC of the week containing t. */
export function weekStart(t: number): number { const d = new Date(t); const day = (d.getUTCDay() + 6) % 7; return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - day * DAY; }
const dayKey = (t: number) => new Date(t).toISOString().slice(0, 10);
const inRange = (t: number | null, from: number, to: number) => t !== null && t >= from && t < to;

const ROOM_TASKS = new Map<string, Map<string, { type: string; mitre?: string }>>(
  ROOMS_META.map(r => [r.id, new Map(r.tasks.map(t => [t.id, { type: t.type, mitre: t.mitreTechnique }]))]));
const TASK_LABEL: Record<string, string> = {
  question: "Multiple choice", log_analysis: "Log analysis", flag: "Find the flag", analyst_choice: "Analyst verdict",
  matching: "Matching", ordering: "Ordering", query_fill: "Query", written_report: "Written report", mission: "Mission",
};
export function lessonTitle(key: string): string {
  const sep = key.indexOf("--");
  const found = sep > 0 ? findLesson(key.slice(0, sep), key.slice(sep + 2)) : null;
  return found?.lesson.title ?? key;
}
const scenarioTitle = (slug: string, title?: string | null) => title || SCENARIO_TITLE[slug] || slug;

/** Which attempts of each scenario were "blind": seconds, not an investigation. */
export function blindAttempts(rows: ScenarioRow[]): Set<ScenarioRow> {
  const out = new Set<ScenarioRow>();
  const by = new Map<string, ScenarioRow[]>();
  for (const r of rows) { const l = by.get(r.slug) ?? []; l.push(r); by.set(r.slug, l); }
  for (const list of by.values()) {
    const times = list.map(r => r.time_taken ?? 0).filter(t => t >= BLIND_SCENARIO_S);
    const med = times.length >= 3 ? median(times) : null;
    for (const r of list) {
      const t = r.time_taken ?? 0;
      if (t < BLIND_SCENARIO_S || (med !== null && t < med * 0.1)) out.add(r);
    }
  }
  return out;
}

function level(a: AreaStat): TrendArea["level"] {
  if (a.items < MIN_ITEMS || a.accuracy === null) return "insufficient";
  return a.accuracy >= 80 ? "strong" : a.accuracy >= 60 ? "developing" : "weak";
}

const RUBRIC_MAX = { verdict: 25, depth: 25, evidence: 30, reasoning: 20 } as const;
const RUBRIC_LABEL = { verdict: "Verdict", depth: "Depth", evidence: "Evidence", reasoning: "Reasoning" } as const;
const QUALITY_ADVICE: Record<"identification" | "evidence" | "depth", string> = {
  identification: "Name the exact attack and the technique ID it matches, not just the category.",
  evidence: "Cite the exact value (IP, hash, user, host) and the log it came from.",
  depth: "Explain why the evidence points to that conclusion, then the action and the business impact.",
};

// ─── Builder ─────────────────────────────────────────────────────────────────

export function buildProgress(raw: RawRows, opts: { periodDays?: number } = {}): ProgressPayload {
  const now = raw.now;
  /** The overview period ("this week" by default; the printable report picks 7 / 30 / 90). */
  const periodDays = Math.min(365, Math.max(1, Math.round(opts.periodDays ?? 7)));
  const PERIOD = periodDays * DAY;
  const items = groupItems(raw.attempts);
  const firstTry = summarize(items);
  const blind = blindAttempts(raw.scenarios);
  const realScenarios = raw.scenarios.filter(r => !blind.has(r));
  const itemAt = (i: ItemResult<AttemptRow>) => ts(i.attempts[0]?.created_at ?? null);

  // ── per-room first-try record (for the timeline) ──
  const roomItems = new Map<string, ItemResult<AttemptRow>[]>();
  for (const it of items) { const l = roomItems.get(it.room_id) ?? []; l.push(it); roomItems.set(it.room_id, l); }

  // ── timeline ──
  const timeline: TimelineItem[] = [];
  for (const r of raw.rooms) {
    const at = r.completed_at ?? r.updated_at; if (!at) continue;
    const mine = roomItems.get(r.room_id) ?? [];
    const lat = (r.telemetry ?? []).map(t => t.decisionLatencyMs).filter((x): x is number => typeof x === "number" && x >= 0).map(x => Math.min(x, MAX_DECISION_MS));
    timeline.push({
      kind: "room", id: r.room_id, title: ROOM_TITLE[r.room_id] ?? r.room_id, at,
      result: mine.length ? `${mine.filter(i => i.firstTryCorrect).length}/${mine.length} right first try${r.completed_at ? "" : " · in progress"}` : (r.completed_at ? "Completed" : "In progress"),
      minutes: lat.length ? Math.max(1, Math.round(lat.reduce((s, x) => s + x, 0) / 60_000)) : null,
      href: `/rooms/${encodeURIComponent(r.room_id)}`,
    });
  }
  const quizAttempts = raw.learning.filter(a => a.kind === "quiz");
  const lessonAttempts = raw.learning.filter(a => a.kind === "lesson");
  const quizSeen = new Set(quizAttempts.map(a => a.content_id));
  const attemptNo = new Map<string, number>();
  for (const a of [...raw.learning].sort((x, y) => Date.parse(x.created_at) - Date.parse(y.created_at))) {
    const k = `${a.kind}|${a.content_id}`; const n = (attemptNo.get(k) ?? 0) + 1; attemptNo.set(k, n);
    timeline.push({
      kind: a.kind, id: a.content_id, title: a.kind === "quiz" ? (QUIZ_TITLE[a.content_id] ?? a.content_id) : lessonTitle(a.content_id), at: a.created_at,
      result: `${a.score_pct}% (${a.correct}/${a.total})${a.passed ? " · passed" : ""}${n > 1 ? ` · attempt ${n}` : ""}`,
      minutes: null, href: a.kind === "quiz" ? `/quizzes/${encodeURIComponent(a.content_id)}` : null,
    });
  }
  // Quizzes finished before every attempt was kept: one line from the best-score record.
  for (const q of raw.quizzes) {
    if (quizSeen.has(q.quiz_slug) || !q.last_completed_at) continue;
    timeline.push({ kind: "quiz", id: q.quiz_slug, title: QUIZ_TITLE[q.quiz_slug] ?? q.quiz_slug, at: q.last_completed_at,
      result: `Best ${q.best_score_pct ?? 0}%${(q.attempts ?? 0) > 1 ? ` · ${q.attempts} attempts` : ""}`, minutes: null, href: `/quizzes/${encodeURIComponent(q.quiz_slug)}` });
  }
  const lessonSeen = new Set(lessonAttempts.map(a => a.content_id));
  for (const l of raw.lessons) {
    if (lessonSeen.has(l.lesson_key) || !l.completed_at) continue;
    timeline.push({ kind: "lesson", id: l.lesson_key, title: lessonTitle(l.lesson_key), at: l.completed_at,
      result: `Knowledge check ${l.best_quiz_pct ?? 0}% · passed`, minutes: null, href: null });
  }
  const bySlug = new Map<string, ScenarioRow[]>();
  for (const r of raw.scenarios) { const l = bySlug.get(r.slug) ?? []; l.push(r); bySlug.set(r.slug, l); }
  for (const [slug, list] of bySlug) {
    const sorted = [...list].sort((a, b) => (ts(b.completed_at) ?? 0) - (ts(a.completed_at) ?? 0));
    const real = sorted.filter(r => !blind.has(r));
    const last = sorted[0];
    const best = Math.max(...(real.length ? real : sorted).map(r => r.score ?? 0));
    timeline.push({
      kind: "scenario", id: slug, title: scenarioTitle(slug, last.title), at: last.completed_at ?? new Date(now).toISOString(),
      result: `${last.score ?? 0}%${sorted.length > 1 ? ` · best ${best}% of ${sorted.length} attempts` : ""}`,
      minutes: real.length ? Math.round(real.reduce((s, r) => s + (r.time_taken ?? 0), 0) / 60) : null,
      href: `/scenarios/${encodeURIComponent(slug)}`,
      attempts: sorted.map(r => ({ at: r.completed_at ?? "", score: r.score ?? 0, timeS: r.time_taken ?? 0, blind: blind.has(r) })),
      blind: blind.has(last),
    });
  }
  for (const s of raw.sessions) {
    if (!s.played_at) continue;
    const caught = s.attacks_caught_count ?? 0, presented = s.attacks_presented_count ?? 0, missed = s.fn_count ?? 0;
    timeline.push({ kind: "shift", id: s.played_at, title: "Live SOC shift", at: s.played_at,
      result: `${caught}/${presented} attacks caught${missed ? ` · ${missed} missed` : ""} · ${s.events_opened_count ?? 0} logs opened`,
      minutes: s.duration_ms ? Math.max(1, Math.round(s.duration_ms / 60_000)) : null, href: "/dashboard" });
  }
  for (const t of raw.team) {
    const at = t.ended_at ?? t.started_at; if (!at) continue;
    const c = t.card;
    const mins = t.started_at && t.ended_at ? Math.round(Math.min(Date.parse(t.ended_at) - Date.parse(t.started_at), MAX_TEAM_SHIFT_MS) / 60_000) : null;
    timeline.push({ kind: "team", id: t.session_id, title: "Team exercise", at,
      result: c ? [c.role ?? t.role, c.rubricPct != null ? `rubric ${c.rubricPct}%` : null, c.slaPct != null ? `SLA ${c.slaPct}%` : null].filter(Boolean).join(" · ") : `${t.role ?? "Member"} · report not built yet`,
      minutes: mins !== null && mins >= 0 ? mins : null, href: `/team/${t.session_id}` });
  }
  for (const e of raw.edr) {
    timeline.push({ kind: "edr", id: `${e.case_id}|${e.created_at}`, title: e.title ?? e.case_id, at: e.created_at,
      result: `${e.correct ? "Correct" : "Not quite"} · ${e.chosen ?? ""}`.trim(), minutes: e.duration_ms ? Math.max(1, Math.round(e.duration_ms / 60_000)) : null,
      href: `/edr?case=${encodeURIComponent(e.case_id)}` });
  }
  timeline.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));

  // ── activity counts and minutes per event ──
  type Ev = { kind: ActivityKind; t: number; minutes: number };
  const events: Ev[] = [];
  for (const r of raw.rooms) for (const tel of r.telemetry ?? []) {
    if (typeof tel.decisionLatencyMs === "number" && typeof tel.submittedAt === "number") events.push({ kind: "room", t: tel.submittedAt, minutes: Math.min(tel.decisionLatencyMs, MAX_DECISION_MS) / 60_000 });
  }
  const countEvents: Ev[] = [];
  for (const r of raw.rooms) { const t = ts(r.completed_at); if (t !== null) countEvents.push({ kind: "room", t, minutes: 0 }); }
  for (const a of raw.learning) { const t = ts(a.created_at); if (t !== null) countEvents.push({ kind: a.kind, t, minutes: 0 }); }
  for (const q of raw.quizzes) if (!quizSeen.has(q.quiz_slug)) { const t = ts(q.last_completed_at); if (t !== null) countEvents.push({ kind: "quiz", t, minutes: 0 }); }
  for (const l of raw.lessons) if (!lessonSeen.has(l.lesson_key)) { const t = ts(l.completed_at); if (t !== null) countEvents.push({ kind: "lesson", t, minutes: 0 }); }
  for (const r of realScenarios) { const t = ts(r.completed_at); if (t !== null) { countEvents.push({ kind: "scenario", t, minutes: 0 }); events.push({ kind: "scenario", t, minutes: (r.time_taken ?? 0) / 60 }); } }
  for (const s of raw.sessions) { const t = ts(s.played_at); if (t !== null) { countEvents.push({ kind: "shift", t, minutes: 0 }); events.push({ kind: "shift", t, minutes: (s.duration_ms ?? 0) / 60_000 }); } }
  for (const tm of raw.team) { const t = ts(tm.ended_at ?? tm.started_at); if (t !== null) { countEvents.push({ kind: "team", t, minutes: 0 }); const st = ts(tm.started_at), en = ts(tm.ended_at); if (st !== null && en !== null && en > st) events.push({ kind: "team", t, minutes: Math.min(en - st, MAX_TEAM_SHIFT_MS) / 60_000 }); } }
  for (const e of raw.edr) { const t = ts(e.created_at); if (t !== null) { countEvents.push({ kind: "edr", t, minutes: 0 }); events.push({ kind: "edr", t, minutes: Math.min(e.duration_ms ?? 0, 3_600_000) / 60_000 }); } }

  const thisWeek = weekStart(now);
  const weeks = Array.from({ length: 8 }, (_, i) => thisWeek - (7 - i) * WEEK).map(start => {
    const counts: Record<ActivityKind, number> = { room: 0, quiz: 0, lesson: 0, scenario: 0, shift: 0, team: 0, edr: 0 };
    for (const e of countEvents) if (inRange(e.t, start, start + WEEK)) counts[e.kind]++;
    const minutes = Math.round(events.filter(e => inRange(e.t, start, start + WEEK)).reduce((s, e) => s + e.minutes, 0));
    return { start: new Date(start).toISOString(), counts, minutes };
  });
  const dayCounts = new Map<string, number>();
  for (const e of countEvents) dayCounts.set(dayKey(e.t), (dayCounts.get(dayKey(e.t)) ?? 0) + 1);
  for (const it of items) { const t = itemAt(it); if (t !== null) dayCounts.set(dayKey(t), (dayCounts.get(dayKey(t)) ?? 0) + 1); }
  const today = Date.UTC(new Date(now).getUTCFullYear(), new Date(now).getUTCMonth(), new Date(now).getUTCDate());
  const days = Array.from({ length: 84 }, (_, i) => { const k = dayKey(today - (83 - i) * DAY); return { date: k, count: dayCounts.get(k) ?? 0 }; });

  // ── overview tiles (this week vs last week) ──
  const wFrom = now - PERIOD, pFrom = now - 2 * PERIOD;
  const done = (from: number, to: number) => countEvents.filter(e => inRange(e.t, from, to)).length;
  const firstTryIn = (from: number, to: number) => {
    let n = 0, ok = 0;
    for (const it of items) if (inRange(itemAt(it), from, to)) { n++; if (it.firstTryCorrect) ok++; }
    for (const f of raw.firsts) if (inRange(ts(f.created_at), from, to)) { n++; if (f.correct) ok++; }
    return { n, pct: pct(ok, n) };
  };
  const passedIncidents = firstPassPerIncident(raw.incidents);
  const liveTotals = (from: number, to: number) => passedIncidents
    .filter(i => inRange(ts(i.submitted_at), from, to))
    .map(i => { const a = ts(i.injected_at), b = ts(i.submitted_at); return a !== null && b !== null && b >= a ? b - a : null; })
    .filter((x): x is number => x !== null);
  const sessionCatch = (from: number, to: number) => raw.sessions.filter(s => inRange(ts(s.played_at), from, to)).map(s => s.avg_catch_ms).filter((x): x is number => typeof x === "number" && x > 0);
  const roomLatency = (from: number, to: number) => {
    const xs: number[] = [];
    for (const it of items) { const a = it.attempts[0]; if (a?.latency_ms != null && inRange(ts(a.created_at ?? null), from, to)) xs.push(Math.min(a.latency_ms, MAX_DECISION_MS)); }
    return xs;
  };
  const missedIn = (from: number, to: number) => {
    const live = Math.max(
      raw.incidents.filter(i => i.outcome === "missed" && inRange(ts(i.submitted_at), from, to)).length,
      raw.sessions.filter(s => inRange(ts(s.played_at), from, to)).reduce((s, x) => s + (x.fn_count ?? 0), 0));
    const team = raw.team.filter(t => inRange(ts(t.ended_at), from, to)).reduce((s, t) => s + (t.card?.falseNegatives?.length ?? 0) + (t.card?.walkedPast?.length ?? 0), 0);
    return live + team;
  };
  const hasLive = passedIncidents.length > 0 || raw.sessions.some(s => (s.avg_catch_ms ?? 0) > 0);
  const responseTile = hasLive
    ? { label: "Live-feed response (median)", nowMs: median(liveTotals(wFrom, now).length ? liveTotals(wFrom, now) : sessionCatch(wFrom, now)), prevMs: median(liveTotals(pFrom, wFrom).length ? liveTotals(pFrom, wFrom) : sessionCatch(pFrom, wFrom)), targetMs: LIVE_TARGET_MS }
    : { label: "Decision time per question (median)", nowMs: median(roomLatency(wFrom, now)), prevMs: median(roomLatency(pFrom, wFrom)), targetMs: null };
  const ftNow = firstTryIn(wFrom, now), ftPrev = firstTryIn(pFrom, wFrom);

  // ── skills ──
  const stats = skillStats(items, raw.firsts);
  const statsIn = (from: number, to: number) => skillStats(items.filter(i => inRange(itemAt(i), from, to)), raw.firsts.filter(f => inRange(ts(f.created_at), from, to)));
  const last30 = statsIn(now - 30 * DAY, now + DAY), prev30 = statsIn(now - 60 * DAY, now - 30 * DAY);
  const doneRooms = new Set(raw.rooms.filter(r => r.completed_at).map(r => r.room_id));
  const passedQuizzes = new Set([...raw.quizzes.filter(q => q.passed).map(q => q.quiz_slug), ...quizAttempts.filter(a => a.passed).map(a => a.content_id)]);
  const rank: Record<string, number> = { beginner: 0, intermediate: 1, advanced: 2, Beginner: 0, Intermediate: 1, Advanced: 2 };
  const practiceIn = (area: SkillArea): TrendArea["practice"] => [
    ...roomsInArea(area).filter(r => !doneRooms.has(r.id)).sort((a, b) => (rank[a.difficulty] ?? 1) - (rank[b.difficulty] ?? 1)).slice(0, 3)
      .map(r => ({ kind: "room" as const, id: r.id, title: r.title, href: `/rooms/${encodeURIComponent(r.id)}` })),
    ...QUIZZES_META.filter(q => areaOf("quiz", q.slug) === area && !passedQuizzes.has(q.slug)).slice(0, 2)
      .map(q => ({ kind: "quiz" as const, id: q.slug, title: q.title, href: `/quizzes/${encodeURIComponent(q.slug)}` })),
  ];
  const areas: TrendArea[] = stats.map(a => {
    const n = last30.find(x => x.area === a.area)!, p = prev30.find(x => x.area === a.area)!;
    return { ...a, level: level(a), trend: n.items >= MIN_ITEMS && p.items >= MIN_ITEMS ? { now: n.accuracy ?? 0, prev: p.accuracy ?? 0 } : null, practice: practiceIn(a.area) };
  }).sort((x, y) => {
    const order = { weak: 0, developing: 1, strong: 2, insufficient: 3 } as const;
    return order[x.level] - order[y.level] || (x.accuracy ?? 101) - (y.accuracy ?? 101) || y.items - x.items;
  });
  const tacticMap = new Map<string, { items: number; ok: number }>();
  for (const it of items) {
    const tech = ROOM_TASKS.get(it.room_id)?.get(it.task_id)?.mitre; if (!tech) continue;
    const tac = raw.tacticOf(tech); if (!tac) continue;
    const e = tacticMap.get(tac) ?? { items: 0, ok: 0 }; e.items++; if (it.firstTryCorrect) e.ok++; tacticMap.set(tac, e);
  }
  const tactics = [...tacticMap.entries()].map(([tactic, e]) => ({ tactic, items: e.items, firstTryCorrect: e.ok, accuracy: Math.round((e.ok / e.items) * 100) }))
    .sort((a, b) => a.accuracy - b.accuracy || b.items - a.items);
  const retried = items.filter(i => i.solved && !i.firstTryCorrect);
  const tries = items.filter(i => i.triesToSolve !== null).map(i => i.triesToSolve!);

  // ── sentences + next steps ──
  const judgedAreas = judged(stats);
  const strongest = [...judgedAreas].reverse().find(a => (a.accuracy ?? 0) >= 80);
  const weakest = judgedAreas.find(a => (a.accuracy ?? 100) < 80);
  const weekKinds = countEvents.filter(e => inRange(e.t, wFrom, now));
  const kindWord: Record<ActivityKind, [string, string]> = { room: ["room", "rooms"], quiz: ["quiz", "quizzes"], lesson: ["lesson check", "lesson checks"], scenario: ["scenario", "scenarios"], shift: ["live shift", "live shifts"], team: ["team exercise", "team exercises"], edr: ["EDR case", "EDR cases"] };
  const parts = (Object.keys(kindWord) as ActivityKind[]).map(k => { const n = weekKinds.filter(e => e.kind === k).length; return n ? `${n} ${kindWord[k][n === 1 ? 0 : 1]}` : null; }).filter(Boolean) as string[];
  const sentences: string[] = [];
  sentences.push(parts.length ? `In the last ${periodDays} days you completed ${parts.length > 1 ? `${parts.slice(0, -1).join(", ")} and ${parts[parts.length - 1]}` : parts[0]}.` : `Nothing completed in the last ${periodDays} days yet.`);
  if (strongest) sentences.push(`Strongest: ${strongest.label} (${strongest.accuracy}% right first try).`);
  if (weakest) sentences.push(`Needs work: ${weakest.label} (${weakest.accuracy}%, ${weakest.items} questions).`);
  else if (judgedAreas.length === 0) sentences.push(`Answer at least ${MIN_ITEMS} questions in a topic to see how strong you are in it.`);
  const weekMisses = [
    ...raw.incidents.filter(i => i.outcome === "missed" && inRange(ts(i.submitted_at), wFrom, now)).map(i => i.title),
    ...raw.team.filter(t => inRange(ts(t.ended_at), wFrom, now)).flatMap(t => [...(t.card?.falseNegatives ?? []), ...(t.card?.walkedPast ?? [])].map(m => m.label)),
  ];
  // Same count as the "Missed attacks" tile (a live miss also counted only in a shift's total).
  const weekMissCount = Math.max(weekMisses.length, missedIn(wFrom, now));
  if (weekMissCount) sentences.push(`You missed ${weekMissCount} attack${weekMissCount > 1 ? "s" : ""}${weekMisses.length ? `: ${[...new Set(weekMisses)].slice(0, 2).join(", ")}${weekMissCount > 2 ? " and more" : ""}` : ""}.`);

  const next: NextStep[] = [];
  const focus = weakest;
  if (focus) {
    const p = practiceIn(focus.area);
    const room = p.find(x => x.kind === "room"); const quiz = p.find(x => x.kind === "quiz");
    if (room) next.push({ label: `Room: ${room.title}`, detail: `Builds ${focus.label}, your weakest topic`, href: room.href });
    if (quiz) next.push({ label: `Quiz: ${quiz.title}`, detail: `Checks ${focus.label}`, href: quiz.href });
  }
  const toReview = items.filter(i => !i.firstTryCorrect).length + raw.firsts.filter(f => !f.correct).length;
  if (toReview > 0) next.push({ label: `Review ${toReview} mistake${toReview > 1 ? "s" : ""}`, detail: "Questions you did not get right the first time", href: "/progress?tab=mistakes" });
  if (next.length < 3) {
    const nextRoom = ROOMS_META.filter(r => !doneRooms.has(r.id)).sort((a, b) => (rank[a.difficulty] ?? 1) - (rank[b.difficulty] ?? 1))[0];
    if (nextRoom && !next.some(n => n.href.endsWith(encodeURIComponent(nextRoom.id)))) next.push({ label: `Room: ${nextRoom.title}`, detail: SKILL_LABEL[areaOf("room", nextRoom.id)], href: `/rooms/${encodeURIComponent(nextRoom.id)}` });
  }

  // ── response times ──
  const firstAttempts = items.map(i => i.attempts[0]).filter((a): a is AttemptRow => !!a);
  const withLatency = firstAttempts.filter(a => typeof a.latency_ms === "number" && a.latency_ms >= 0);
  let roomSource: ProgressPayload["response"]["rooms"]["source"] = withLatency.length ? "attempts" : "none";
  let roomLat = withLatency.map(a => Math.min(a.latency_ms!, MAX_DECISION_MS));
  if (!roomLat.length) {
    roomLat = raw.rooms.flatMap(r => (r.telemetry ?? []).map(t => t.decisionLatencyMs)).filter((x): x is number => typeof x === "number" && x >= 0).map(x => Math.min(x, MAX_DECISION_MS));
    if (roomLat.length) roomSource = "telemetry";
  }
  const byTypeMap = new Map<string, AttemptRow[]>();
  for (const a of withLatency) { const l = byTypeMap.get(a.task_type ?? "task") ?? []; l.push(a); byTypeMap.set(a.task_type ?? "task", l); }
  const byType = [...byTypeMap.entries()].map(([type, list]) => {
    const lat = list.map(a => Math.min(a.latency_ms!, MAX_DECISION_MS)); const med = median(lat) ?? 0;
    const q = { fastRight: 0, fastWrong: 0, slowRight: 0, slowWrong: 0 };
    for (const a of list) { const fast = Math.min(a.latency_ms!, MAX_DECISION_MS) < med; if (fast) { if (a.correct) q.fastRight++; else q.fastWrong++; } else { if (a.correct) q.slowRight++; else q.slowWrong++; } }
    return { type, label: TASK_LABEL[type] ?? type, count: list.length, median: median(lat), accuracy: pct(list.filter(a => a.correct).length, list.length), ...q };
  }).sort((a, b) => b.count - a.count);
  const blindList = withLatency.filter(a => a.latency_ms! < BLIND_DECISION_MS);

  const incidentSpans = passedIncidents.map(i => ({
    sev: i.severity ?? "high",
    notice: diff(i.injected_at, i.first_opened_at), investigate: diff(i.first_opened_at, i.report_opened_at),
    write: diff(i.report_opened_at, i.submitted_at), total: diff(i.injected_at, i.submitted_at),
  }));
  const totals = incidentSpans.map(s => s.total).filter((x): x is number => x !== null);
  const sessionAvgs = raw.sessions.map(s => s.avg_catch_ms).filter((x): x is number => typeof x === "number" && x > 0);
  const liveSource: ProgressPayload["response"]["live"]["source"] = totals.length ? "incidents" : sessionAvgs.length ? "sessions" : "none";
  const liveTotalXs = totals.length ? totals : sessionAvgs;
  const sevs = [...new Set(incidentSpans.map(s => s.sev))];

  const scenarioTimes = realScenarios.map(r => (r.time_taken ?? 0) * 1000).filter(x => x > 0);
  const edrTimes = raw.edr.map(e => e.duration_ms).filter((x): x is number => typeof x === "number" && x > 0);
  const teamFirst = raw.team.map(t => t.card?.firstActionS).filter((x): x is number => typeof x === "number" && x >= 0).map(x => x * 1000);
  const teamReported = raw.team.flatMap(t => t.card?.reported ?? []);
  const teamSev = ["critical", "high", "medium"].map(sev => {
    const xs = teamReported.filter(r => r.severity === sev && typeof r.responseS === "number").map(r => r.responseS! * 1000);
    return { severity: sev, median: median(xs), count: xs.length, target: (TEAM_SLA_S[sev] ?? 1800) * 1000 };
  }).filter(x => x.count > 0);
  const weekly = weeks.map(w => {
    const from = Date.parse(w.start), to = from + WEEK;
    const fa = firstAttempts.filter(a => inRange(ts(a.created_at ?? null), from, to));
    const lat = fa.filter(a => typeof a.latency_ms === "number").map(a => Math.min(a.latency_ms!, MAX_DECISION_MS));
    return { start: w.start, roomMedianMs: median(lat), roomAccuracy: pct(fa.filter(a => a.correct).length, fa.length), liveMedianMs: median(liveTotals(from, to)) };
  });

  // ── reports ──
  const scenarioReports = [...bySlug.entries()].map(([slug, list]) => {
    const sorted = [...list].sort((a, b) => (ts(b.completed_at) ?? 0) - (ts(a.completed_at) ?? 0));
    const real = sorted.filter(r => !blind.has(r));
    const attempts = sorted.map(r => scenarioAttemptView(r, blind.has(r)));
    return { slug, title: scenarioTitle(slug, sorted[0]?.title), best: Math.max(0, ...(real.length ? real : sorted).map(r => r.score ?? 0)), last: sorted[0]?.score ?? 0, count: sorted.length, attempts };
  }).sort((a, b) => (ts(b.attempts[0]?.at) ?? 0) - (ts(a.attempts[0]?.at) ?? 0));

  const teamReports = raw.team.map(t => {
    const c = t.card;
    const misses = c ? [
      ...(c.falseNegatives ?? []).map(m => ({ ...m, kind: "called benign" as const })),
      ...(c.walkedPast ?? []).map(m => ({ ...m, kind: "walked past" as const })),
      ...(c.falseAlarms ?? []).map(m => ({ ...m, kind: "false alarm" as const })),
    ].slice(0, 20) : [];
    return {
      sessionId: t.session_id, at: t.ended_at ?? t.started_at, role: c?.role ?? t.role, company: t.company_id, ready: !!c,
      rubricPct: c?.rubricPct ?? null, insufficientEvidence: !!c?.insufficientEvidence, rubric: (c?.rubric ?? []).slice(0, 12),
      slaPct: c?.slaPct ?? null, slaMet: c?.slaMet ?? 0, slaTotal: c?.slaTotal ?? 0, firstActionS: c?.firstActionS ?? null,
      dispAcc: c?.dispAcc ?? null, isoPct: c?.isoPct ?? null, isolations: c?.isolations?.length ?? 0, blindCalls: c?.blindCalls ?? 0,
      forensicAccPct: c?.forensic?.accPct ?? null, misses,
    };
  }).sort((a, b) => (ts(b.at) ?? 0) - (ts(a.at) ?? 0));

  const learningGroups = (kind: "quiz" | "lesson") => {
    const by = new Map<string, LearningAttemptRow[]>();
    for (const a of raw.learning) if (a.kind === kind) { const l = by.get(a.content_id) ?? []; l.push(a); by.set(a.content_id, l); }
    return by;
  };
  const quizGroups = learningGroups("quiz");
  const quizReports = [...new Set([...raw.quizzes.map(q => q.quiz_slug), ...quizGroups.keys()])].map(slug => {
    const prog = raw.quizzes.find(q => q.quiz_slug === slug);
    const atts = (quizGroups.get(slug) ?? []).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)).map(a => ({ at: a.created_at, score: a.score_pct, passed: a.passed }));
    return { slug, title: QUIZ_TITLE[slug] ?? slug, best: prog?.best_score_pct ?? (atts.length ? Math.max(...atts.map(a => a.score)) : null), passed: !!prog?.passed || atts.some(a => a.passed), attempts: atts, _at: atts[0]?.at ?? prog?.last_completed_at ?? "" };
  }).sort((a, b) => Date.parse(b._at || "0") - Date.parse(a._at || "0")).map(({ _at: _x, ...rest }) => { void _x; return rest; });
  const lessonGroups = learningGroups("lesson");
  const lessonReports = [...new Set([...raw.lessons.map(l => l.lesson_key), ...lessonGroups.keys()])].map(key => {
    const prog = raw.lessons.find(l => l.lesson_key === key);
    const atts = (lessonGroups.get(key) ?? []).sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at)).map(a => ({ at: a.created_at, score: a.score_pct, passed: a.passed }));
    return { key, title: lessonTitle(key), best: prog?.best_quiz_pct ?? (atts.length ? Math.max(...atts.map(a => a.score)) : null), passed: !!prog?.quiz_passed_at || atts.some(a => a.passed), attempts: atts, _at: atts[0]?.at ?? prog?.completed_at ?? "" };
  }).sort((a, b) => Date.parse(b._at || "0") - Date.parse(a._at || "0")).map(({ _at: _x, ...rest }) => { void _x; return rest; });

  const quality = reportQuality(realScenarios, raw.incidents);

  const criticalMisses: ProgressPayload["criticalMisses"] = [
    ...raw.incidents.filter(i => i.outcome === "missed").map(i => {
      const tech = (i.mitre ?? [])[0] ?? null;
      return { source: "live" as const, title: i.title, at: i.submitted_at, detail: i.missed_tell, technique: tech, practice: practiceFor(tech) };
    }),
    ...raw.team.flatMap(t => [...(t.card?.falseNegatives ?? []).map(m => ({ m, how: "Closed as benign" })), ...(t.card?.walkedPast ?? []).map(m => ({ m, how: "Opened and left without action" }))]
      .map(({ m, how }) => ({ source: "team" as const, title: m.label, at: t.ended_at, detail: `${how} in a team exercise (${m.severity})`, technique: m.technique ?? null, practice: m.practice ?? practiceFor(m.technique) }))),
  ].sort((a, b) => (ts(b.at) ?? 0) - (ts(a.at) ?? 0)).slice(0, 50);

  return {
    generatedAt: new Date(now).toISOString(),
    periodDays,
    overview: {
      tiles: {
        done: { now: done(wFrom, now), prev: done(pFrom, wFrom) },
        firstTry: { now: ftNow.pct, prev: ftPrev.pct, items: ftNow.n },
        missed: { now: missedIn(wFrom, now), prev: missedIn(pFrom, wFrom) },
        response: responseTile,
      },
      sentences,
      next: next.slice(0, 3),
    },
    activity: {
      weeks, days, timeline: timeline.slice(0, 300),
      totals: { minutes: Math.round(events.reduce((s, e) => s + e.minutes, 0)), items: countEvents.length },
    },
    skills: {
      areas, tactics, firstTry,
      persistence: { avgTriesToSolve: tries.length ? Math.round((tries.reduce((s, x) => s + x, 0) / tries.length) * 10) / 10 : null, solvedAfterRetry: retried.length },
    },
    response: {
      rooms: { ...stat(roomLat), accuracy: pct(firstAttempts.filter(a => a.correct).length, firstAttempts.length), byType, source: roomSource },
      blindCalls: { count: blindList.length, wrong: blindList.filter(a => !a.correct).length },
      live: {
        notice: stat(incidentSpans.map(s => s.notice).filter((x): x is number => x !== null)),
        investigate: stat(incidentSpans.map(s => s.investigate).filter((x): x is number => x !== null)),
        write: stat(incidentSpans.map(s => s.write).filter((x): x is number => x !== null)),
        total: { ...stat(liveTotalXs), withinTarget: liveTotalXs.length ? pct(liveTotalXs.filter(x => x <= LIVE_TARGET_MS).length, liveTotalXs.length) : null },
        targetMs: LIVE_TARGET_MS, source: liveSource,
        bySeverity: sevs.map(sev => { const xs = incidentSpans.filter(s => s.sev === sev).map(s => s.total).filter((x): x is number => x !== null); return { severity: sev, median: median(xs), count: xs.length }; }),
      },
      scenarios: stat(scenarioTimes),
      edr: { ...stat(edrTimes), accuracy: pct(raw.edr.filter(e => e.correct).length, raw.edr.length) },
      team: { firstAction: stat(teamFirst), slaMet: raw.team.reduce((s, t) => s + (t.card?.slaMet ?? 0), 0), slaTotal: raw.team.reduce((s, t) => s + (t.card?.slaTotal ?? 0), 0), bySeverity: teamSev },
      weekly,
    },
    reports: {
      scenarios: scenarioReports,
      incidents: [...raw.incidents].sort((a, b) => Date.parse(b.submitted_at) - Date.parse(a.submitted_at)).slice(0, 150),
      team: teamReports, quizzes: quizReports, lessons: lessonReports, edr: raw.edr.slice(0, 100),
      quality,
    },
    criticalMisses,
  };
}

function diff(a: string | null, b: string | null): number | null {
  const x = ts(a), y = ts(b);
  return x !== null && y !== null && y >= x ? y - x : null;
}

/** The first PASSING report per incident (a re-submit after a pass is not a new response). */
export function firstPassPerIncident(rows: IncidentRow[]): IncidentRow[] {
  const seen = new Set<string>(); const out: IncidentRow[] = [];
  for (const r of [...rows].sort((a, b) => Date.parse(a.submitted_at) - Date.parse(b.submitted_at))) {
    if (r.outcome !== "passed") continue;
    const k = r.incident_key ? `${r.shift_key ?? ""}|${r.incident_key}` : `row-${r.id}`;
    if (seen.has(k)) continue; seen.add(k); out.push(r);
  }
  return out;
}

export function scenarioAttemptView(r: ScenarioRow, isBlind: boolean): ScenarioAttemptView {
  const rep = r.report ?? {};
  const det = r.report_detail ?? null;
  const items = det?.items?.length ? det.items
    : rep.rubric ? (Object.keys(RUBRIC_MAX) as (keyof typeof RUBRIC_MAX)[]).map(k => ({ key: k, label: RUBRIC_LABEL[k], points: rep.rubric![k] ?? 0, max: RUBRIC_MAX[k], detail: "" })) : [];
  return {
    at: r.completed_at ?? "", score: r.score ?? 0, xp: r.xp_earned ?? 0, timeS: r.time_taken ?? 0, blind: isBlind,
    verdict: rep.verdict ?? null, verdictReason: (rep.verdictReason ?? "").slice(0, 8000), notes: (rep.notes ?? "").slice(0, 8000),
    reportScore: typeof rep.reportScore === "number" ? rep.reportScore : null, passed: typeof rep.passed === "boolean" ? rep.passed : null,
    items, improvements: det?.improvements ?? [], summary: det?.summary ?? null, aiFeedback: det?.aiFeedback ?? null,
    citedIndicators: det?.citedIndicators ?? [], missedIndicators: det?.missedIndicators ?? null,
    fabricatedValues: det?.fabricatedValues ?? [], misattributedValues: det?.misattributedValues ?? [],
    quizScore: typeof det?.quizScore === "number" ? det.quizScore : null, questions: det?.questions ?? null,
    hasDetail: !!det,
  };
}

/**
 * Report quality across sources on one shared scale (percent of each component's max):
 * identification (scenario verdict /25, incident attack /40), evidence (scenario evidence
 * /30, incident evidence /30), depth (scenario depth+reasoning /45, incident action and
 * impact /30). The weakest component is the one most often lowest in the last 10 reports.
 */
export function reportQuality(scenarios: ScenarioRow[], incidents: IncidentRow[]): ProgressPayload["reports"]["quality"] {
  const points: QualityPoint[] = [];
  for (const r of scenarios) {
    const rb = r.report?.rubric; if (!rb || !r.completed_at) continue;
    points.push({ at: r.completed_at, source: "scenario", title: scenarioTitle(r.slug, r.title),
      identification: Math.round((rb.verdict / 25) * 100), evidence: Math.round((rb.evidence / 30) * 100), depth: Math.round(((rb.depth + rb.reasoning) / 45) * 100) });
  }
  for (const i of incidents) {
    if (i.outcome === "missed" || i.attack_score == null || i.ioc_score == null || i.action_score == null) continue;
    points.push({ at: i.submitted_at, source: "incident", title: i.title,
      identification: Math.round((i.attack_score / 40) * 100), evidence: Math.round((i.ioc_score / 30) * 100), depth: Math.round((i.action_score / 30) * 100) });
  }
  points.sort((a, b) => Date.parse(a.at) - Date.parse(b.at));
  const recent = points.slice(-10);
  let weakest: ProgressPayload["reports"]["quality"]["weakest"] = null;
  if (recent.length >= 3) {
    const tally = { identification: 0, evidence: 0, depth: 0 };
    for (const p of recent) {
      const low = (["identification", "evidence", "depth"] as const).reduce((m, k) => (p[k] < p[m] ? k : m), "identification" as "identification" | "evidence" | "depth");
      if (p[low] < 100) tally[low]++;
    }
    const key = (Object.keys(tally) as (keyof typeof tally)[]).reduce((m, k) => (tally[k] > tally[m] ? k : m), "evidence" as keyof typeof tally);
    if (tally[key] > 0) weakest = { key, count: tally[key], of: recent.length, advice: QUALITY_ADVICE[key] };
  }
  return { points: points.slice(-60), weakest };
}
