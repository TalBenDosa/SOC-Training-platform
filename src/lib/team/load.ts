/**
 * Team-exercise LOAD — how fast logs arrive and how many attacks run, sized by
 * difficulty AND by the team actually in the room (Tal, 2026-09-30).
 *
 * 2026-10-25 (Tal): the pace follows the analysts' WORK, not a fixed rate. An analyst at any tier
 * has to read a log, analyse it and write a good escalation, and that takes time. The model:
 *
 *  - CAPACITY: Tier-1 analysts × shift minutes × UTILIZATION (the rest is breathing room: talking
 *    to the team, re-reading, asking a question).
 *  - ATTACK WORK comes off the top: every alert worth triaging (TRIAGE_MIN each) and every
 *    escalation worth writing well (ESCALATION_MIN each).
 *  - READING: what is left (never less than READ_FLOOR of the capacity) sets how many logs fit,
 *    at READ_SEC_PER_LOG each, and that is the pace (logs per minute, within a floor and a cap).
 *  - If the attacks alone would not leave room to read the feed, the standalone pool attacks are
 *    trimmed first; the storylines the instructor planned are never dropped.
 *
 * Only Tier-1 analysts read the raw feed and write the escalations, so they set the capacity.
 * T2/T3/Manager/TI work escalations and cases. ATTACK COUNT still follows TEAM SIZE (every
 * player), within what the Tier-1 team can absorb.
 *
 * Pure and isomorphic: /start seeds the timeline from it and the lobby shows the
 * same numbers to the instructor before the shift starts.
 */

export type Difficulty = "easy" | "medium" | "hard";

/** Roles that are not players: they neither triage nor count toward team size. */
const NON_PLAYER = new Set(["instructor", "observer"]);

/** How long the work takes (minutes / seconds per item). */
export const WORK = {
  /** Read a routine log and decide it is routine. */
  READ_SEC_PER_LOG: 25,
  /** A high / critical alert: claim it, read its fields, check the related logs. */
  TRIAGE_MIN: 1,
  /** Write a good escalation: summary, evidence from the log, IOCs, severity. */
  ESCALATION_MIN: 5,
  /** Share of the shift an analyst actually works the feed. */
  UTILIZATION: 0.8,
  /** Never less than this share of the capacity stays for reading the feed. */
  READ_FLOOR: 0.35,
} as const;

/** Alerts and escalations a storyline / a standalone attack / the benign-positive alerts typically bring. */
const ALERTS_PER_STORY = 5, ESCALATIONS_PER_STORY = 2, FP_ALERTS = 4;

export const LOAD_RULES = {
  /** Floor and ceiling for the whole room's pace (logs per minute). */
  minLogsPerMin: { easy: 0.8, medium: 1, hard: 1.2 } as Record<Difficulty, number>,
  maxLogsPerMin: { easy: 5, medium: 6, hard: 8 } as Record<Difficulty, number>,
  /** Live-telemetry length of the shift. */
  shiftMin: { easy: 30, medium: 35, hard: 40 } as Record<Difficulty, number>,
  /** The fewest standalone attacks a room keeps when trimming for capacity (a lone Tier-1 cannot escalate them well on top of a storyline). */
  minPoolAttacks: { easy: 0, medium: 0, hard: 0 } as Record<Difficulty, number>,
} as const;

export interface TeamLoad {
  difficulty: Difficulty;
  /** Tier-1 analysts triaging the feed (at least 1 — someone always triages). */
  triageAnalysts: number;
  /** Players (everyone but instructor/observer). */
  players: number;
  logsPerMin: number;
  /** Mean gap between logs, split into a base + uniform jitter. */
  baseGapMs: number;
  jitterMs: number;
  /** Concurrent attack stories (kill chains). */
  stories: number;
  /** Standalone attacks from the company's own pool. */
  poolAttacks: number;
  /** Noise logs to seed so the feed spans the shift at this pace. */
  noiseCount: number;
  shiftMin: number;
  /** Planned Tier-1 work against capacity (1 = the team is fully busy). For the lobby. */
  workload: number;
}

const clamp = (n: number, lo: number, hi: number) => Math.max(lo, Math.min(hi, n));

/** Stories by team size — easy stays single-threaded for small groups. */
function storiesFor(d: Difficulty, players: number): number {
  if (d === "easy") return players >= 6 ? 2 : 1;
  if (d === "medium") return players <= 2 ? 1 : 2;
  return players >= 7 ? 3 : 2;
}

/** Standalone attacks by team size. */
function poolAttacksFor(d: Difficulty, players: number): number {
  if (d === "easy") return players >= 4 ? 1 : 0;
  if (d === "medium") return clamp(1 + Math.floor(players / 2), 1, 5);
  return clamp(2 + Math.floor(players / 2), 2, 7);
}

/**
 * Typical logs a story / pool attack adds (used only to size the noise so the
 * shift length holds; the real counts come from the content).
 */
const AVG_STORY_LOGS = 10;
const AVG_POOL_ATTACK_LOGS = 2;

/** Minutes of Tier-1 work the attacks bring: triaging their alerts and escalating them. */
export function attackWorkMin(stories: number, poolAttacks: number): number {
  const alerts = stories * ALERTS_PER_STORY + poolAttacks + FP_ALERTS;
  const escalations = stories * ESCALATIONS_PER_STORY + poolAttacks;
  return alerts * WORK.TRIAGE_MIN + escalations * WORK.ESCALATION_MIN;
}

/** The load for a room: pace and attack count from the Tier-1 team's capacity over the shift. */
function size(difficulty: Difficulty, triageAnalysts: number, players: number, shiftMin: number, storiesIn?: number): TeamLoad {
  const capacity = triageAnalysts * shiftMin * WORK.UTILIZATION;
  const room = capacity * (1 - WORK.READ_FLOOR);
  // The storylines the instructor planned stay. The automatic count follows team size (T2/T3 need
  // real work too), except that a lone Tier-1 is never handed more than one storyline can carry.
  let stories = storiesIn ?? storiesFor(difficulty, players);
  if (storiesIn == null && triageAnalysts === 1) while (stories > 1 && attackWorkMin(stories, 0) > room) stories--;
  // Too many attacks for this Tier-1 team to escalate well: trim the standalone ones first.
  let poolAttacks = poolAttacksFor(difficulty, players);
  while (poolAttacks > LOAD_RULES.minPoolAttacks[difficulty] && attackWorkMin(stories, poolAttacks) > room) poolAttacks--;
  const readMin = Math.max(capacity * WORK.READ_FLOOR, capacity - attackWorkMin(stories, poolAttacks));
  const readable = (readMin * 60) / WORK.READ_SEC_PER_LOG;
  const logsPerMin = Math.round(clamp(readable / shiftMin, LOAD_RULES.minLogsPerMin[difficulty], LOAD_RULES.maxLogsPerMin[difficulty]) * 10) / 10;

  const meanGap = 60_000 / logsPerMin;
  const jitterMs = Math.round(meanGap * 0.25);
  const baseGapMs = Math.round(meanGap - jitterMs / 2);
  const totalLogs = Math.round(logsPerMin * shiftMin);
  const attackLogs = stories * AVG_STORY_LOGS + poolAttacks * AVG_POOL_ATTACK_LOGS;
  // Keep attacks a minority of the feed even for the smallest rooms.
  const noiseCount = Math.max(attackLogs * 2, totalLogs - attackLogs);
  const work = (totalLogs * WORK.READ_SEC_PER_LOG) / 60 + attackWorkMin(stories, poolAttacks);
  const workload = Math.round((work / (triageAnalysts * shiftMin)) * 100) / 100;

  return { difficulty, triageAnalysts, players, logsPerMin, baseGapMs, jitterMs, stories, poolAttacks, noiseCount, shiftMin, workload };
}

export function teamLoad(difficulty: Difficulty, roster: { role: string; status?: string }[]): TeamLoad {
  const active = roster.filter(m => m.status !== "left" && !NON_PLAYER.has(m.role));
  const players = Math.max(1, active.length);
  const triageAnalysts = Math.max(1, active.filter(m => m.role === "t1").length);
  return size(difficulty, triageAnalysts, players, LOAD_RULES.shiftMin[difficulty]);
}

/**
 * Shift lengths the instructor can pick in the Session Builder (2026-10-18 review: the four
 * Team Training exercises ran 14-27 minutes while their timelines were planned for 35-42, so the
 * attacks the admin chose arrived after the session had ended). null = the difficulty default.
 */
export const SHIFT_CHOICES = [20, 30, 45] as const;
export function sanitizeShiftMinutes(v: unknown): number | null {
  const n = Number(v);
  return (SHIFT_CHOICES as readonly number[]).includes(n) ? n : null;
}

/** The same room over a shift of `minutes` (the instructor's choice): capacity, pace and noise re-sized for it. */
export function withShiftMinutes(load: TeamLoad, minutes: number | null): TeamLoad {
  if (!minutes || minutes === load.shiftMin) return load;
  return size(load.difficulty, load.triageAnalysts, load.players, minutes, load.stories);
}

/** The same room with `stories` concurrent attack stories (the instructor's plan); pace re-sized so the work still fits. */
export function withStoryCount(load: TeamLoad, stories: number): TeamLoad {
  if (stories === load.stories) return load;
  return size(load.difficulty, load.triageAnalysts, load.players, load.shiftMin, stories);
}

/**
 * The fixed, difficulty-only load the exercise used before team sizing — kept as
 * the default for callers that pass no roster, so existing seeds replay exactly.
 */
export function legacyLoad(difficulty: Difficulty): TeamLoad {
  const baseGapMs = difficulty === "hard" ? 9000 : difficulty === "easy" ? 14000 : 12000;
  return {
    difficulty, triageAnalysts: 1, players: 1,
    logsPerMin: Math.round((60_000 / (baseGapMs + 1750)) * 10) / 10,
    baseGapMs, jitterMs: 3500,
    stories: difficulty === "easy" ? 1 : 2,
    poolAttacks: difficulty === "hard" ? 4 : difficulty === "easy" ? 0 : 3,
    noiseCount: difficulty === "hard" ? 162 : difficulty === "easy" ? 86 : 135,
    shiftMin: 35,
    workload: 1,
  };
}
