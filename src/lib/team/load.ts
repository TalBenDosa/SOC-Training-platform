/**
 * Team-exercise LOAD — how fast logs arrive and how many attacks run, sized by
 * difficulty AND by the team actually in the room (Tal, 2026-09-30).
 *
 * Before: the pace and the attack count depended on difficulty alone — a lone
 * Tier-1 got the same ~4–6 logs/min a four-analyst floor got, couldn't keep up,
 * and the exercise turned into speed-clicking instead of analysis.
 *
 *  - LOG PACE follows TRIAGE CAPACITY: the Tier-1 analysts, who are the ones
 *    reading the raw feed. Each one is budgeted a steady per-analyst rate; the
 *    room total grows with them up to a cap. (T2/T3/Manager/TI work escalations
 *    and cases, not the raw feed, so they don't raise the pace.)
 *  - ATTACK COUNT follows TEAM SIZE (every player): more people → more concurrent
 *    incidents and standalone attacks, so everyone has real work.
 *  - SHIFT LENGTH stays fixed per difficulty; the noise volume is derived from it.
 *
 * Pure and isomorphic: /start seeds the timeline from it and the lobby shows the
 * same numbers to the instructor before the shift starts.
 */

export type Difficulty = "easy" | "medium" | "hard";

/** Roles that are not players: they neither triage nor count toward team size. */
const NON_PLAYER = new Set(["instructor", "observer"]);

export const LOAD_RULES = {
  /** Logs per minute each Tier-1 analyst is budgeted to read and disposition. */
  perAnalystLogsPerMin: { easy: 1.5, medium: 2, hard: 2.5 } as Record<Difficulty, number>,
  /** Ceiling for the whole room, however many Tier-1s join. */
  maxLogsPerMin: { easy: 5, medium: 6.5, hard: 8 } as Record<Difficulty, number>,
  /** Live-telemetry length of the shift. */
  shiftMin: { easy: 30, medium: 35, hard: 40 } as Record<Difficulty, number>,
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

export function teamLoad(difficulty: Difficulty, roster: { role: string; status?: string }[]): TeamLoad {
  const active = roster.filter(m => m.status !== "left" && !NON_PLAYER.has(m.role));
  const players = Math.max(1, active.length);
  const triageAnalysts = Math.max(1, active.filter(m => m.role === "t1").length);

  const logsPerMin = Math.min(LOAD_RULES.maxLogsPerMin[difficulty], LOAD_RULES.perAnalystLogsPerMin[difficulty] * triageAnalysts);
  const meanGap = 60_000 / logsPerMin;
  const jitterMs = Math.round(meanGap * 0.25);
  const baseGapMs = Math.round(meanGap - jitterMs / 2);

  const stories = storiesFor(difficulty, players);
  const poolAttacks = poolAttacksFor(difficulty, players);
  const shiftMin = LOAD_RULES.shiftMin[difficulty];
  const totalLogs = Math.round(logsPerMin * shiftMin);
  const attackLogs = stories * AVG_STORY_LOGS + poolAttacks * AVG_POOL_ATTACK_LOGS;
  // Keep attacks a minority of the feed even for the smallest, fastest-paced rooms.
  const noiseCount = Math.max(attackLogs * 2, totalLogs - attackLogs);

  return { difficulty, triageAnalysts, players, logsPerMin, baseGapMs, jitterMs, stories, poolAttacks, noiseCount, shiftMin };
}

/** The same load with `stories` concurrent attack stories (the instructor's plan); noise re-sized so the shift length holds. */
export function withStoryCount(load: TeamLoad, stories: number): TeamLoad {
  if (stories === load.stories) return load;
  const totalLogs = Math.round(load.logsPerMin * load.shiftMin);
  const attackLogs = stories * AVG_STORY_LOGS + load.poolAttacks * AVG_POOL_ATTACK_LOGS;
  return { ...load, stories, noiseCount: Math.max(attackLogs * 2, totalLogs - attackLogs) };
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
  };
}
