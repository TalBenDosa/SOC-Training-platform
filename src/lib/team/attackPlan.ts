/**
 * The attacks an instructor plans for a team exercise: how many concurrent attack stories run
 * (or "auto" — sized by the team, load.ts) and, per attack, a chosen storyline or a random one.
 * Stored staff-only in team_sessions.config.attacks (scenario_id keeps the first chosen one for
 * older readers). Isomorphic: the builder, the routes and /start share it.
 */
import { withStoryCount, type TeamLoad } from "./load";

export const MAX_ATTACKS = 3;
export interface AttackPlan {
  /** Concurrent attack stories; null = sized by the team (load.ts). */
  count: number | null;
  /** Up to MAX_ATTACKS slots: a storyline id, or null for a random pick. */
  slots: (string | null)[];
  /** One more random attack, released only once the team has caught every planned one (default on). */
  bonus: boolean;
}

const ID_RE = /^[a-z0-9][a-z0-9-]{1,119}$/;
const cleanId = (v: unknown): string | null => (typeof v === "string" && ID_RE.test(v) ? v : null);

/**
 * From a create request: `attack_count` (1–3, else auto) and `scenario_ids` (≤3, "" / null =
 * random); an older client's single `scenario_id` is slot 1. Repeated storylines collapse to
 * one (the later slot becomes random); slots beyond the count are dropped.
 */
export function sanitizeAttackPlan(body: { attack_count?: unknown; scenario_ids?: unknown; scenario_id?: unknown; bonus_attack?: unknown }): AttackPlan {
  const n = Number(body.attack_count);
  const count = Number.isInteger(n) && n >= 1 && n <= MAX_ATTACKS ? n : null;
  const raw = Array.isArray(body.scenario_ids) ? body.scenario_ids.slice(0, MAX_ATTACKS) : [body.scenario_id];
  const seen = new Set<string>();
  const slots = raw.map(cleanId).map(id => (id && !seen.has(id) ? (seen.add(id), id) : null));
  const kept = count ? slots.slice(0, count) : slots;
  while (kept.length && kept[kept.length - 1] === null) kept.pop();
  return { count, slots: kept, bonus: body.bonus_attack !== false };
}

/** The stored plan (config.attacks), else the legacy single storyline. */
export function planFromConfig(config: unknown, scenarioId?: string | null): AttackPlan {
  const a = (config as { attacks?: { count?: unknown; slots?: unknown; bonus?: unknown } } | null)?.attacks;
  if (a) return sanitizeAttackPlan({ attack_count: a.count, scenario_ids: a.slots, bonus_attack: a.bonus });
  return { count: null, slots: scenarioId ? [scenarioId] : [], bonus: true };
}

/** The chosen storylines, in slot order. */
export const pinnedIds = (plan: AttackPlan): string[] => plan.slots.filter((s): s is string => !!s);

/** How many attack stories run: the chosen count, else the team's — always reaching the last chosen slot. */
export function attackCount(plan: AttackPlan, load: TeamLoad): number {
  const n = plan.count ?? load.stories;
  const lastChosen = plan.slots.reduce((m, id, i) => (id ? i + 1 : m), 0);
  return Math.min(MAX_ATTACKS, Math.max(n, lastChosen, 1));
}

/** The team's load with the planned attack count (noise re-sized so the shift length holds). */
export function loadWithPlan(load: TeamLoad, plan: AttackPlan): TeamLoad {
  return withStoryCount(load, attackCount(plan, load));
}
