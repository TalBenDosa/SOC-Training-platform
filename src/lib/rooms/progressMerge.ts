/**
 * Pure helpers for merging a room's saved progress entry.
 *
 * WHY (audit 2026-09, "I practice but my points don't go up"): RoomClient read
 * progress ONCE on mount. On a hard reload / new tab it mounted before the
 * remote backend finished hydrating, so it started from an EMPTY entry, and the
 * next save REPLACED the server row — lower xp_earned, lost per-task bests,
 * dropped completedAt. Every room save now merges with the stored entry, so a
 * stale in-memory state can never lower what was already earned. The DB has the
 * same guarantee for user-driven updates (migration 0074).
 */

/** Must match room_progress_xp_earned_bound (migration 0025). */
export const ROOM_XP_DB_CAP = 1000;

export interface MergeableRoomEntry {
  completedTaskIds: string[];
  xpEarned: number;
  completedAt?: string;
  perTaskXp?: Record<string, number>;
  telemetry?: unknown[];
}

/** Clamp a room's xp to what the DB row accepts (0..ROOM_XP_DB_CAP, integer). */
export function clampRoomXp(xp: number): number {
  if (!Number.isFinite(xp)) return 0;
  return Math.min(ROOM_XP_DB_CAP, Math.max(0, Math.round(xp)));
}

/** Per-task best: the max of both maps for every task id. */
export function mergeTaskXpMax(
  a: Record<string, number> | undefined,
  b: Record<string, number> | undefined,
): Record<string, number> {
  const out: Record<string, number> = {};
  for (const src of [a ?? {}, b ?? {}]) {
    for (const [k, v] of Object.entries(src)) {
      if (typeof v !== "number" || !Number.isFinite(v)) continue;
      out[k] = Math.max(out[k] ?? 0, v);
    }
  }
  return out;
}

export function sumTaskXp(map: Record<string, number> | undefined): number {
  return Object.values(map ?? {}).reduce((s, v) => s + (Number.isFinite(v) ? v : 0), 0);
}

/**
 * Merge the entry about to be saved (`next`) with what is already stored.
 *  - perTaskXp: per-task max (a re-attempt or a stale state never lowers a best)
 *  - xpEarned: never below the stored value; normally the sum of perTaskXp; capped
 *  - completedAt: the stored one wins (first pass date is kept, never cleared)
 *  - completedTaskIds: union, EXCEPT in `replaceIds` mode (the "review missed
 *    tasks" flow deliberately re-opens tasks — their XP is kept regardless)
 *  - telemetry: next when it already extends the stored list, else appended
 */
export function mergeRoomEntry(
  stored: MergeableRoomEntry | undefined,
  next: MergeableRoomEntry,
  opts: { replaceIds?: boolean } = {},
): MergeableRoomEntry {
  if (!stored) {
    const perTaskXp = mergeTaskXpMax(undefined, next.perTaskXp);
    return {
      ...next,
      perTaskXp,
      xpEarned: clampRoomXp(Math.max(next.xpEarned ?? 0, sumTaskXp(perTaskXp))),
    };
  }
  const perTaskXp = mergeTaskXpMax(stored.perTaskXp, next.perTaskXp);
  const xpEarned = clampRoomXp(Math.max(stored.xpEarned ?? 0, next.xpEarned ?? 0, sumTaskXp(perTaskXp)));
  const completedTaskIds = opts.replaceIds
    ? [...next.completedTaskIds]
    : Array.from(new Set([...(stored.completedTaskIds ?? []), ...next.completedTaskIds]));
  const storedTel = stored.telemetry ?? [];
  const nextTel = next.telemetry ?? [];
  const telemetry = nextTel.length >= storedTel.length ? nextTel : [...storedTel, ...nextTel];
  const completedAt = stored.completedAt ?? next.completedAt;
  return {
    completedTaskIds,
    xpEarned,
    perTaskXp,
    telemetry,
    ...(completedAt ? { completedAt } : {}),
  };
}

/**
 * The room's SCORE xp for the 65% mastery gate: gradeable tasks only (reading
 * engagement XP is stored in perTaskXp so it survives a reload and reaches the
 * overall score, but it must not help pass a room). Legacy entries saved before
 * perTaskXp existed fall back to the stored xpEarned.
 */
export function roomScoreXp(
  entry: Pick<MergeableRoomEntry, "xpEarned" | "perTaskXp">,
  gradeableTaskMax: Record<string, number>,
): number {
  const map = entry.perTaskXp ?? {};
  if (Object.keys(map).length === 0) return entry.xpEarned ?? 0;
  let s = 0;
  for (const [id, max] of Object.entries(gradeableTaskMax)) {
    if (max > 0) s += Math.min(max, map[id] ?? 0);
  }
  return s;
}
